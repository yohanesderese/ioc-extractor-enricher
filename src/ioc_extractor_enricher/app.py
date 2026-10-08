"""Local FastAPI analyst UI, JSON endpoints and session-scoped report review."""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.datastructures import UploadFile
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .cache import SQLiteCache
from .enrichment import (
    OTX,
    RDAP,
    AbuseIPDB,
    EnrichmentEngine,
    EnrichmentResult,
    GreyNoise,
    InternetDB,
    MalwareBazaar,
    URLhaus,
    VirusTotal,
)
from .exports import ExportItem, export_csv, export_json, export_stix
from .extractor import extract
from .misp import MISPClient, MISPResult
from .models import IOC, ExtractionOptions
from .noise_filter import load_whitelist
from .refang import refang
from .scorer import ScoreResult, score_results

ASSETS = Path(__file__).parent
MAX_INPUT_BYTES = 1_048_576
MAX_IOCS = 50
MAX_REPORTS = 32
MAX_SESSIONS = 64
REPORT_TTL = 3600
JOB_TIMEOUT = 300
COOKIE = "ioc_session"
View = Literal["cards", "table"]
VerdictFilter = Literal["all", "malicious", "suspicious", "clean", "unknown"]
Sort = Literal["score", "value", "type"]
Order = Literal["asc", "desc"]
ReviewFilter = Literal["all", "flagged", "unflagged"]


class BodyLimitMiddleware:
    """Bound incoming request bodies before multipart parsing or JSON validation."""

    def __init__(self, app: ASGIApp) -> None:
        """Allow 1 MiB of content plus limited multipart overhead."""
        self.app = app
        self.limit = MAX_INPUT_BYTES + 65_536

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Count body chunks; return 413 before a large upload can fill temporary storage."""
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.limit:
                await JSONResponse({"detail": "Input exceeds the 1 MiB limit."}, status_code=413)(
                    scope, receive, send
                )
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def limited_receive() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, limited_receive, send)


@dataclass
class Session:
    """Ephemeral browser identity and CSRF token, never provider credentials."""

    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    created: float = field(default_factory=time.monotonic)


@dataclass
class Card:
    """An IOC, immutable source evidence and a separate analyst review annotation."""

    id: int
    ioc: IOC
    evidence: list[EnrichmentResult] = field(default_factory=list)
    assessment: ScoreResult = field(default_factory=lambda: score_results([]))
    pending: bool = False
    false_positive: bool = False


@dataclass
class Report:
    """A bounded, temporary report owned by one browser session."""

    id: str
    owner: str
    cards: list[Card]
    created: float = field(default_factory=time.monotonic)

    misp_result: MISPResult | None = None
    misp_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def pending(self) -> bool:
        """Whether any cards still await provider evidence."""
        return any(card.pending for card in self.cards)


class AnalyzeInput(BaseModel):
    """JSON analysis request; extraction runs locally unless enrichment is selected."""

    model_config = ConfigDict(extra="forbid")
    text: str = Field(default="", max_length=MAX_INPUT_BYTES)
    url: str = Field(default="", max_length=8192)
    enrich: bool = False
    include_reserved_ips: bool = False
    include_zero_hashes: bool = False
    filter_noise: bool = True


class ReviewInput(BaseModel):
    """Explicit desired review state makes retries idempotent."""

    model_config = ConfigDict(extra="forbid")
    false_positive: bool


class PushInput(BaseModel):
    """Explicit confirmation independent of CSRF protection."""

    model_config = ConfigDict(extra="forbid")
    confirm: bool = False


def create_app(
    engine: EnrichmentEngine | None = None,
    *,
    cache_path: str | Path = "enrichment.db",
    whitelist_path: Path | None = None,
    misp: MISPClient | None = None,
) -> FastAPI:
    """Build an isolated app; tests inject an engine and never use live providers."""
    templates = Jinja2Templates(directory=str(ASSETS / "templates"))

    def safe_url(value: str | None) -> str | None:
        """Only allow HTTP(S) provider links in rendered evidence."""
        try:
            parsed = urlsplit(value or "")
            return value if parsed.scheme in {"http", "https"} and parsed.netloc else None
        except ValueError:
            return None

    templates.env.filters["safe_url"] = safe_url
    sessions: dict[str, Session] = {}
    reports: dict[str, Report] = {}
    jobs: dict[str, asyncio.Task[None]] = {}
    whitelist = load_whitelist(whitelist_path) if whitelist_path else frozenset()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        """Create shared clients at startup and cancel outstanding work on shutdown."""
        application.state.misp = misp
        try:
            if engine is not None:
                application.state.engine = engine
                yield
            else:
                async with httpx.AsyncClient() as client, SQLiteCache(cache_path) as cache:
                    application.state.engine = EnrichmentEngine(
                        [
                            VirusTotal(client),
                            AbuseIPDB(client),
                            OTX(client),
                            URLhaus(client),
                            MalwareBazaar(client),
                            InternetDB(client),
                            GreyNoise(client),
                            RDAP(client),
                        ],
                        cache,
                    )
                    application.state.misp = misp or MISPClient(client)
                    try:
                        yield
                    finally:
                        for job in jobs.values():
                            job.cancel()
                        await asyncio.gather(*tuple(jobs.values()), return_exceptions=True)
        finally:
            for job in jobs.values():
                job.cancel()
            await asyncio.gather(*tuple(jobs.values()), return_exceptions=True)

    application = FastAPI(
        title="IOC Extractor & Enricher", lifespan=lifespan, docs_url=None, redoc_url=None
    )
    application.add_middleware(BodyLimitMiddleware)
    application.mount("/static", StaticFiles(directory=ASSETS / "static"), name="static")

    @application.middleware("http")
    async def local_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Prevent report caching and restrict browser scripts to local assets."""
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        return response

    def prune() -> None:
        """Expire old reports and sessions, cancelling work for expired reports."""
        now = time.monotonic()
        for key, report in tuple(reports.items()):
            if now - report.created >= REPORT_TTL:
                reports.pop(key)
                if key in jobs:
                    jobs[key].cancel()
        for key, session in tuple(sessions.items()):
            if now - session.created >= REPORT_TTL:
                sessions.pop(key)

    def session_for(request: Request) -> tuple[str, Session]:
        """Require the HttpOnly browser cookie for report reads and mutations."""
        prune()
        key = request.cookies.get(COOKIE, "")
        if key not in sessions:
            raise HTTPException(403, "Open the home page to start a browser session.")
        return key, sessions[key]

    def verify_csrf(request: Request, token: str | None) -> None:
        """Check a session token and reject explicit cross-origin submissions."""
        _, session = session_for(request)
        if not token or not secrets.compare_digest(token, session.csrf):
            raise HTTPException(403, "Invalid session token. Reload the home page.")
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") != str(request.base_url).rstrip("/"):
            raise HTTPException(403, "Cross-origin submissions are not allowed.")

    def owned_report(request: Request, report_id: str) -> Report:
        """Return a report only to the session that created it."""
        owner, _ = session_for(request)
        report = reports.get(report_id)
        if report is None or report.owner != owner:
            raise HTTPException(404, "Report not found or expired.")
        return report

    async def process(report: Report) -> None:
        """Update individual cards as their provider queues finish."""

        async def update(card: Card) -> None:
            try:
                card.evidence = await application.state.engine.enrich(card.ioc)
            except Exception:
                card.evidence = [
                    EnrichmentResult(
                        "enrichment",
                        "error",
                        reasons=("Enrichment failed for this indicator.",),
                    )
                ]
            card.assessment = score_results(card.evidence)
            card.pending = False

        try:
            async with asyncio.timeout(JOB_TIMEOUT):
                await asyncio.gather(*(update(card) for card in report.cards))
        except Exception:
            for card in report.cards:
                if card.pending:
                    card.evidence = [
                        EnrichmentResult(
                            "enrichment",
                            "timeout",
                            reasons=(
                                "Report enrichment did not complete. Analyze again to retry.",
                            ),
                        )
                    ]
                    card.assessment = score_results(card.evidence)
                    card.pending = False
        finally:
            jobs.pop(report.id, None)

    def start_report(request: Request, data: AnalyzeInput) -> Report:
        """Validate input limits before extraction and optional background lookups."""
        owner, _ = session_for(request)
        if data.url.strip():
            try:
                parsed = urlsplit(refang(data.url.strip()))
                if parsed.scheme.lower() not in {"http", "https"}:
                    raise ValueError
                if not parsed.netloc or any(char.isspace() for char in data.url.strip()):
                    raise ValueError
                if not parsed.hostname or (
                    parsed.port is not None and not 1 <= parsed.port <= 65535
                ):
                    raise ValueError
            except ValueError:
                raise HTTPException(422, "Enter one HTTP(S) URL indicator.") from None
        text = "\n".join(part for part in (data.text, data.url.strip()) if part)
        if not text.strip():
            raise HTTPException(422, "Paste text, upload a text file, or enter a URL indicator.")
        if len(text.encode("utf-8")) > MAX_INPUT_BYTES:
            raise HTTPException(413, "Input exceeds the 1 MiB limit.")
        iocs = extract(
            text,
            ExtractionOptions(
                data.include_reserved_ips, data.include_zero_hashes, data.filter_noise
            ),
            whitelist,
        )
        if len(iocs) > MAX_IOCS:
            raise HTTPException(422, f"Limit each report to {MAX_IOCS} unique indicators.")
        if len(reports) >= MAX_REPORTS:
            raise HTTPException(429, "Report capacity reached. Try again after reports expire.")
        report = Report(
            secrets.token_urlsafe(24),
            owner,
            [Card(index, ioc, pending=data.enrich) for index, ioc in enumerate(iocs)],
        )
        reports[report.id] = report
        if data.enrich and iocs:
            jobs[report.id] = asyncio.create_task(process(report))
        return report

    def select_cards(
        report: Report | None,
        verdict: VerdictFilter,
        sort: Sort,
        order: Order,
        review: ReviewFilter,
    ) -> list[Card]:
        """Share display ordering and filters with downloads."""
        cards = list(report.cards) if report else []
        if verdict != "all":
            cards = [card for card in cards if card.assessment.verdict == verdict]
        if review != "all":
            cards = [card for card in cards if card.false_positive == (review == "flagged")]
        if sort == "score":
            # Unknown scores always follow known scores, for either sort direction.
            cards.sort(
                key=lambda card: (
                    card.assessment.score is None,
                    (card.assessment.score or 0) * (-1 if order == "desc" else 1),
                    card.ioc.value,
                )
            )
        else:
            cards.sort(key=lambda card: getattr(card.ioc, sort), reverse=order == "desc")
        return cards

    def render(
        request: Request,
        report: Report | None = None,
        *,
        view: View = "cards",
        verdict: VerdictFilter = "all",
        sort: Sort = "score",
        order: Order = "desc",
        review: ReviewFilter = "all",
        error: str | None = None,
    ) -> HTMLResponse:
        """Render the full page or a safe HTMX fragment using current report filters."""
        _, session = session_for(request)
        cards = select_cards(report, verdict, sort, order, review)
        context = {
            "report": report,
            "cards": cards,
            "csrf": session.csrf,
            "view": view,
            "verdict": verdict,
            "sort": sort,
            "order": order,
            "review": review,
            "error": error,
            "max_iocs": MAX_IOCS,
            "misp_enabled": bool(application.state.misp and application.state.misp.configured),
        }
        name = "results.html" if request.headers.get("HX-Request") == "true" else "index.html"
        return templates.TemplateResponse(request=request, name=name, context=context)

    def serialize(report: Report) -> dict:
        """Return public report data without owner tokens or server task state."""
        return {
            "id": report.id,
            "pending": report.pending,
            "cards": [asdict(card) for card in report.cards],
            "misp": asdict(report.misp_result) if report.misp_result else None,
        }

    def review_card(report: Report, card_id: int, flagged: bool) -> Card:
        """Set an annotation without altering provider evidence or the calculated score."""
        if not 0 <= card_id < len(report.cards):
            raise HTTPException(404, "Indicator not found.")
        card = report.cards[card_id]
        card.false_positive = flagged
        return card

    @application.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> Response:
        """Start a local browser session and show the analysis form."""
        prune()
        key = request.cookies.get(COOKIE, "")
        if key not in sessions:
            if len(sessions) >= MAX_SESSIONS:
                raise HTTPException(429, "Session capacity reached. Try again later.")
            key = secrets.token_urlsafe(32)
            sessions[key] = Session()
            response = templates.TemplateResponse(
                request=request,
                name="index.html",
                context={
                    "report": None,
                    "error": None,
                    "csrf": sessions[key].csrf,
                    "max_iocs": MAX_IOCS,
                },
            )
            response.set_cookie(
                COOKIE,
                key,
                httponly=True,
                samesite="strict",
                secure=request.url.scheme == "https",
                max_age=REPORT_TTL,
            )
            return response
        return render(request)

    @application.post("/analyze", response_class=HTMLResponse)
    async def analyze_form(request: Request) -> Response:
        """Accept pasted text, a bounded UTF-8 upload and/or a URL indicator."""
        async with request.form(max_files=1, max_fields=12, max_part_size=MAX_INPUT_BYTES) as form:
            verify_csrf(request, str(form.get("csrf", "")))
            text = str(form.get("text", ""))
            upload = form.get("upload")
            try:
                if isinstance(upload, UploadFile) and upload.filename:
                    raw = await upload.read(MAX_INPUT_BYTES + 1)
                    if len(raw) > MAX_INPUT_BYTES:
                        raise HTTPException(413, "Uploaded file exceeds the 1 MiB limit.")
                    try:
                        uploaded = raw.decode("utf-8-sig")
                    except UnicodeError:
                        raise HTTPException(422, "Upload a UTF-8 text file.") from None
                    if "\x00" in uploaded or upload.filename.lower().endswith(".pdf"):
                        raise HTTPException(422, "PDF and binary parsing are not available yet.")
                    text += "\n" + uploaded
                report = start_report(
                    request,
                    AnalyzeInput(
                        text=text,
                        url=str(form.get("url", "")),
                        enrich=form.get("enrich") == "on",
                        include_reserved_ips=form.get("include_reserved_ips") == "on",
                        include_zero_hashes=form.get("include_zero_hashes") == "on",
                        filter_noise=form.get("filter_noise") == "on",
                    ),
                )
                return render(request, report)
            except ValidationError:
                return render(request, error="Input is too long or contains invalid options.")
            except HTTPException as exc:
                # HTMX displays useful input errors instead of silently dropping non-2xx bodies.
                if request.headers.get("HX-Request") == "true":
                    return render(request, error=str(exc.detail))
                response = render(request, error=str(exc.detail))
                response.status_code = exc.status_code
                return response

    @application.get("/reports/{report_id}/results", response_class=HTMLResponse)
    async def results_view(
        request: Request,
        report_id: str,
        view: View = "cards",
        verdict: VerdictFilter = "all",
        sort: Sort = "score",
        order: Order = "desc",
        review: ReviewFilter = "all",
    ) -> HTMLResponse:
        """Poll, filter, sort or switch views without repeating provider lookups."""
        return render(
            request,
            owned_report(request, report_id),
            view=view,
            verdict=verdict,
            sort=sort,
            order=order,
            review=review,
        )

    @application.post("/reports/{report_id}/cards/{card_id}/false-positive")
    async def review_form(
        request: Request,
        report_id: str,
        card_id: int,
        view: View = "cards",
        verdict: VerdictFilter = "all",
        sort: Sort = "score",
        order: Order = "desc",
        review: ReviewFilter = "all",
    ) -> Response:
        """Apply a session-local analyst annotation and refresh the current view."""
        async with request.form(max_files=0, max_fields=3) as form:
            verify_csrf(request, str(form.get("csrf", "")))
            flagged = form.get("false_positive")
            if flagged not in {"true", "false"}:
                raise HTTPException(422, "Review state must be true or false.")
            report = owned_report(request, report_id)
            review_card(report, card_id, flagged == "true")
        return render(
            request, report, view=view, verdict=verdict, sort=sort, order=order, review=review
        )

    @application.post("/api/analyze", status_code=202)
    async def analyze_json(request: Request, data: AnalyzeInput) -> dict:
        """Start an analysis; use the session's X-CSRF-Token header."""
        verify_csrf(request, request.headers.get("X-CSRF-Token"))
        return serialize(start_report(request, data))

    @application.get("/api/reports/{report_id}")
    async def report_json(request: Request, report_id: str) -> dict:
        """Return evidence, scores and review annotations for an owned report."""
        return serialize(owned_report(request, report_id))

    @application.post("/api/reports/{report_id}/cards/{card_id}/false-positive")
    async def review_json(
        request: Request, report_id: str, card_id: int, data: ReviewInput
    ) -> dict:
        """Set a review state without changing the source verdict or score."""
        verify_csrf(request, request.headers.get("X-CSRF-Token"))
        return asdict(review_card(owned_report(request, report_id), card_id, data.false_positive))

    def snapshot(cards: list[Card]) -> list[ExportItem]:
        """Copy completed report data without server ownership and locks."""
        return [ExportItem(c.ioc, c.assessment, tuple(c.evidence), c.false_positive) for c in cards]

    @application.get("/reports/{report_id}/export/{format}")
    async def download(
        request: Request,
        report_id: str,
        format: Literal["csv", "json", "stix"],
        verdict: VerdictFilter = "all",
        sort: Sort = "score",
        order: Order = "desc",
        review: ReviewFilter = "all",
    ) -> Response:
        """Download completed cards using current display filters."""
        report = owned_report(request, report_id)
        if report.pending:
            raise HTTPException(409, "Wait for enrichment to finish before exporting.")
        items = snapshot(select_cards(report, verdict, sort, order, review))
        exporters = {
            "csv": (export_csv, "text/csv", "csv"),
            "json": (export_json, "application/json", "json"),
            "stix": (export_stix, "application/stix+json", "stix.json"),
        }
        exporter, media_type, extension = exporters[format]
        return Response(
            exporter(items),
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="ioc-report-{report.id}.{extension}"'
            },
        )

    async def push_report(report: Report, confirm: bool) -> MISPResult:
        """Retain outcomes and serialize attempts to prevent repeated remote writes."""
        if not confirm:
            raise HTTPException(422, "Confirm creation of a private unpublished MISP event.")
        if report.pending:
            raise HTTPException(409, "Wait for enrichment to finish before pushing.")
        client = application.state.misp
        if client is None or not client.configured:
            raise HTTPException(409, "MISP is not configured.")
        async with report.misp_lock:
            if report.misp_result is None:
                report.misp_result = MISPResult(
                    "pending",
                    "MISP creation is in progress or uncertain. Check MISP before resending.",
                )
                report.misp_result = await client.push(snapshot(report.cards), report.id)
            return report.misp_result

    @application.post("/api/reports/{report_id}/misp")
    async def push_json(request: Request, report_id: str, data: PushInput) -> dict:
        """Require both a session token and explicit confirmation."""
        verify_csrf(request, request.headers.get("X-CSRF-Token"))
        return asdict(await push_report(owned_report(request, report_id), data.confirm))

    @application.post("/reports/{report_id}/misp", response_class=HTMLResponse)
    async def push_form(
        request: Request,
        report_id: str,
        view: View = "cards",
        verdict: VerdictFilter = "all",
        sort: Sort = "score",
        order: Order = "desc",
        review: ReviewFilter = "all",
    ) -> Response:
        """Only create an event after submitting the confirmation form."""
        async with request.form(max_files=0, max_fields=2) as form:
            verify_csrf(request, str(form.get("csrf", "")))
            report = owned_report(request, report_id)
            await push_report(report, form.get("confirm") == "on")
        return render(
            request, report, view=view, verdict=verdict, sort=sort, order=order, review=review
        )

    return application


app = create_app()
