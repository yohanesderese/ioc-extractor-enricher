"""Local app workflows with synthetic evidence and no live provider requests."""

import asyncio
import re
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.types import Receive, Send

from ioc_extractor_enricher.app import COOKIE, MAX_INPUT_BYTES, BodyLimitMiddleware, create_app
from ioc_extractor_enricher.enrichment import EnrichmentEngine, EnrichmentResult
from ioc_extractor_enricher.models import IOC, IOCType


class SyntheticSource:
    """Fast deterministic evidence for three synthetic indicator outcomes."""

    name = "virustotal"
    interval = 0.0

    def __init__(self) -> None:
        """Track calls to catch accidental repeat enrichment while filtering."""
        self.calls = 0

    def supports(self, kind: IOCType) -> bool:
        """Support all types for a simple injected test provider."""
        return True

    async def lookup(self, ioc: IOC) -> EnrichmentResult:
        """Return synthetic verdicts, including unsafe content for escaping tests."""
        self.calls += 1
        verdict = (
            "malicious"
            if ioc.value.startswith("alpha")
            else "clean"
            if ioc.value.startswith("beta")
            else "unknown"
        )
        return EnrichmentResult(
            self.name,
            "ok",
            verdict,
            ("Synthetic evidence <script>alert(1)</script>",),
            {"count": 2},
            link="javascript:alert(1)",
        )


@pytest.fixture
def source() -> SyntheticSource:
    """Provide fresh call state for each test."""
    return SyntheticSource()


@pytest.fixture
def client(source: SyntheticSource) -> Iterator[TestClient]:
    """Run app lifespan with an injected provider, never environment credentials."""
    with TestClient(create_app(EnrichmentEngine([source]))) as browser:
        yield browser


def session_token(client: TestClient) -> str:
    """Read the public form CSRF token after starting a browser session."""
    page = client.get("/")
    assert page.status_code == 200
    match = re.search(r'name="csrf" value="([^"]+)"', page.text)
    assert match
    return match.group(1)


def analyze(client: TestClient, text: str, *, enrich: bool = False) -> dict:
    """Start a synthetic report using the documented session API."""
    token = session_token(client)
    response = client.post(
        "/api/analyze", json={"text": text, "enrich": enrich}, headers={"X-CSRF-Token": token}
    )
    assert response.status_code == 202, response.text
    return response.json()


def completed(client: TestClient, report_id: str) -> dict:
    """Poll deterministic local jobs until done, bounding test failures."""
    for _ in range(100):
        response = client.get(f"/api/reports/{report_id}")
        assert response.status_code == 200
        report = response.json()
        if not report["pending"]:
            return report
    raise AssertionError("Synthetic enrichment did not finish")


def test_home_and_local_assets(client: TestClient) -> None:
    """Home page has all input modes, local assets and private session headers."""
    response = client.get("/")
    assert all(f'name="{name}"' in response.text for name in ("text", "upload", "url", "enrich"))
    assert "httponly" in response.headers["set-cookie"].lower()
    assert "samesite=strict" in response.headers["set-cookie"].lower()
    assert response.headers["cache-control"] == "no-store"
    assert "script-src 'self'" in response.headers["content-security-policy"]
    for path in ("app.css", "app.js", "htmx.min.js"):
        assert client.get(f"/static/{path}").status_code == 200
    assert "cdn.jsdelivr.net" not in response.text


def test_offline_extraction_and_unknown_score(client: TestClient, source: SyntheticSource) -> None:
    """Extraction returns normalized IOCs without calling providers or assigning clean."""
    report = analyze(client, "Example[.]com EXAMPLE.com")
    assert len(report["cards"]) == 1
    card = report["cards"][0]
    assert card["ioc"]["value"] == "example.com"
    assert card["assessment"]["verdict"] == "unknown" and card["assessment"]["score"] is None
    assert not report["pending"] and source.calls == 0
    assert "owner" not in report


def test_enrichment_cards_and_escaping(client: TestClient, source: SyntheticSource) -> None:
    """Background enrichment updates cards; all source content is escaped and safe linked."""
    report = analyze(client, "alpha.example.com <script>alert(1)</script>", enrich=True)
    done = completed(client, report["id"])
    assert done["cards"][0]["assessment"]["score"] == 100
    response = client.get(f"/reports/{report['id']}/results", headers={"HX-Request": "true"})
    assert response.status_code == 200
    assert "<!doctype" not in response.text
    assert "&lt;script&gt;" in response.text
    assert "<script>alert(1)</script>" not in response.text
    assert 'href="javascript:' not in response.text
    assert "Synthetic evidence" in response.text and "Why this score?" in response.text
    assert source.calls == 1


def test_filters_sorting_and_table_do_not_repeat_lookups(
    client: TestClient,
    source: SyntheticSource,
) -> None:
    """Filtering and view switches use stored report evidence with unknown scores last."""
    report = analyze(client, "gamma.example.com beta.example.com alpha.example.com", enrich=True)
    completed(client, report["id"])
    route = f"/reports/{report['id']}/results"
    response = client.get(route, params={"view": "table", "sort": "score", "order": "desc"})
    assert "<table>" in response.text
    rows = re.findall(r'<tr data-card-id="(\d+)"', response.text)
    assert rows == ["2", "1", "0"]
    response = client.get(route, params={"view": "table", "sort": "score", "order": "asc"})
    assert re.findall(r'<tr data-card-id="(\d+)"', response.text) == ["1", "2", "0"]
    response = client.get(route, params={"verdict": "malicious"})
    assert "Showing 1 of 3" in response.text
    assert 'data-card-id="2"' in response.text and 'data-card-id="1"' not in response.text
    assert source.calls == 3


def test_false_positive_keeps_evidence_and_score(client: TestClient) -> None:
    """Annotations are idempotent, reversible and independent of source scoring."""
    report = analyze(client, "alpha.example.com", enrich=True)
    before = completed(client, report["id"])["cards"][0]
    route = f"/api/reports/{report['id']}/cards/0/false-positive"
    token = session_token(client)
    for flagged in (True, True, False):
        response = client.post(
            route, json={"false_positive": flagged}, headers={"X-CSRF-Token": token}
        )
        assert response.status_code == 200
        card = response.json()
        assert card["false_positive"] == flagged
        assert card["assessment"] == before["assessment"] and card["evidence"] == before["evidence"]


def test_false_positive_form_and_review_filter(client: TestClient) -> None:
    """HTMX review controls update their view and preserve the chosen filter."""
    report = analyze(client, "example.com")
    response = client.post(
        f"/reports/{report['id']}/cards/0/false-positive?view=table",
        data={"csrf": session_token(client), "false_positive": "true"},
        headers={"HX-Request": "true"},
    )
    assert response.status_code == 200 and "<table>" in response.text
    assert "Clear false positive" in response.text
    response = client.get(f"/reports/{report['id']}/results?review=unflagged")
    assert "Showing 0 of 1" in response.text


def test_upload_and_url_inputs(client: TestClient) -> None:
    """UTF-8 text files and URL indicators use the same extraction pipeline."""
    token = session_token(client)
    response = client.post(
        "/analyze",
        data={"csrf": token, "filter_noise": "on", "url": "https://example.org/path"},
        files={"upload": ("synthetic.txt", b"example[.]com", "text/plain")},
        headers={"HX-Request": "true"},
    )
    assert response.status_code == 200
    assert "3 indicators extracted" in response.text
    assert "https://example.org/path" in response.text and "example.com" in response.text


@pytest.mark.parametrize(
    "filename,body", [("binary.txt", b"\xff\xfe\x00"), ("report.pdf", b"%PDF synthetic")]
)
def test_invalid_upload(client: TestClient, filename: str, body: bytes) -> None:
    """Unsupported uploads show useful errors rather than raw tracebacks."""
    response = client.post(
        "/analyze",
        data={"csrf": session_token(client)},
        files={"upload": (filename, body)},
        headers={"HX-Request": "true"},
    )
    assert response.status_code == 200 and 'role="alert"' in response.text


def test_input_limits_and_validation(client: TestClient) -> None:
    """Bound byte size, IOC count, blank input and malformed URL submissions."""
    token = session_token(client)
    headers = {"X-CSRF-Token": token}
    for body in (
        {"text": " "},
        {"url": "file:///etc/passwd"},
        {"text": " ".join(f"host{i}.example.com" for i in range(51))},
    ):
        assert client.post("/api/analyze", json=body, headers=headers).status_code == 422
    response = client.post(
        "/api/analyze", json={"text": "é" * (MAX_INPUT_BYTES // 2 + 1)}, headers=headers
    )
    assert response.status_code == 413
    response = client.post(
        "/api/analyze", json={"text": "a" * (MAX_INPUT_BYTES * 2)}, headers=headers
    )
    assert response.status_code == 413


def test_sessions_csrf_and_cross_origin(client: TestClient) -> None:
    """Browser reports are session-scoped and mutations require a same-origin token."""
    assert client.post("/api/analyze", json={"text": "example.com"}).status_code == 403
    token = session_token(client)
    assert (
        client.post(
            "/api/analyze", json={"text": "example.com"}, headers={"X-CSRF-Token": "invalid"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/analyze",
            json={"text": "example.com"},
            headers={
                "X-CSRF-Token": token,
                "Origin": "https://example.org",
            },
        ).status_code
        == 403
    )
    report = analyze(client, "example.com")
    client.cookies.clear()
    session_token(client)
    assert client.get(f"/api/reports/{report['id']}").status_code == 404


def test_invalid_report_card_and_filter(client: TestClient) -> None:
    """Missing report IDs, card IDs and invalid filter enums fail explicitly."""
    report = analyze(client, "example.com")
    assert client.get("/api/reports/missing").status_code == 404
    assert client.get(f"/reports/{report['id']}/results?sort=invalid").status_code == 422
    response = client.post(
        f"/api/reports/{report['id']}/cards/99/false-positive",
        json={"false_positive": True},
        headers={"X-CSRF-Token": session_token(client)},
    )
    assert response.status_code == 404


def test_whitelist_option(tmp_path: Path, source: SyntheticSource) -> None:
    """App factory loads a configured whitelist and respects the UI/API toggle."""
    path = tmp_path / "benign.txt"
    path.write_text("example.com\n", encoding="utf-8")
    with TestClient(create_app(EnrichmentEngine([source]), whitelist_path=path)) as client:
        token = session_token(client)
        headers = {"X-CSRF-Token": token}
        response = client.post("/api/analyze", json={"text": "example.com"}, headers=headers)
        assert response.json()["cards"] == []
        response = client.post(
            "/api/analyze", json={"text": "example.com", "filter_noise": False}, headers=headers
        )
        assert len(response.json()["cards"]) == 1


def test_default_lifespan_without_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Default startup uses environment-only adapters and closes its SQLite cache."""
    for key in (
        "VT_API_KEY",
        "ABUSEIPDB_API_KEY",
        "OTX_API_KEY",
        "ABUSECH_AUTH_KEY",
        "GREYNOISE_API_KEY",
        "MISP_API_KEY",
    ):
        monkeypatch.setenv(key, "")

    async def no_network(*args: object, **kwargs: object) -> httpx.Response:
        return httpx.Response(404, json={"detail": "Synthetic no record"})

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", no_network)
    path = tmp_path / "cache.db"
    with TestClient(create_app(cache_path=path)) as client:
        report = analyze(client, "example.com", enrich=True)
        done = completed(client, report["id"])
        assert done["cards"][0]["assessment"]["verdict"] == "unknown"
        assert all(
            r["status"] in {"disabled", "unsupported", "not_found"}
            for r in done["cards"][0]["evidence"]
        )
        assert client.cookies.get(COOKIE)
    assert path.exists()


def test_pending_poll_and_shutdown_cancellation() -> None:
    """Pending reports poll while shutdown cleanly cancels unfinished enrichment."""

    class StalledSource(SyntheticSource):
        async def lookup(self, ioc: IOC) -> EnrichmentResult:
            """Wait until app shutdown cancels this synthetic lookup."""
            await asyncio.Event().wait()
            raise AssertionError("Unreachable")

    with TestClient(create_app(EnrichmentEngine([StalledSource()], timeout=100))) as client:
        report = analyze(client, "example.com", enrich=True)
        assert report["pending"]
        response = client.get(f"/reports/{report['id']}/results", headers={"HX-Request": "true"})
        assert 'hx-trigger="every 1s"' in response.text and "Pending" in response.text


def test_streamed_body_limit_before_routing() -> None:
    """Chunked bodies cannot bypass the byte limit or reach JSON/multipart parsers."""

    async def scenario() -> None:
        messages = iter(
            [
                {"type": "http.request", "body": b"a" * MAX_INPUT_BYTES, "more_body": True},
                {"type": "http.request", "body": b"b" * 65_537, "more_body": False},
            ]
        )
        sent = []

        async def receive() -> dict:
            return next(messages)

        async def send(message: dict) -> None:
            sent.append(message)

        async def never_route(scope: dict, receive: Receive, send: Send) -> None:
            raise AssertionError("Oversized input reached the app")

        await BodyLimitMiddleware(never_route)({"type": "http", "method": "POST"}, receive, send)
        assert sent[0]["status"] == 413

    asyncio.run(scenario())


def test_form_errors_without_javascript(client: TestClient) -> None:
    """Progressive enhancement also provides meaningful full-page validation errors."""
    response = client.post("/analyze", data={"csrf": session_token(client), "text": " "})
    assert response.status_code == 422
    assert "<!doctype html>" in response.text and 'role="alert"' in response.text


def test_defanged_url_input(client: TestClient) -> None:
    """URL input accepts the same defanged separators as pasted report text."""
    response = client.post(
        "/api/analyze",
        json={"url": "hxxps[:]//example[.]com/path"},
        headers={"X-CSRF-Token": session_token(client)},
    )
    assert response.status_code == 202
    assert response.json()["cards"][0]["ioc"]["value"] == "https://example.com/path"
    response = client.post(
        "/api/analyze",
        json={"url": "https://example.com:99999/"},
        headers={"X-CSRF-Token": session_token(client)},
    )
    assert response.status_code == 422


def test_report_capacity(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """The process report cap prevents unbounded memory use without evicting active reports."""
    monkeypatch.setattr("ioc_extractor_enricher.app.MAX_REPORTS", 1)
    first = analyze(client, "example.com")
    response = client.post(
        "/api/analyze",
        json={"text": "example.org"},
        headers={"X-CSRF-Token": session_token(client)},
    )
    assert response.status_code == 429
    assert client.get(f"/api/reports/{first['id']}").status_code == 200


def test_report_job_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """A report timeout marks unfinished cards unknown and retains its explanation."""
    monkeypatch.setattr("ioc_extractor_enricher.app.JOB_TIMEOUT", 0.01)

    class StalledSource(SyntheticSource):
        async def lookup(self, ioc: IOC) -> EnrichmentResult:
            """Simulate a source blocked in its queue beyond the report lifetime."""
            await asyncio.Event().wait()
            raise AssertionError("Unreachable")

    with TestClient(create_app(EnrichmentEngine([StalledSource()], timeout=100))) as client:
        report = analyze(client, "example.com", enrich=True)
        card = completed(client, report["id"])["cards"][0]
        assert card["assessment"]["score"] is None
        assert card["assessment"]["verdict"] == "unknown"
        assert card["evidence"][0]["status"] == "timeout"
