"""Synthetic provider responses and async engine failure-isolation tests."""

import asyncio
import base64
import json
from dataclasses import asdict
from pathlib import Path
from urllib.parse import quote

import httpx
import pytest

from ioc_extractor_enricher.cache import SQLiteCache
from ioc_extractor_enricher.enrichment import (
    OTX,
    AbuseIPDB,
    EnrichmentEngine,
    EnrichmentResult,
    VirusTotal,
)
from ioc_extractor_enricher.enrichment.base import HTTPPlugin, retry_delay
from ioc_extractor_enricher.models import IOC, IOCType
from ioc_extractor_enricher.rate_limit import RateLimiter

IP = IOC("ipv4", "8.8.8.8", "Synthetic test context")
SYNTHETIC_KEY = "synthetic-test-token"
PROVIDERS = [VirusTotal, AbuseIPDB, OTX]


@pytest.fixture(autouse=True)
def synthetic_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use synthetic keys and forbid live httpx requests in enrichment tests."""
    for name in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY"):
        monkeypatch.setenv(name, SYNTHETIC_KEY)

    async def forbid_network(*args: object, **kwargs: object) -> httpx.Response:
        raise AssertionError("Tests must use MockTransport")

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbid_network)


def vt_payload(malicious: int = 0, suspicious: int = 0, harmless: int = 0) -> dict:
    """Build minimal analysis counts without provider or employer data."""
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": 5,
                }
            }
        }
    }


@pytest.mark.parametrize(
    "kind,value,path",
    [
        ("ipv4", "8.8.8.8", "ip_addresses/8.8.8.8"),
        ("ipv6", "2606:4700:4700::1111", "ip_addresses/2606%3A4700%3A4700%3A%3A1111"),
        ("domain", "example.com", "domains/example.com"),
        ("md5", "a" * 32, "files/" + "a" * 32),
        ("sha1", "b" * 40, "files/" + "b" * 40),
        ("sha256", "c" * 64, "files/" + "c" * 64),
    ],
)
def test_virustotal_routes(kind: IOCType, value: str, path: str) -> None:
    """Every supported non-URL type uses the correct v3 report endpoint."""

    async def scenario() -> None:
        def respond(request: httpx.Request) -> httpx.Response:
            assert request.method == "GET"
            assert request.url.raw_path.decode() == "/api/v3/" + path
            assert request.headers["x-apikey"] == SYNTHETIC_KEY
            assert SYNTHETIC_KEY not in str(request.url)
            return httpx.Response(200, json=vt_payload(malicious=2))

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await VirusTotal(client).lookup(IOC(kind, value, ""))
            assert result.verdict == "malicious"
            assert result.facts["malicious"] == 2
            assert result.reasons and result.link

    asyncio.run(scenario())


def test_virustotal_url_identifier() -> None:
    """URL reports use unpadded URL-safe base64, preserving case in paths."""

    async def scenario() -> None:
        url = "https://example.com/Case?q=A"
        identifier = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

        def respond(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/v3/urls/" + identifier
            return httpx.Response(200, json=vt_payload(suspicious=1))

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await VirusTotal(client).lookup(IOC("url", url, ""))
            assert result.verdict == "suspicious"
            assert result.link == "https://www.virustotal.com/gui/url/" + identifier

    asyncio.run(scenario())


@pytest.mark.parametrize("harmless,verdict", [(3, "clean"), (0, "unknown")])
def test_virustotal_no_detections(harmless: int, verdict: str) -> None:
    """Undetected alone is not positive clean evidence."""

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json=vt_payload(harmless=harmless))
            )
        ) as client:
            assert (await VirusTotal(client).lookup(IP)).verdict == verdict

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "confidence,reports,verdict",
    [
        (90, 4, "malicious"),
        (25, 2, "suspicious"),
        (0, 1, "suspicious"),
        (0, 0, "unknown"),
    ],
)
def test_abuseipdb_evidence(confidence: int, reports: int, verdict: str) -> None:
    """Abuse confidence and report counts remain explainable and bounded."""

    async def scenario() -> None:
        def respond(request: httpx.Request) -> httpx.Response:
            assert request.url.host == "api.abuseipdb.com"
            assert request.url.params == httpx.QueryParams(
                {
                    "ipAddress": "2606:4700:4700::1111",
                    "maxAgeInDays": "90",
                }
            )
            assert request.headers["Key"] == SYNTHETIC_KEY
            return httpx.Response(
                200,
                json={
                    "data": {
                        "abuseConfidenceScore": confidence,
                        "totalReports": reports,
                        "countryCode": "ZZ",
                        "reports": [{"comment": "Do not retain"}],
                    }
                },
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await AbuseIPDB(client).lookup(IOC("ipv6", "2606:4700:4700::1111", ""))
            assert result.verdict == verdict
            assert result.facts["abuseConfidenceScore"] == confidence
            assert "reports" not in result.facts

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "kind,value,provider_kind",
    [
        ("ipv4", "8.8.8.8", "IPv4"),
        ("ipv6", "2606:4700:4700::1111", "IPv6"),
        ("domain", "example.com", "domain"),
        ("url", "https://example.com/a?b=c", "url"),
        ("md5", "a" * 32, "file"),
        ("sha1", "b" * 40, "file"),
        ("sha256", "c" * 64, "file"),
        ("cve", "CVE-2024-12345", "cve"),
    ],
)
def test_otx_routes(kind: IOCType, value: str, provider_kind: str) -> None:
    """OTX routes encode indicators as single path segments."""

    async def scenario() -> None:
        def respond(request: httpx.Request) -> httpx.Response:
            assert request.headers["X-OTX-API-KEY"] == SYNTHETIC_KEY
            expected = f"/api/v1/indicators/{provider_kind}/{quote(value, safe='')}/general"
            assert request.url.raw_path.decode() == expected
            return httpx.Response(200, json={"pulse_info": {"count": 2}})

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await OTX(client).lookup(IOC(kind, value, ""))
            assert result.verdict == "suspicious"
            assert result.facts == {"pulse_count": 2}

    asyncio.run(scenario())


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize(
    "code,status",
    [
        (404, "not_found"),
        (429, "rate_limited"),
        (401, "error"),
        (403, "error"),
        (503, "error"),
    ],
)
def test_http_failures(provider: type[HTTPPlugin], code: int, status: str) -> None:
    """Provider errors never expose raw bodies, keys or exception text."""

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    code, text=SYNTHETIC_KEY, headers={"Retry-After": "12"}
                )
            )
        ) as client:
            result = await provider(client).lookup(IP)
            assert result.status == status
            assert result.verdict == "unknown"
            assert SYNTHETIC_KEY not in json.dumps(asdict(result))
            if code == 429:
                assert result.retry_after == 12

    asyncio.run(scenario())


@pytest.mark.parametrize("provider", PROVIDERS)
def test_disabled_and_unsupported(
    provider: type[HTTPPlugin], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unconfigured sources and unsupported types never perform HTTP requests."""
    monkeypatch.setenv(provider.env_key, "")

    async def scenario() -> None:
        def no_request(request: httpx.Request) -> httpx.Response:
            raise AssertionError("Disabled source attempted a request")

        async with httpx.AsyncClient(transport=httpx.MockTransport(no_request)) as client:
            plugin = provider(client)
            assert (await plugin.lookup(IP)).status == "disabled"
            assert (await plugin.lookup(IOC("email", "user@example.com", ""))).status == (
                "unsupported"
            )
            engine = EnrichmentEngine([plugin])
            results = await engine.enrich_many([IP, IP])
            assert [r[0].status for r in results] == ["disabled", "disabled"]

    asyncio.run(scenario())


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("body", ["not JSON", "[]", "{}"])
def test_malformed_payload(provider: type[HTTPPlugin], body: str) -> None:
    """Invalid JSON and missing evidence are errors rather than clean verdicts."""

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, text=body))
        ) as client:
            result = await provider(client).lookup(IP)
            assert result.status == "error"
            assert result.verdict == "unknown"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "exception,status", [(httpx.ReadTimeout, "timeout"), (httpx.ConnectError, "error")]
)
def test_transport_failures(exception: type[httpx.RequestError], status: str) -> None:
    """Transport exceptions are normalized without leaking their message."""

    async def scenario() -> None:
        def respond(request: httpx.Request) -> httpx.Response:
            raise exception(SYNTHETIC_KEY, request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await VirusTotal(client).lookup(IP)
            assert result.status == status
            assert SYNTHETIC_KEY not in repr(result)

    asyncio.run(scenario())


def test_redirect_does_not_forward_key() -> None:
    """An injected redirect-enabled client cannot forward source authentication."""

    async def scenario() -> None:
        requests = []

        def respond(request: httpx.Request) -> httpx.Response:
            requests.append(request.url.host)
            return httpx.Response(302, headers={"Location": "https://example.com/"})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(respond), follow_redirects=True
        ) as client:
            assert (await VirusTotal(client).lookup(IP)).status == "error"
        assert requests == ["www.virustotal.com"]

    asyncio.run(scenario())


def test_engine_cache_coalesces_and_normalizes(tmp_path: Path) -> None:
    """Simultaneous equivalent indicators share a single provider request."""

    async def scenario() -> None:
        calls = 0

        def respond(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            assert request.url.path == "/api/v3/domains/example.com"
            return httpx.Response(200, json=vt_payload(malicious=1))

        async with SQLiteCache(tmp_path / "cache.db") as cache:
            async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
                engine = EnrichmentEngine([VirusTotal(client)], cache, intervals={"virustotal": 0})
                results = await engine.enrich_many(
                    [
                        IOC("domain", "EXAMPLE.COM", "first"),
                        IOC("domain", "example.com", "second"),
                    ]
                )
                assert calls == 1
                assert sum(r[0].cached for r in results) == 1
                assert (await engine.enrich(IOC("domain", "example.com", "")))[0].cached

    asyncio.run(scenario())


def test_engine_sources_run_independently() -> None:
    """A stalled source times out while another completes, preserving source order."""

    async def scenario() -> None:
        other_completed = asyncio.Event()

        async def respond(request: httpx.Request) -> httpx.Response:
            if request.url.host == "www.virustotal.com":
                await other_completed.wait()
                await asyncio.Event().wait()
            other_completed.set()
            return httpx.Response(200, json={"pulse_info": {"count": 1}})

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            engine = EnrichmentEngine(
                [VirusTotal(client), OTX(client)],
                timeout=0.02,
                intervals={"virustotal": 0, "otx": 0},
            )
            results = await engine.enrich(IP)
            assert [r.source for r in results] == ["virustotal", "otx"]
            assert [r.status for r in results] == ["timeout", "ok"]
            assert other_completed.is_set()

    asyncio.run(scenario())


def test_engine_plugin_failure_and_cache_failure(tmp_path: Path) -> None:
    """Unexpected plugin errors and broken caches cannot erase other source evidence."""

    class BrokenPlugin:
        name = "broken"
        interval = 0.0

        def supports(self, kind: IOCType) -> bool:
            """Support all types for this synthetic failing provider."""
            return True

        async def lookup(self, ioc: IOC) -> EnrichmentResult:
            """Simulate an exception containing details that must remain private."""
            raise RuntimeError(SYNTHETIC_KEY)

    async def scenario() -> None:
        cache = SQLiteCache(tmp_path / "cache.db")
        await cache.close()
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"pulse_info": {"count": 0}})
            )
        ) as client:
            engine = EnrichmentEngine([BrokenPlugin(), OTX(client)], cache)
            results = await engine.enrich(IP)
            assert [r.status for r in results] == ["error", "ok"]
            assert results[1].verdict == "unknown"
            assert SYNTHETIC_KEY not in repr(results)

    asyncio.run(scenario())


def test_engine_cancellation_releases_source() -> None:
    """Cancelled lookups propagate cancellation and do not poison the source queue."""

    async def scenario() -> None:
        started = asyncio.Event()
        calls = 0

        async def respond(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                started.set()
                await asyncio.Event().wait()
            return httpx.Response(200, json={"pulse_info": {"count": 1}})

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            engine = EnrichmentEngine([OTX(client)], intervals={"otx": 0})
            task = asyncio.create_task(engine.enrich(IP))
            await started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert (await engine.enrich(IP))[0].status == "ok"

    asyncio.run(scenario())


def test_retry_after_and_engine_cooldown() -> None:
    """429 cooldowns delay the next request, without retrying or caching the error."""
    assert retry_delay("12") == 12
    assert retry_delay("garbage") is None
    assert retry_delay("inf") is None
    assert retry_delay("Thu, 01 Jan 1970 00:00:00 GMT") == 0

    async def scenario() -> None:
        now = 100.0
        starts = []

        async def advance(delay: float) -> None:
            nonlocal now
            now += delay

        def respond(request: httpx.Request) -> httpx.Response:
            starts.append(now)
            if len(starts) == 1:
                return httpx.Response(429, headers={"Retry-After": "12"})
            return httpx.Response(200, json={"pulse_info": {"count": 0}})

        async with SQLiteCache(":memory:") as cache:
            async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
                engine = EnrichmentEngine([OTX(client)], cache)
                engine._limiters["otx"] = RateLimiter(1, clock=lambda: now, sleep=advance)
                assert (await engine.enrich(IP))[0].status == "rate_limited"
                assert (await engine.enrich(IP))[0].status == "ok"
                assert starts == [100, 112]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "provider,payload",
    [
        (VirusTotal, vt_payload(malicious=-1)),
        (VirusTotal, vt_payload(malicious=True)),
        (AbuseIPDB, {"data": {"abuseConfidenceScore": 101, "totalReports": 1}}),
        (OTX, {"pulse_info": {"count": "2"}}),
    ],
)
def test_invalid_evidence_counts(provider: type[HTTPPlugin], payload: dict) -> None:
    """Malformed counts must never turn into clean or actionable evidence."""

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
        ) as client:
            result = await provider(client).lookup(IP)
            assert result.status == "error" and result.verdict == "unknown"

    asyncio.run(scenario())


def test_adapter_wall_clock_timeout() -> None:
    """The adapter itself bounds slow transports even without the engine."""

    async def scenario() -> None:
        async def stalled(request: httpx.Request) -> httpx.Response:
            await asyncio.Event().wait()
            raise AssertionError("Unreachable")

        async with httpx.AsyncClient(transport=httpx.MockTransport(stalled)) as client:
            result = await OTX(client, timeout=0.01).lookup(IP)
            assert result.status == "timeout"

    asyncio.run(scenario())


def test_configuration_validation() -> None:
    """Duplicate source names, invalid delays and invalid result shapes are rejected."""

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(404))
        ) as client:
            with pytest.raises(ValueError):
                EnrichmentEngine([OTX(client), OTX(client)])
            with pytest.raises(ValueError):
                EnrichmentEngine([OTX(client)], timeout=0)
            with pytest.raises(ValueError):
                OTX(client, timeout=0)
            with pytest.raises(ValueError):
                EnrichmentResult("otx", "error", "clean")
            with pytest.raises(ValueError):
                EnrichmentResult("otx", "ok", facts={"nested": []})

    asyncio.run(scenario())
