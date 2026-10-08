"""Remaining source adapters use only mocked HTTP and synthetic provider evidence."""

import asyncio
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs

import httpx
import pytest

from ioc_extractor_enricher.enrichment import RDAP, GreyNoise, InternetDB, MalwareBazaar, URLhaus
from ioc_extractor_enricher.models import IOC

CASES = [
    (
        URLhaus,
        IOC("url", "https://example.com/payload", ""),
        {"query_status": "ok", "threat": "malware_download", "url_status": "offline"},
        "malicious",
    ),
    (
        URLhaus,
        IOC("domain", "example.com", ""),
        {"query_status": "ok", "url_count": "2"},
        "suspicious",
    ),
    (
        MalwareBazaar,
        IOC("sha256", "a" * 64, ""),
        {"query_status": "ok", "data": [{"sha256_hash": "a" * 64, "signature": "Synthetic"}]},
        "malicious",
    ),
    (
        InternetDB,
        IOC("ipv4", "8.8.8.8", ""),
        {"ip": "8.8.8.8", "ports": [443], "vulns": [], "hostnames": [], "cpes": [], "tags": []},
        "unknown",
    ),
    (
        GreyNoise,
        IOC("ipv4", "8.8.8.8", ""),
        {"ip": "8.8.8.8", "noise": True, "riot": False, "classification": "malicious"},
        "malicious",
    ),
    (
        RDAP,
        IOC("domain", "sub.example.com", ""),
        {
            "ldhName": "example.com",
            "events": [
                {
                    "eventAction": "registration",
                    "eventDate": (datetime.now(UTC) - timedelta(days=5)).isoformat(),
                }
            ],
        },
        "suspicious",
    ),
]


@pytest.fixture(autouse=True)
def synthetic_keys(monkeypatch):
    """Never consume local provider credentials, including during malformed-response tests."""
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "synthetic-key")
    monkeypatch.setenv("GREYNOISE_API_KEY", "synthetic-key")


@pytest.mark.parametrize("adapter,ioc,payload,verdict", CASES)
def test_lookup_and_request_shape(adapter, ioc, payload, verdict):
    """Adapters normalize documented evidence and use fixed provider endpoints."""
    calls = []

    def respond(request):
        calls.append(request)
        assert request.url.scheme == "https"
        if adapter in (URLhaus, MalwareBazaar):
            assert request.method == "POST" and request.headers["Auth-Key"] == "synthetic-key"
            form = parse_qs(request.content.decode())
            if adapter is MalwareBazaar:
                assert form == {"query": ["get_info"], "hash": [ioc.value]}
            else:
                assert form == {"url" if ioc.type == "url" else "host": [ioc.value]}
        elif adapter in (RDAP, InternetDB):
            assert "Authorization" not in request.headers and "key" not in request.headers
        elif adapter is GreyNoise:
            assert request.headers["key"] == "synthetic-key"
        if adapter is RDAP:
            assert request.url.path.endswith("/domain/example.com")
        return httpx.Response(200, json=payload)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await adapter(client).lookup(ioc)
            assert result.status == "ok" and result.verdict == verdict
            assert result.reasons and "synthetic-key" not in repr(result)

    asyncio.run(run())
    assert len(calls) == 1


@pytest.mark.parametrize("adapter,ioc,payload,verdict", CASES)
@pytest.mark.parametrize(
    "status,expected",
    [(404, "not_found"), (429, "rate_limited"), (403, "error"), (302, "error"), (500, "error")],
)
def test_shared_failure_contract(adapter, ioc, payload, verdict, status, expected):
    """All providers fail independently with unknown verdicts and without redirecting keys."""
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(
            status,
            text="synthetic-key",
            headers={"Retry-After": "7", "Location": "https://other.example.com"},
        )

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(respond), follow_redirects=True
        ) as client:
            result = await adapter(client).lookup(ioc)
            assert result.status == expected and result.verdict == "unknown"
            assert "synthetic-key" not in repr(result)
            if status == 429:
                assert result.retry_after == 7

    asyncio.run(run())
    assert len(calls) == 1


@pytest.mark.parametrize("adapter,ioc,payload,verdict", CASES)
def test_malformed_and_timeout(adapter, ioc, payload, verdict):
    """Malformed bodies and transport timeouts are safe normalized failures."""

    async def run():
        for body in ({}, [], {"query_status": "ok", "data": []}):
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(
                    lambda request, body=body: httpx.Response(200, json=body)
                )
            ) as client:
                assert (await adapter(client).lookup(ioc)).status == "error"

        def timed_out(request):
            raise httpx.ReadTimeout("synthetic-key")

        async with httpx.AsyncClient(transport=httpx.MockTransport(timed_out)) as client:
            result = await adapter(client).lookup(ioc)
            assert result.status == "timeout" and "synthetic-key" not in repr(result)

    asyncio.run(run())


@pytest.mark.parametrize(
    "adapter,key",
    [
        (URLhaus, "ABUSECH_AUTH_KEY"),
        (MalwareBazaar, "ABUSECH_AUTH_KEY"),
        (GreyNoise, "GREYNOISE_API_KEY"),
    ],
)
def test_missing_keys_disabled(monkeypatch, adapter, key):
    """Missing/placeholder keys cause no lookup, while unsupported types stay explicit."""
    monkeypatch.setenv(key, "...")

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: pytest.fail("Unexpected HTTP"))
        ) as client:
            plugin = adapter(client)
            kind = next(iter(plugin.types))
            assert (await plugin.lookup(IOC(kind, "synthetic", ""))).status == "disabled"
            assert (await plugin.lookup(IOC("email", "a@example.com", ""))).status == "unsupported"

    asyncio.run(run())


def test_conservative_context_mapping():
    """Age, exposure and RIOT records alone do not imply clean evidence."""

    async def run():
        async with httpx.AsyncClient() as client:
            ip = IOC("ipv4", "8.8.8.8", "")
            gn = GreyNoise(client)
            assert (
                gn.parse(
                    ip, {"ip": ip.value, "noise": False, "riot": True, "classification": "unknown"}
                ).verdict
                == "unknown"
            )
            assert (
                gn.parse(
                    ip, {"ip": ip.value, "noise": True, "riot": False, "classification": "unknown"}
                ).verdict
                == "suspicious"
            )
            assert (
                gn.parse(
                    ip, {"ip": ip.value, "noise": False, "riot": True, "classification": "benign"}
                ).verdict
                == "clean"
            )
            db = InternetDB(client)
            payload = {
                "ip": ip.value,
                "ports": [22],
                "hostnames": [],
                "tags": [],
                "cpes": [],
                "vulns": ["CVE-2026-1234"],
            }
            assert db.parse(ip, payload).verdict == "suspicious"
            with pytest.raises(ValueError):
                db.parse(ip, payload | {"ip": "1.1.1.1"})
            domain = IOC("domain", "sub.example.com", "")
            rdap = RDAP(client)
            for days in (100, -1):
                result = rdap.parse(
                    domain,
                    {
                        "ldhName": "example.com",
                        "events": [
                            {
                                "eventAction": "registration",
                                "eventDate": (datetime.now(UTC) - timedelta(days=days)).isoformat(),
                            }
                        ],
                    },
                )
                assert result.verdict == "unknown"
            assert rdap.parse(domain, {"ldhName": "example.com"}).verdict == "unknown"
            with pytest.raises(ValueError):
                rdap.parse(domain, {"ldhName": "different.com"})
            with pytest.raises(ValueError):
                rdap.endpoint(IOC("domain", "example.invalid", ""))
            assert not rdap.supports("ipv4") and not db.supports("ipv6")

    asyncio.run(run())


@pytest.mark.parametrize(
    "adapter,ioc,payload",
    [
        (URLhaus, IOC("url", "https://example.com", ""), {"query_status": "no_results"}),
        (MalwareBazaar, IOC("sha256", "a" * 64, ""), {"query_status": "hash_not_found"}),
    ],
)
def test_no_record_never_clean(adapter, ioc, payload):
    """Provider no-record response shapes retain unknown verdicts."""

    async def run():
        async with httpx.AsyncClient() as client:
            result = adapter(client).parse(ioc, payload)
            assert result.status == "not_found" and result.verdict == "unknown"

    asyncio.run(run())


@pytest.mark.parametrize("kind,field,length", [("md5", "md5_hash", 32), ("sha1", "sha1_hash", 40)])
def test_malwarebazaar_alternate_hashes(kind, field, length):
    """Alternate hashes must match the requested value, not merely any returned sample."""

    async def run():
        async with httpx.AsyncClient() as client:
            adapter = MalwareBazaar(client)
            ioc = IOC(kind, "b" * length, "")
            payload = {"query_status": "ok", "data": [{field: ioc.value, "sha256_hash": "a" * 64}]}
            assert adapter.parse(ioc, payload).verdict == "malicious"
            payload["data"][0][field] = "c" * length
            with pytest.raises(ValueError):
                adapter.parse(ioc, payload)

    asyncio.run(run())
