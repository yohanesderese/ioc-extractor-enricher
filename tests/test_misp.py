"""MISP payload and transport tests use synthetic credentials and mocked HTTP."""

import asyncio
import json

import httpx
import pytest
from test_exports import item

from ioc_extractor_enricher.misp import MISPClient, build_event


def test_private_event_and_review_semantics():
    """Only unflagged values/scores are shared, with detection enabled for malicious IOCs."""
    event = build_event(
        [
            item(verdict="malicious", context="PRIVATE SENTENCE"),
            item(value="unknown.example.com"),
            item(verdict="clean"),
            item("cve", "CVE-2026-1234", "malicious"),
            item(flagged=True),
        ],
        "synthetic",
    )
    assert event["Event"]["distribution"] == 0 and event["Event"]["published"] is False
    attributes = event["Event"]["Attribute"]
    assert len(attributes) == 4 and [a["to_ids"] for a in attributes] == [True, False, False, False]
    assert "PRIVATE SENTENCE" not in json.dumps(event)
    assert build_event([item()], "synthetic")["Event"]["uuid"] == event["Event"]["uuid"]
    with pytest.raises(ValueError):
        build_event([item(flagged=True)], "empty")


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://misp.example.com",
        "https://user:pass@example.com",
        "https://misp.example.com?key=secret",
        "https://x:bad",
    ],
)
def test_invalid_configuration(monkeypatch, url):
    """Invalid configuration cannot initiate any remote write."""
    monkeypatch.setenv("MISP_URL", url)
    monkeypatch.setenv("MISP_API_KEY", "synthetic-key")

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: pytest.fail("Unexpected request"))
        ) as client:
            adapter = MISPClient(client)
            assert not adapter.configured
            assert (await adapter.push([item()], "test")).status == "disabled"

    asyncio.run(run())


@pytest.mark.parametrize(
    "status,payload,expected",
    [
        (201, {"Event": {"id": "42"}}, "success"),
        (200, {"Event": {"id": True}}, "error"),
        (200, {"Event": {"id": "../secret"}}, "error"),
        (200, {}, "error"),
        (403, {"error": "synthetic-key"}, "error"),
        (429, {}, "error"),
        (302, {}, "error"),
        (500, {}, "error"),
    ],
)
def test_push_transport(monkeypatch, status, payload, expected):
    """POST destination/auth are fixed; redirect/error bodies never leak into results."""
    monkeypatch.setenv("MISP_URL", "https://misp.example.com/base")
    monkeypatch.setenv("MISP_API_KEY", "synthetic-key")
    calls = []

    def respond(request):
        calls.append(request)
        assert (
            request.method == "POST"
            and str(request.url) == "https://misp.example.com/base/events/add"
        )
        assert request.headers["Authorization"] == "synthetic-key"
        assert json.loads(request.content)["Event"]["published"] is False
        return httpx.Response(
            status, json=payload, headers={"Location": "https://other.example.com"}
        )

    async def run():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(respond), follow_redirects=True
        ) as client:
            result = await MISPClient(client).push([item()], "test")
            assert result.status == expected and "synthetic-key" not in repr(result)
            if expected == "success":
                assert result.link == "https://misp.example.com/base/events/view/42"

    asyncio.run(run())
    assert len(calls) == 1


def test_timeout_is_uncertain_and_never_retried(monkeypatch):
    """A timeout may follow a successful remote creation; the adapter never retries."""
    monkeypatch.setenv("MISP_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_API_KEY", "synthetic-key")
    calls = []

    def respond(request):
        calls.append(request)
        raise httpx.ReadTimeout("synthetic-key")

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            result = await MISPClient(client).push([item()], "test")
            assert result.status == "timeout" and "Check MISP" in result.message
            assert "synthetic-key" not in repr(result)

    asyncio.run(run())
    assert len(calls) == 1
