"""Session-private downloads and explicit, replay-safe MISP web actions."""

import asyncio

import httpx
from fastapi.testclient import TestClient
from test_web import SyntheticSource, analyze, completed, session_token

from ioc_extractor_enricher.app import create_app
from ioc_extractor_enricher.enrichment import EnrichmentEngine
from ioc_extractor_enricher.misp import MISPClient


def test_owned_downloads_filters_and_evidence():
    """Downloads use stored evidence and display filters without repeated provider calls."""
    source = SyntheticSource()
    with TestClient(create_app(EnrichmentEngine([source]))) as client:
        report = analyze(client, "alpha.example.com beta.example.com", enrich=True)
        completed(client, report["id"])
        path = f"/reports/{report['id']}/export"
        response = client.get(f"{path}/json?verdict=malicious")
        assert response.status_code == 200 and len(response.json()) == 1
        assert response.json()[0]["ioc"]["value"] == "alpha.example.com"
        assert "attachment" in response.headers["Content-Disposition"]
        assert "owner" not in response.text and "csrf" not in response.text
        for format in ("csv", "stix"):
            assert client.get(f"{path}/{format}").status_code == 200
        assert client.get(f"{path}/invalid").status_code == 422
        assert source.calls == 2
        client.cookies.clear()
        session_token(client)
        assert client.get(f"{path}/json").status_code == 404


def test_pending_download_and_push_rejected():
    """Pending evidence cannot be exported or sent to MISP."""

    class StalledSource(SyntheticSource):
        async def lookup(self, ioc):
            """Remain pending until shutdown cancels the synthetic job."""
            await asyncio.Event().wait()

    with TestClient(create_app(EnrichmentEngine([StalledSource()], timeout=100))) as client:
        report = analyze(client, "example.com", enrich=True)
        assert client.get(f"/reports/{report['id']}/export/json").status_code == 409
        assert (
            client.post(
                f"/api/reports/{report['id']}/misp",
                json={"confirm": True},
                headers={"X-CSRF-Token": session_token(client)},
            ).status_code
            == 409
        )


def test_explicit_push_csrf_confirmation_and_replay(monkeypatch):
    """Analysis never writes remotely; an explicit push excludes flags and is sent once."""
    monkeypatch.setenv("MISP_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_API_KEY", "synthetic-key")
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(201, json={"Event": {"id": "42"}})

    remote = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        with TestClient(
            create_app(EnrichmentEngine([SyntheticSource()]), misp=MISPClient(remote))
        ) as client:
            report = analyze(client, "alpha.example.com beta.example.com", enrich=True)
            completed(client, report["id"])
            token = session_token(client)
            headers = {"X-CSRF-Token": token}
            assert calls == []
            client.post(
                f"/api/reports/{report['id']}/cards/1/false-positive",
                json={"false_positive": True},
                headers=headers,
            )
            path = f"/api/reports/{report['id']}/misp"
            assert client.post(path, json={"confirm": True}).status_code == 403
            assert client.post(path, json={"confirm": False}, headers=headers).status_code == 422
            for _ in range(2):
                response = client.post(path, json={"confirm": True}, headers=headers)
                assert response.status_code == 200 and response.json()["status"] == "success"
            assert len(calls) == 1
            import json

            attributes = json.loads(calls[0].content)["Event"]["Attribute"]
            assert len(attributes) == 1 and attributes[0]["value"] == "alpha.example.com"
            page = client.get(f"/reports/{report['id']}/results")
            assert "View MISP event" in page.text
            assert "synthetic-key" not in page.text
    finally:
        asyncio.run(remote.aclose())


def test_disabled_push():
    """Unconfigured MISP is a clear UI/API state with no external writes."""
    with TestClient(create_app(EnrichmentEngine([]))) as client:
        report = analyze(client, "example.com")
        response = client.post(
            f"/api/reports/{report['id']}/misp",
            json={"confirm": True},
            headers={"X-CSRF-Token": session_token(client)},
        )
        assert response.status_code == 409
        assert "MISP push is disabled" in client.get(f"/reports/{report['id']}/results").text


def test_misp_form_and_failed_attempt_replay(monkeypatch):
    """An explicitly submitted timeout stays visible and cannot cause another write."""
    monkeypatch.setenv("MISP_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_API_KEY", "synthetic-key")
    calls = []

    def respond(request):
        calls.append(request)
        raise httpx.ReadTimeout("synthetic-key")

    remote = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        with TestClient(create_app(EnrichmentEngine([]), misp=MISPClient(remote))) as client:
            report = analyze(client, "example.com")
            path = f"/reports/{report['id']}/misp?view=table"
            token = session_token(client)
            assert client.post(path, data={"csrf": token}).status_code == 422
            for _ in range(2):
                response = client.post(
                    path, data={"csrf": token, "confirm": "on"}, headers={"HX-Request": "true"}
                )
                assert response.status_code == 200 and "<table>" in response.text
                assert "Check MISP" in response.text and "synthetic-key" not in response.text
            assert len(calls) == 1
    finally:
        asyncio.run(remote.aclose())


def test_concurrent_pushes_share_one_attempt(monkeypatch):
    """The per-report lock coalesces concurrent browser submissions into a single event."""
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setenv("MISP_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_API_KEY", "synthetic-key")
    calls = []

    async def respond(request):
        calls.append(request)
        await asyncio.sleep(0.03)
        return httpx.Response(201, json={"Event": {"id": 42}})

    remote = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    try:
        with TestClient(create_app(EnrichmentEngine([]), misp=MISPClient(remote))) as client:
            report = analyze(client, "example.com")
            token = session_token(client)

            def submit():
                return client.post(
                    f"/api/reports/{report['id']}/misp",
                    json={"confirm": True},
                    headers={"X-CSRF-Token": token},
                )

            with ThreadPoolExecutor(max_workers=2) as workers:
                results = list(workers.map(lambda _: submit(), range(2)))
            assert all(response.json()["status"] == "success" for response in results)
            assert len(calls) == 1
    finally:
        asyncio.run(remote.aclose())
