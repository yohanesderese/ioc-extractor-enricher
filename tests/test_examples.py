"""Validate published synthetic examples against the extractor, scorer and STIX schema."""

import asyncio
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import httpx
import pytest
from stix2 import parse

from ioc_extractor_enricher.enrichment import EnrichmentEngine
from ioc_extractor_enricher.exports import export_csv, export_json

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def demo_module() -> ModuleType:
    """Load the documented standalone demo without starting its server."""
    spec = importlib.util.spec_from_file_location("iocdesk_demo", EXAMPLES / "demo.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_published_examples_match_fixture() -> None:
    """All nine types and committed JSON/CSV are derived from the same synthetic text."""
    items = demo_module().sample_items()
    assert {item.ioc.type for item in items} == {
        "ipv4",
        "ipv6",
        "domain",
        "url",
        "md5",
        "sha1",
        "sha256",
        "email",
        "cve",
    }
    assert (EXAMPLES / "exports/synthetic.json").read_text(encoding="utf-8") == export_json(items)
    # read_text normalizes CSV CRLF newlines; compare text consistently.
    assert (EXAMPLES / "exports/synthetic.csv").read_text(encoding="utf-8") == export_csv(
        items
    ).replace("\r\n", "\n")
    assert {item.assessment.verdict for item in items} == {
        "malicious",
        "suspicious",
        "clean",
        "unknown",
    }
    assert all(item.assessment.verdict == "unknown" for item in items if item.ioc.type != "domain")


def test_published_stix_validates_and_preserves_notes() -> None:
    """Notes preserve every assessment and only fabricated risky domains get indicators."""
    bundle = parse((EXAMPLES / "exports/synthetic.stix.json").read_text(encoding="utf-8"))
    notes = [json.loads(obj.content) for obj in bundle.objects if obj.type == "note"]
    assert notes == json.loads((EXAMPLES / "exports/synthetic.json").read_text(encoding="utf-8"))
    indicators = [obj for obj in bundle.objects if obj.type == "indicator"]
    assert len(indicators) == 2
    assert all("SIMULATED" in result["evidence"][0]["reasons"][0] for result in notes)


def test_demo_enrichment_is_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulated enrichment works while all live HTTP transports are forbidden."""

    async def forbidden(*args: object, **kwargs: object) -> httpx.Response:
        raise AssertionError("The demo must not make live HTTP requests")

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)
    demo = demo_module()

    async def run() -> None:
        items = demo.sample_items()
        results = await EnrichmentEngine([demo.DemoSource()]).enrich_many(
            [item.ioc for item in items]
        )
        assert len(results) == len(items)
        assert all(evidence[0].source == "demo" for evidence in results)
        assert all(evidence[0].facts == {"synthetic": True} for evidence in results)

    asyncio.run(run())
