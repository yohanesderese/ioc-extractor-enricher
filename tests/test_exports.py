"""Synthetic portable exports and conservative STIX semantics."""

import csv
import io
import json

import pytest
from stix2 import parse

from ioc_extractor_enricher.enrichment import EnrichmentResult
from ioc_extractor_enricher.exports import ExportItem, export_csv, export_json, export_stix
from ioc_extractor_enricher.models import IOC
from ioc_extractor_enricher.scorer import score_results


def item(kind="domain", value="example.com", verdict="unknown", flagged=False, context="Synthetic"):
    """Construct an isolated synthetic assessment."""
    evidence = EnrichmentResult("synthetic", "ok", verdict, ("Synthetic evidence",))
    return ExportItem(IOC(kind, value, context), score_results([evidence]), (evidence,), flagged)


def test_json_lossless_and_csv_formula_protection():
    """JSON preserves context while spreadsheet cells cannot become formulas."""
    original = item(context=' =HYPERLINK("https://example.com")')
    assert json.loads(export_json([original]))[0]["ioc"]["context"] == original.ioc.context
    row = list(csv.DictReader(io.StringIO(export_csv([original]))))[0]
    assert row["context"].startswith("'") and row["score"] == ""
    assert json.loads(row["evidence"])[0]["source"] == "synthetic"


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("ipv4", "8.8.8.8", "ipv4-addr"),
        ("ipv6", "2606:4700:4700::1111", "ipv6-addr"),
        ("domain", "example.com", "domain-name"),
        ("url", "https://example.com/a'b", "url"),
        ("md5", "a" * 32, "file"),
        ("sha1", "a" * 40, "file"),
        ("sha256", "a" * 64, "file"),
        ("email", "analyst@example.com", "email-addr"),
        ("cve", "CVE-2026-1234", "vulnerability"),
    ],
)
def test_all_stix_types_validate(kind, value, expected):
    """Every supported IOC is represented with validated STIX 2.1 objects."""
    bundle = parse(export_stix([item(kind, value, "malicious")]))
    assert any(obj.type == expected for obj in bundle.objects)
    indicators = [obj for obj in bundle.objects if obj.type == "indicator"]
    assert len(indicators) == (0 if kind == "cve" else 1)
    note = next(obj for obj in bundle.objects if obj.type == "note")
    assert json.loads(note.content)["ioc"]["value"] == value
    assert set(note.object_refs).issubset({obj.id for obj in bundle.objects})


@pytest.mark.parametrize(
    "verdict,flagged,count",
    [
        ("unknown", False, 0),
        ("clean", False, 0),
        ("suspicious", False, 1),
        ("malicious", True, 0),
        ("suspicious", True, 0),
    ],
)
def test_stix_risk_only_indicators(verdict, flagged, count):
    """Unknown, clean and analyst-flagged observations do not become detection patterns."""
    bundle = parse(export_stix([item(verdict=verdict, flagged=flagged)]))
    assert sum(obj.type == "indicator" for obj in bundle.objects) == count
    assert (
        json.loads(next(obj.content for obj in bundle.objects if obj.type == "note"))[
            "false_positive"
        ]
        == flagged
    )


def test_empty_exports():
    """Empty filters produce usable downloads rather than exceptions."""
    assert json.loads(export_json([])) == []
    assert len(export_csv([]).splitlines()) == 1
    assert parse(export_stix([]), version="2.1").type == "bundle"
