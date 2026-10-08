"""Portable report snapshots, with conservative STIX indicator semantics."""

import csv
import io
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from stix2 import v21

from .enrichment.base import EnrichmentResult
from .models import IOC
from .scorer import ScoreResult


@dataclass(frozen=True)
class ExportItem:
    """A completed IOC assessment and its independent review annotation."""

    ioc: IOC
    assessment: ScoreResult
    evidence: tuple[EnrichmentResult, ...] = ()
    false_positive: bool = False


def export_json(items: Sequence[ExportItem]) -> str:
    """Preserve full evidence, context and scoring without session credentials."""
    return json.dumps([asdict(item) for item in items], ensure_ascii=False, indent=2)


def _cell(value: str) -> str:
    """Neutralize spreadsheet formula prefixes; JSON remains the lossless format."""
    return (
        "'" + value
        if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n"))
        else value
    )


def export_csv(items: Sequence[ExportItem]) -> str:
    """Write one row per IOC, including JSON evidence and spreadsheet-safe text."""
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        ["type", "value", "score", "verdict", "context", "false_positive", "reasons", "evidence"]
    )
    for item in items:
        writer.writerow(
            [
                _cell(item.ioc.type),
                _cell(item.ioc.value),
                item.assessment.score if item.assessment.score is not None else "",
                item.assessment.verdict,
                _cell(item.ioc.context),
                item.false_positive,
                _cell("\n".join(item.assessment.reasons)),
                json.dumps([asdict(result) for result in item.evidence], ensure_ascii=False),
            ]
        )
    return output.getvalue()


def export_stix(items: Sequence[ExportItem]) -> str:
    """Emit STIX 2.1 observables and notes; only unflagged risk becomes an Indicator."""
    objects = {}
    now = datetime.now(UTC)
    properties = {
        "ipv4": (v21.IPv4Address, "ipv4-addr:value"),
        "ipv6": (v21.IPv6Address, "ipv6-addr:value"),
        "domain": (v21.DomainName, "domain-name:value"),
        "url": (v21.URL, "url:value"),
        "email": (v21.EmailAddress, "email-addr:value"),
    }
    algorithms = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
    for item in items:
        kind, value = item.ioc.type, item.ioc.value
        if kind == "cve":
            observable = v21.Vulnerability(
                name=value, external_references=[{"source_name": "cve", "external_id": value}]
            )
            path = None
        elif kind in algorithms:
            algorithm = algorithms[kind]
            observable = v21.File(hashes={algorithm: value})
            path = f"file:hashes.'{algorithm}'"
        else:
            constructor, path = properties[kind]
            observable = constructor(value=value)
        objects[observable.id] = observable
        references = [observable.id]
        if (
            path
            and not item.false_positive
            and item.assessment.verdict in {"malicious", "suspicious"}
        ):
            literal = value.replace("\\", "\\\\").replace("'", "\\'")
            indicator = v21.Indicator(
                name=f"{kind}: {value}",
                pattern=f"[{path} = '{literal}']",
                pattern_type="stix",
                pattern_version="2.1",
                valid_from=now,
                created=now,
                modified=now,
                description="Automated assessment; consult the attached evidence note.",
            )
            objects[indicator.id] = indicator
            references.append(indicator.id)
        note = v21.Note(
            content=json.dumps(asdict(item), ensure_ascii=False),
            object_refs=references,
            created=now,
            modified=now,
        )
        objects[note.id] = note
    return v21.Bundle(objects=list(objects.values())).serialize(pretty=True)
