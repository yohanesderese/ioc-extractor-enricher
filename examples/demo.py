"""Offline demo and export generator with fabricated evidence, never live provider calls."""

import argparse
from pathlib import Path

import uvicorn

from ioc_extractor_enricher.app import create_app
from ioc_extractor_enricher.enrichment import EnrichmentEngine, EnrichmentResult
from ioc_extractor_enricher.exports import ExportItem, export_csv, export_json, export_stix
from ioc_extractor_enricher.extractor import extract
from ioc_extractor_enricher.models import IOC, ExtractionOptions, IOCType
from ioc_extractor_enricher.scorer import score_results

REPORT_PATH = Path(__file__).with_name("synthetic-report.txt")


class DemoSource:
    """Fabricated outcomes for reserved example domains; every other IOC stays unknown."""

    name = "demo"
    interval = 0.0

    def supports(self, kind: IOCType) -> bool:
        """Accept every extractor type for the simulated offline UI."""
        return True

    @staticmethod
    def evidence(ioc: IOC) -> EnrichmentResult:
        """Demonstrate risk labels without claiming reputation for public addresses or hashes."""
        verdict = "unknown"
        if ioc.type == "domain" and ioc.value == "alpha.example.com":
            verdict = "malicious"
        elif ioc.type == "domain" and ioc.value == "gamma.example.com":
            verdict = "suspicious"
        elif ioc.type == "domain" and ioc.value == "beta.example.org":
            verdict = "clean"
        return EnrichmentResult(
            "demo",
            "ok",
            verdict,
            ("SIMULATED evidence for UI demonstration only; no provider was queried.",),
            {"synthetic": True},
            observed_at=1767225600.0,
        )

    async def lookup(self, ioc: IOC) -> EnrichmentResult:
        """Return deterministic local evidence without HTTP or credentials."""
        return self.evidence(ioc)


def sample_items() -> list[ExportItem]:
    """Exercise all nine IOC types, explicitly including documentation addresses."""
    iocs = extract(
        REPORT_PATH.read_text(encoding="utf-8"), ExtractionOptions(include_reserved_ips=True)
    )
    return [
        ExportItem(ioc, score_results([DemoSource.evidence(ioc)]), (DemoSource.evidence(ioc),))
        for ioc in iocs
    ]


def write_exports(directory: Path) -> None:
    """Write synthetic CSV/JSON/STIX examples from the same fixture and score policy."""
    directory.mkdir(parents=True, exist_ok=True)
    items = sample_items()
    for filename, exporter in (
        ("synthetic.csv", export_csv),
        ("synthetic.json", export_json),
        ("synthetic.stix.json", export_stix),
    ):
        content = exporter(items)
        if filename.endswith(".csv"):
            # Keep repository fixtures LF-only; spreadsheet downloads still use standard CSV CRLF.
            content = content.replace("\r\n", "\n")
        (directory / filename).write_text(content, encoding="utf-8")
    print(f"Wrote {len(items)} synthetic IOC assessments to {directory}.")


def main() -> None:
    """Generate examples and/or serve an explicitly simulated workspace on localhost."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export-dir", type=Path, help="Write fabricated sample exports here")
    parser.add_argument("--serve", action="store_true", help="Serve the offline demo on localhost")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()
    if args.export_dir:
        write_exports(args.export_dir)
    if args.serve:
        print("OFFLINE DEMO: all evidence is simulated. No provider or MISP requests are made.")
        uvicorn.run(create_app(EnrichmentEngine([DemoSource()])), host="127.0.0.1", port=args.port)
    elif not args.export_dir:
        parser.print_help()


if __name__ == "__main__":
    main()
