"""Command line entry point for text extraction."""

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .extractor import extract
from .models import ExtractionOptions
from .noise_filter import load_whitelist


def main(argv: list[str] | None = None) -> int:
    """Read pasted text, a UTF-8 file or stdin, and emit JSON."""
    parser = argparse.ArgumentParser(description="Extract IOCs offline as JSON.")
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--text", help="Text to extract from")
    inputs.add_argument("--file", type=Path, help="UTF-8 text file (not PDF/HTML yet)")
    parser.add_argument("--whitelist", type=Path, help="Benign domain/IP list")
    parser.add_argument("--no-noise-filter", action="store_true")
    parser.add_argument("--include-reserved-ips", action="store_true")
    parser.add_argument("--include-zero-hashes", action="store_true")
    args = parser.parse_args(argv)
    try:
        text = (
            args.text
            if args.text is not None
            else (args.file.read_text(encoding="utf-8") if args.file else sys.stdin.read())
        )
        whitelist = load_whitelist(args.whitelist) if args.whitelist else frozenset()
    except (OSError, UnicodeError) as exc:
        parser.exit(2, f"ioc-extract: {exc}\n")
    options = ExtractionOptions(
        include_reserved_ips=args.include_reserved_ips,
        include_zero_hashes=args.include_zero_hashes,
        filter_noise=not args.no_noise_filter,
    )
    print(json.dumps([asdict(ioc) for ioc in extract(text, options, whitelist)], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
