"""Validate an installed wheel's bundled assets and offline extraction entry point."""

import json
import subprocess
import sys
from importlib.resources import files
from pathlib import Path


def main() -> None:
    """Fail if assets or CLI behavior are missing from an installed distribution."""
    package = files("ioc_extractor_enricher")
    for name in (
        "templates/index.html",
        "templates/results.html",
        "static/htmx.min.js",
        "static/HTMX-LICENSE.txt",
        "static/app.css",
        "static/app.js",
        "enrichment/data/rdap-dns.json",
    ):
        assert package.joinpath(name).is_file(), f"Missing packaged asset: {name}"
    bootstrap = json.loads(package.joinpath("enrichment/data/rdap-dns.json").read_text())
    assert bootstrap["services"]
    output = subprocess.check_output(
        [
            str(Path(sys.executable).with_name("ioc-extract")),
            "--text",
            "Seen hxxps://Example[.]com/demo",
        ],
        text=True,
    )
    indicators = json.loads(output)
    assert {(ioc["type"], ioc["value"]) for ioc in indicators} == {
        ("url", "https://example.com/demo"),
        ("domain", "example.com"),
    }
    print("Installed package assets and offline CLI verified.")


if __name__ == "__main__":
    main()
