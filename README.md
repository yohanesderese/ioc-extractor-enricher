# ioc-extractor-enricher

Offline IOC extraction for SOC and CTI analysts. M1 provides a Python library and
CLI. Enrichment, verdict scoring, the web UI, and export integrations are planned
for later milestones.

## Setup

Requires Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

`tldextract` validates domains against its bundled public suffix snapshot without
network requests. `pytest` and `ruff` are development tools. No API keys are needed
for extraction; `.env.example` contains placeholders for future enrichment.

## Usage

```bash
ioc-extract --text 'Seen hxxps://Example[.]com/path and user[at]example.org'
ioc-extract --file report.txt
printf '%s\n' '8.8.8.8' | ioc-extract
ioc-extract --file report.txt --whitelist config/whitelist.txt
```

Output is a JSON array containing `type`, normalized `value`, and the first
original context sentence. Supported types: IPv4, IPv6, domain, HTTP(S) URL, MD5,
SHA1, SHA256, email, and CVE. URL and email domains are emitted as extra IOCs;
URL IP hosts are also emitted as address IOCs.

Common defanging forms such as `hxxp`, `[.]`, `(.)`, `[:]`, `[at]`, and `\.` are
restored before validation. Reserved/private IPs and all-zero hashes are excluded
by default. Use `--include-reserved-ips` or `--include-zero-hashes` to include them.

Whitelists contain one benign domain or IP per line, with optional `#` comments.
Domains match themselves and their subdomains, including URL and email hosts.
Filtering is enabled when a whitelist is supplied; `--no-noise-filter` disables
it. The sample whitelist starts empty.

```python
from ioc_extractor_enricher import extract

for ioc in extract("Seen example[.]com in a synthetic report."):
    print(ioc.type, ioc.value, ioc.context)
```

## Validation

```bash
ruff check .
pytest
```

Tests use synthetic data and make no API calls. Extraction identifies syntactically
valid candidates, not maliciousness. Context uses punctuation/line boundaries,
so abbreviations can split sentences. ASCII DNS names and HTTP(S) URLs are
supported; PDF/HTML parsing, URL fetching, Unicode domain conversion, and live
public suffix updates are outside M1.

## Milestones

- M1: extraction, refanging, validation, noise filtering, tests and CLI.
- M2: enrichment plugins, cache and rate limiting.
- M3: explainable scoring, FastAPI and HTMX UI.
- M4: additional sources, CSV/JSON/STIX export and optional MISP push.
- M5: usage examples, screenshots, Docker and CI.
