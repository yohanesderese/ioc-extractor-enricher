# ioc-extractor-enricher

Offline IOC extraction for SOC and CTI analysts. M1 provides a Python library and
CLI. M2 adds an async enrichment library with VirusTotal, AbuseIPDB, and AlienVault
OTX adapters. Verdict scoring, the web UI, and export integrations are planned
for later milestones.

## Setup

Requires Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

`tldextract` validates domains against its bundled public suffix snapshot without
network requests. `httpx` handles asynchronous enrichment HTTP requests. `pytest`
and `ruff` are development tools. No API keys are needed for extraction.

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

## Enrichment (M2)

The enrichment API is a Python library; `ioc-extract` remains offline. Configure
the source keys in your process environment before constructing adapters:

| Source | Environment variable | Supported IOC types |
| --- | --- | --- |
| VirusTotal | `VT_API_KEY` | IPv4, IPv6, domain, URL, MD5, SHA1, SHA256 |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | IPv4, IPv6 |
| AlienVault OTX | `OTX_API_KEY` | IPv4, IPv6, domain, URL, hashes, CVE |

`.env.example` documents the names. The library does not open `.env` files; your
launcher can supply their values as environment variables. Missing, empty, or
example-placeholder keys disable that source without making an HTTP request.
Keys are sent in provider authentication headers, not URLs, and redirects are
disabled. Request/response bodies and exception messages are not logged or cached.

```python
import asyncio
from dataclasses import asdict

import httpx

from ioc_extractor_enricher import extract
from ioc_extractor_enricher.cache import SQLiteCache
from ioc_extractor_enricher.enrichment import (
    AbuseIPDB,
    EnrichmentEngine,
    OTX,
    VirusTotal,
)


async def main() -> None:
    iocs = extract("Synthetic example: example[.]com")
    async with httpx.AsyncClient() as client, SQLiteCache("enrichment.db") as cache:
        engine = EnrichmentEngine(
            [VirusTotal(client), AbuseIPDB(client), OTX(client)],
            cache,
        )
        for ioc, evidence in zip(iocs, await engine.enrich_many(iocs)):
            print(ioc.value, [asdict(result) for result in evidence])


asyncio.run(main())
```

Enrichment sends indicator values to the configured providers; context sentences
remain local. VirusTotal documents that queried indicators may enter its public
dataset. Use public or synthetic indicators for demos.

Each result contains `source`, `status`, `verdict`, `reasons`, selected `facts`,
a provider `link`, `observed_at` (Unix timestamp), and `cached`. Status values are
`ok`, `not_found`, `disabled`, `unsupported`, `timeout`, `rate_limited`, and `error`.
Failures retain an `unknown` verdict and do not erase other source results.

Source verdicts are evidence mappings, not the final weighted M3 score:

- VirusTotal: malicious detections take precedence over suspicious detections;
  positive harmless detections yield clean. Only undetected results yield unknown.
- AbuseIPDB: confidence of at least 75 yields malicious; lower positive confidence
  or report counts yield suspicious. No reports yield unknown. Reports use a
  90-day window.
- OTX: positive pulse references yield suspicious and require analyst review;
  no pulse references yield unknown.

SQLite entries are keyed by source, normalized IOC type, and value. Defaults are
1 hour for IPs, URLs, and email; 6 hours for domains; 24 hours for hashes and CVEs.
Override with `SQLiteCache(path, ttls={"domain": 3600})`; a TTL of zero disables
caching for that type. Only `ok` and `not_found` results are cached. Expired or
corrupt entries become misses, and SQLite operation failures allow uncached
lookups. The caller owns the cache and HTTP client lifetimes.

Each engine queues requests FIFO per source, while different sources run
concurrently. Requests start at least 15 seconds apart for VirusTotal and 1 second
apart for AbuseIPDB/OTX by default. Override seconds with
`EnrichmentEngine(plugins, cache, intervals={"otx": 2})`. Cache hits skip request
slots, and simultaneous identical requests share cached evidence. These limits
apply to one engine/process; they do not coordinate across processes or account
for calls made by other applications, and do not enforce daily account quotas.

HTTP 429 responses return immediately as `rate_limited`, with subsequent requests
delayed by `Retry-After` (seconds or HTTP date), or at least 60 seconds when it is
absent/invalid. There are no automatic retries. Lookup timeouts default to 10
seconds and exclude time spent waiting in the source queue. Configure the engine
and individual adapter `timeout` arguments as needed. Cancelling a batch releases
its queued requests.

Provider tests use `httpx.MockTransport`, synthetic environment keys, and a guard
against live HTTP. Queue timing and TTL tests use controlled clocks. Provider
accounts and live authentication have not been exercised by these tests.

API references: [VirusTotal v3 reports](https://docs.virustotal.com/reference/ip-info),
[VirusTotal URL identifiers](https://docs.virustotal.com/reference/url-info),
[AbuseIPDB check](https://docs.abuseipdb.com/#check-endpoint), and the
[official OTX Python SDK](https://github.com/AlienVault-OTX/OTX-Python-SDK).

## Milestones

- M1: extraction, refanging, validation, noise filtering, tests and CLI.
- M2: enrichment plugins, cache and rate limiting.
- M3: explainable scoring, FastAPI and HTMX UI.
- M4: additional sources, CSV/JSON/STIX export and optional MISP push.
- M5: usage examples, screenshots, Docker and CI.
