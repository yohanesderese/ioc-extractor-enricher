# ioc-extractor-enricher

Offline IOC extraction for SOC and CTI analysts. M1 provides a Python library and
CLI. M2 adds an async enrichment library with VirusTotal, AbuseIPDB, and AlienVault
OTX adapters. M3 adds explainable scoring and a local FastAPI/HTMX web workspace.
M4 adds five sources, CSV/JSON/STIX 2.1 downloads and an explicit optional MISP push.

## Setup

Requires Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

`tldextract` validates domains against its bundled public suffix snapshot without
network requests. `httpx` handles asynchronous enrichment HTTP requests. `pytest`
and `ruff` are development tools. `stix2` constructs and validates STIX 2.1 objects.
No API keys are needed for extraction.

The web app uses FastAPI for endpoints, Jinja2 for server-rendered pages,
`python-multipart` for text uploads, and Uvicorn for the local server. HTMX 2.0.11
is bundled with its license and served locally; no CDN is needed at runtime.

## Web workspace (M3)

```bash
uvicorn ioc_extractor_enricher.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. Paste text, upload a UTF-8 text file, or enter a URL
indicator. Inputs may be combined. PDF/binary parsing and fetching report pages
from URLs are not implemented; URL input analyzes the URL itself. Limits are
1 MiB combined text and 50 unique indicators per report.

Extraction runs locally by default. Select **Enrich with configured threat
sources** to send extracted values to providers using the environment keys
described below. Results appear immediately and poll while queued lookups run;
the report job stops after five minutes, retaining completed cards and marking
unfinished cards unknown with a timeout reason. A failed source cannot become a
clean verdict. Keyed sources are disabled without their keys; InternetDB and RDAP
work without keys when enrichment is selected.

Cards show the original context, source status and selected facts, report links,
copy controls, and the score calculation. Switch to the bulk table and filter by
verdict or review state; sort by score, value, or type. Unknown scores always sort
after known scores. False-positive flags are reversible analyst annotations:
they preserve provider evidence and the calculated score.

Reports and review flags stay in process memory, expire after one hour, and are
lost on restart. Evidence caching remains in SQLite. This milestone is for a
single local server/worker, with up to 32 reports and 64 browser sessions; there
is no login system or persistent investigation history. Browser session cookies
scope reports, and mutations require CSRF tokens. Serve on localhost for local
use. Public hosting and shared analyst access need a separate authentication and
persistence design.

The app factory supports injected engines, custom cache paths and optional
whitelist files: `create_app(engine=None, cache_path="enrichment.db",
whitelist_path=Path("config/whitelist.txt"))`. The default whitelist is empty.
Provider keys are loaded at startup, so restart after changing the environment.

### Score policy

Default weights are VirusTotal 5, AbuseIPDB 3, OTX 2, URLhaus 5, MalwareBazaar 5,
GreyNoise 2, InternetDB 1 and RDAP 1. Custom sources default
to weight 1. Known verdict points are malicious 100, suspicious 50, and clean 0.
The score is the rounded weighted mean of known `ok` verdicts only. Unknown or
unavailable sources do not contribute to the denominator; source coverage is
shown alongside the score.

A score of at least 75 is malicious. Any remaining positive source risk stays
suspicious, even if a small contribution rounds to zero. A clean result requires
known clean evidence without positive risk. With no eligible evidence, the score
is `null` and the label is unknown (displayed as `—` in the UI). These are
transparent project heuristics, not calibrated probabilities of compromise.
`score_results(results, weights={"otx": 1})` overrides source weights; zero excludes
a source. Reasons include every source's contribution/exclusion and evidence.

### JSON API

Start a session with `GET /` and retain its `ioc_session` cookie. Read the hidden
form `csrf` value and send it as `X-CSRF-Token` for mutations.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/api/analyze` | Create a report from `text`, `url`, and extraction options; `enrich` defaults to false |
| GET | `/api/reports/{id}` | Poll evidence, assessment, pending state, and review flags |
| POST | `/api/reports/{id}/cards/{card_id}/false-positive` | Set `{"false_positive": true}` or false |
| GET | `/reports/{id}/export/{format}` | Download `csv`, `json`, or `stix`; supports verdict/review/sort/order filters |
| POST | `/api/reports/{id}/misp` | Explicit push with `{"confirm": true}` and CSRF token |
| GET | `/openapi.json` | API schema |

Analysis returns HTTP 202 with the report ID, `pending`, and `cards`. Each card
contains its IOC, evidence, assessment, and analyst annotation. HTML routes use
the same reports and return fragments when `HX-Request: true`. Standalone Swagger
and ReDoc pages are disabled to keep browser assets local.

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
| URLhaus | `ABUSECH_AUTH_KEY` | URL, domain, IPv4 |
| MalwareBazaar | `ABUSECH_AUTH_KEY` | MD5, SHA1, SHA256 |
| Shodan InternetDB | None | IPv4 |
| GreyNoise Community | `GREYNOISE_API_KEY` | IPv4 |
| Registry RDAP | None | Domain (registrable parent) |

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
apart for AbuseIPDB/OTX/URLhaus/MalwareBazaar/InternetDB/RDAP and 5 seconds
apart for GreyNoise by default. Override seconds with
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

## Additional sources and integrations (M4)

[URLhaus](https://urlhaus-api.abuse.ch/) and
[MalwareBazaar](https://bazaar.abuse.ch/api/) use a free abuse.ch Auth-Key for
form-based lookups. URLhaus malware-download URL records are malicious evidence,
including historical offline records; host associations are suspicious context.
A matching MalwareBazaar sample hash is malicious evidence. Neither adapter
uploads reports or retrieves malware samples. Community use follows the providers'
fair-use limits; no paid endpoints or subscriptions are invoked.

[InternetDB](https://book.shodan.io/developer-apis/internetdb/) uses the no-key
API. Open ports alone remain unknown; reported potential vulnerabilities are
suspicious exposure context, not proof of compromise.
[GreyNoise Community](https://docs.greynoise.io/docs/using-the-greynoise-community-api)
requires an eligible account key. The documented free business-email tier offers
up to 50 lookups/week; free-email accounts do not have API-key access. Without a
key the adapter stays disabled. Malicious/benign classifications map to
malicious/clean; unknown scanners are suspicious and RIOT membership alone
remains unknown. Request spacing does not enforce weekly quotas.

RDAP uses the bundled [IANA DNS bootstrap](https://data.iana.org/rdap/dns.json)
snapshot to select HTTPS registry endpoints, with no registrar redirects or WHOIS
subprocess. Subdomains use their registrable parent's registration events. Age
under 30 days is suspicious context; older, missing or future dates remain
unknown. The snapshot is packaged for offline routing and does not auto-update;
registries without a supported HTTPS service return an unavailable result.

After enrichment completes, use the download buttons for the **displayed**
indicators, respecting filters and sorting. JSON includes full context, evidence,
score explanations and false-positive annotations. CSV has one row per IOC and
neutralizes spreadsheet formula prefixes; use JSON for lossless text. STIX 2.1
contains observables (or CVE Vulnerability objects) and evidence Notes. Only
unflagged suspicious/malicious non-CVE findings also become Indicators. Clean,
unknown and flagged findings stay observations, without detection patterns.
STIX/JSON include original context sentences, so review the export before sharing.

For MISP, supply `MISP_URL` (HTTPS, optionally a base path) and `MISP_API_KEY` in
the server environment and restart. The key stays in an Authorization header;
TLS verification is enabled and redirects are disabled. The UI requires explicit
confirmation to send **all unflagged indicators in the report**, regardless of
display filters. It creates an unpublished organization-only event with indicator
values and score summaries, without original sentences or full source evidence.
Only malicious non-CVE attributes have `to_ids=true`; other attributes explicitly
use false. See the [MISP API](https://www.misp-project.org/documentation/openapi.html).

One push attempt is retained per report, including uncertain outcomes. Double
clicks and retries reuse the outcome rather than creating another event. A timeout
or malformed response can follow a successful remote write: check MISP before
sending a new report. Event UUIDs are stable per report, but restarting loses
local reports/attempts; this is not durable cross-process deduplication. Later
local review changes do not modify an already sent event. Authentication and live
MISP servers are not exercised by tests; all transport tests use mocks.

## Milestones

- M1: extraction, refanging, validation, noise filtering, tests and CLI.
- M2: enrichment plugins, cache and rate limiting.
- M3: explainable scoring, FastAPI and HTMX UI.
- M4: additional sources, CSV/JSON/STIX export and optional MISP push.
- M5: usage examples, screenshots, Docker and CI.
