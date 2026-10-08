# Synthetic training examples

Every input, source verdict and score in this directory is for demonstration.
No incident, employer data, malware sample or real provider response is included.
Reserved example domains and documentation IP ranges are used; repeated hashes
and `CVE-2099-12345` are fabricated. Do not treat this content as detection intelligence.

| File | Purpose |
| --- | --- |
| `synthetic-report.txt` | Defanged text covering all nine supported IOC types |
| `demo.py` | Offline source, web preview and export generator |
| `exports/synthetic.csv` | One row per IOC with context, score and JSON evidence |
| `exports/synthetic.json` | Full assessment, reasons and source evidence |
| `exports/synthetic.stix.json` | STIX 2.1 observables, CVE Vulnerability and evidence Notes; two simulated risky domains also become Indicators |

After installing the project from the repository root:

```bash
ioc-extract --file examples/synthetic-report.txt --include-reserved-ips
python examples/demo.py --export-dir /tmp/iocdesk-examples
python examples/demo.py --serve --port 8001
```

The sample produces 12 unique IOCs across all nine types when reserved addresses
are included. `alpha.example.com` is assigned malicious, `gamma.example.com`
suspicious and `beta.example.org` clean **solely by the simulated source**. All
other observations are unknown, including the sample URL. Each result contains
an explicit `SIMULATED` reason and `synthetic=true` fact.

The evidence observation timestamp is fixed at 2026-01-01 for stable JSON/CSV.
STIX generation uses the current export time and fresh bundle/SDO IDs, so newly
created bundles differ in IDs and timestamps. Notes preserve the same synthetic
assessment content. Tests validate the published samples against the fixture
and STIX schema.

To reproduce the screenshots, serve the demo, open `http://127.0.0.1:8001`, and
paste `alpha.example.com gamma.example.com beta.example.org unknown.example.net`.
Select enrichment, expand the first card's evidence, and capture the results
section at desktop and mobile widths. For the all-types table screenshot, upload
the fixture, enable reserved IPs, analyze with the simulated source, and select
**Bulk table**. The regular app uses real providers when enrichment is selected;
use this demo for simulated verdicts.
