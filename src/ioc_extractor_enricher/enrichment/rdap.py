"""Registry RDAP domain age using a bundled IANA DNS bootstrap snapshot."""

import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, urlsplit

import tldextract

from ..models import IOC
from .base import EnrichmentResult, HTTPPlugin

_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


class RDAP(HTTPPlugin):
    """Domain age is context; old domains and missing dates remain unknown."""

    name = "rdap"
    requires_key = False
    types = frozenset({"domain"})

    def endpoint(self, ioc: IOC) -> tuple[str, dict[str, str]]:
        """Use an authoritative registry for the registrable parent of a subdomain."""
        domain = _TLD(ioc.value).top_domain_under_public_suffix
        if not domain:
            raise ValueError("Invalid registered domain")
        tld = domain.rsplit(".", 1)[1]
        bootstrap = json.loads((Path(__file__).parent / "data" / "rdap-dns.json").read_text())
        for suffixes, endpoints in bootstrap["services"]:
            if tld in suffixes:
                for endpoint in endpoints:
                    parsed = urlsplit(endpoint)
                    if parsed.scheme == "https" and parsed.netloc and not parsed.username:
                        return f"{endpoint.rstrip('/')}/domain/{quote(domain, safe='')}", {}
        raise ValueError("Registry has no supported HTTPS RDAP service")

    def parse(self, ioc: IOC, payload: dict) -> EnrichmentResult:
        """Read registration events only; no WHOIS subprocess or registrar redirects."""
        domain = _TLD(ioc.value).top_domain_under_public_suffix
        if payload["ldhName"].lower().rstrip(".") != domain:
            raise ValueError("Registry response does not match the registered domain")
        events = payload.get("events", [])
        if not isinstance(events, list):
            raise ValueError("Invalid registration events")
        dates = []
        for event in events:
            if not isinstance(event, dict) or event.get("eventAction") != "registration":
                continue
            try:
                date = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                if date.tzinfo is not None:
                    dates.append(date.astimezone(UTC))
            except (KeyError, ValueError, AttributeError):
                continue
        link = self.endpoint(ioc)[0]
        facts = {"registered_domain": domain}
        now = datetime.now(UTC)
        if not dates or min(dates) > now:
            return EnrichmentResult(
                self.name,
                "ok",
                reasons=(
                    f"No usable registration date for parent domain {domain}; age is unknown.",
                ),
                facts=facts,
                link=link,
            )
        registered = min(dates)
        age = (now - registered).days
        facts.update(registration_date=registered.isoformat(), age_days=age)
        return EnrichmentResult(
            self.name,
            "ok",
            "suspicious" if age < 30 else "unknown",
            (
                f"Parent domain {domain} was registered {age} days ago. "
                "Registration age alone does not establish maliciousness.",
            ),
            facts,
            link,
        )
