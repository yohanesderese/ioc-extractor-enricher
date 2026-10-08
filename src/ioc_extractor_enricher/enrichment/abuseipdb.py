"""AbuseIPDB v2 check adapter for IPv4 and IPv6."""

from urllib.parse import quote

from ..models import IOC
from .base import EnrichmentResult, HTTPPlugin, count, selected_facts


class AbuseIPDB(HTTPPlugin):
    """Check abuse evidence from the last 90 days without submitting reports."""

    name = "abuseipdb"
    env_key = "ABUSEIPDB_API_KEY"
    auth_header = "Key"
    types = frozenset({"ipv4", "ipv6"})

    def endpoint(self, ioc: IOC) -> tuple[str, dict[str, str]]:
        """Send IPv6 safely as a query parameter."""
        return "https://api.abuseipdb.com/api/v2/check", {
            "ipAddress": ioc.value,
            "maxAgeInDays": "90",
        }

    def parse(self, ioc: IOC, payload: dict) -> EnrichmentResult:
        """Keep confidence and reports; lack of reports is unknown, not clean."""
        data = payload["data"]
        confidence = count(data["abuseConfidenceScore"])
        reports = count(data["totalReports"])
        if confidence > 100:
            raise ValueError("Invalid confidence")
        verdict = (
            "malicious"
            if confidence >= 75
            else ("suspicious" if confidence or reports else "unknown")
        )
        facts = selected_facts(
            data,
            (
                "countryCode",
                "isp",
                "usageType",
                "domain",
                "isTor",
                "lastReportedAt",
                "numDistinctUsers",
            ),
        )
        facts.update(abuseConfidenceScore=confidence, totalReports=reports)
        return EnrichmentResult(
            self.name,
            "ok",
            verdict,
            (f"Abuse confidence {confidence}/100; {reports} reports in the last 90 days.",),
            facts,
            f"https://www.abuseipdb.com/check/{quote(ioc.value, safe='')}",
        )
