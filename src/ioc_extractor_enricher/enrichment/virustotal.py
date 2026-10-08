"""VirusTotal v3 reports for addresses, domains, URLs and hashes."""

import base64
from urllib.parse import quote

from ..models import IOC
from .base import EnrichmentResult, HTTPPlugin, count, selected_facts


class VirusTotal(HTTPPlugin):
    """Read existing reports and keep analysis counts as explainable evidence."""

    name = "virustotal"
    interval = 15.0
    env_key = "VT_API_KEY"
    auth_header = "x-apikey"
    types = frozenset({"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"})

    def endpoint(self, ioc: IOC) -> tuple[str, dict[str, str]]:
        """Encode URL IDs using unpadded URL-safe base64 as required by v3."""
        if ioc.type == "url":
            kind = "urls"
            identifier = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
        else:
            kind = (
                "ip_addresses"
                if ioc.type in {"ipv4", "ipv6"}
                else ("domains" if ioc.type == "domain" else "files")
            )
            identifier = quote(ioc.value, safe="")
        return f"https://www.virustotal.com/api/v3/{kind}/{identifier}", {}

    def parse(self, ioc: IOC, payload: dict) -> EnrichmentResult:
        """Map detection counts without treating an unanalysed report as clean."""
        attributes = payload["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
        malicious = count(stats["malicious"])
        suspicious = count(stats["suspicious"])
        harmless = count(stats.get("harmless", 0))
        undetected = count(stats.get("undetected", 0))
        verdict = (
            "malicious"
            if malicious
            else "suspicious"
            if suspicious
            else "clean"
            if harmless
            else "unknown"
        )
        facts = selected_facts(
            attributes,
            ("country", "asn", "as_owner", "reputation", "last_analysis_date", "type_description"),
        )
        facts.update(
            malicious=malicious, suspicious=suspicious, harmless=harmless, undetected=undetected
        )
        kind = (
            "ip-address"
            if ioc.type in {"ipv4", "ipv6"}
            else ("domain" if ioc.type == "domain" else "url" if ioc.type == "url" else "file")
        )
        identifier = self.endpoint(ioc)[0].rsplit("/", 1)[1]
        return EnrichmentResult(
            self.name,
            "ok",
            verdict,
            (f"{malicious} malicious, {suspicious} suspicious, {harmless} harmless detections.",),
            facts,
            f"https://www.virustotal.com/gui/{kind}/{identifier}",
        )
