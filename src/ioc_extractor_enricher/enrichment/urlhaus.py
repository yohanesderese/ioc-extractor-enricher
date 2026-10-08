"""Authenticated URLhaus URL and host lookups without submissions or downloads."""

import httpx

from ..models import IOC
from .base import EnrichmentResult, HTTPPlugin, count, selected_facts


class URLhaus(HTTPPlugin):
    """Known malware URLs are malicious; host associations require analyst review."""

    name = "urlhaus"
    env_key = "ABUSECH_AUTH_KEY"
    auth_header = "Auth-Key"
    types = frozenset({"url", "domain", "ipv4"})

    def endpoint(self, ioc: IOC) -> tuple[str, dict[str, str]]:
        """Select the URL or host endpoint and lookup form fields."""
        kind = "url" if ioc.type == "url" else "host"
        return f"https://urlhaus-api.abuse.ch/v1/{kind}/", {kind: ioc.value}

    async def request(self, ioc: IOC) -> httpx.Response:
        """URLhaus lookups are form POST requests, not submissions."""
        url, fields = self.endpoint(ioc)
        return await self.client.post(
            url, data=fields, headers=self.headers(), timeout=self.timeout, follow_redirects=False
        )

    def parse(self, ioc: IOC, payload: dict) -> EnrichmentResult:
        """Interpret query status and retain selected evidence, never sample links."""
        if payload["query_status"] == "no_results":
            return EnrichmentResult(self.name, "not_found", reasons=("No URLhaus record found.",))
        if payload["query_status"] != "ok":
            raise ValueError("URLhaus rejected the lookup")
        if ioc.type == "url":
            if payload["threat"] != "malware_download":
                raise ValueError("Unexpected threat category")
            verdict = "malicious"
            reason = "URLhaus records this URL as a malware download location, even if now offline."
            facts = selected_facts(payload, ("url_status", "threat", "date_added", "last_online"))
        else:
            total = payload["url_count"]
            total = int(total) if isinstance(total, str) and total.isdecimal() else count(total)
            verdict = "suspicious" if total else "unknown"
            reason = (
                f"Host is associated with {total} URLhaus malware URLs; association is not proof."
            )
            facts = selected_facts(payload, ("firstseen",)) | {"url_count": total}
        link = payload.get("urlhaus_reference")
        if link is not None and not isinstance(link, str):
            raise ValueError("Invalid report link")
        return EnrichmentResult(self.name, "ok", verdict, (reason,), facts, link)
