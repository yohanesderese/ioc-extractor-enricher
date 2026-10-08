"""GreyNoise Community IPv4 reputation with conservative classification mapping."""

from urllib.parse import quote

from ..models import IOC
from .base import EnrichmentResult, HTTPPlugin, selected_facts


class GreyNoise(HTTPPlugin):
    """Use the free community endpoint with an eligible account's environment key."""

    name = "greynoise"
    env_key = "GREYNOISE_API_KEY"
    auth_header = "key"
    interval = 5.0
    types = frozenset({"ipv4"})

    def endpoint(self, ioc: IOC) -> tuple[str, dict[str, str]]:
        """Query only the Community API, never enterprise endpoints."""
        return f"https://api.greynoise.io/v3/community/{quote(ioc.value, safe='')}", {}

    def parse(self, ioc: IOC, payload: dict) -> EnrichmentResult:
        """Explicit benign classification supplies clean evidence; absent data never does."""
        if payload["ip"] != ioc.value:
            raise ValueError("IP response mismatch")
        noise, riot = payload["noise"], payload["riot"]
        classification = payload["classification"]
        if (
            type(noise) is not bool
            or type(riot) is not bool
            or classification
            not in {
                "malicious",
                "benign",
                "unknown",
            }
        ):
            raise ValueError("Invalid community classification")
        verdict = (
            "malicious"
            if classification == "malicious"
            else "clean"
            if classification == "benign"
            else "suspicious"
            if noise
            else "unknown"
        )
        facts = selected_facts(payload, ("classification", "noise", "riot", "name", "last_seen"))
        return EnrichmentResult(
            self.name,
            "ok",
            verdict,
            (
                f"GreyNoise classification: {classification}; scanning={noise}, "
                f"RIOT record={riot}. RIOT alone is not a clean verdict.",
            ),
            facts,
            f"https://viz.greynoise.io/ip/{quote(ioc.value, safe='')}",
        )
