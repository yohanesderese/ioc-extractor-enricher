"""AlienVault OTX general indicator report adapter."""

from urllib.parse import quote

from ..models import IOC
from .base import EnrichmentResult, HTTPPlugin, count


class OTX(HTTPPlugin):
    """Pulse references indicate suspicion; they do not prove maliciousness."""

    name = "otx"
    env_key = "OTX_API_KEY"
    auth_header = "X-OTX-API-KEY"
    _KINDS = {
        "ipv4": "IPv4",
        "ipv6": "IPv6",
        "domain": "domain",
        "url": "url",
        "md5": "file",
        "sha1": "file",
        "sha256": "file",
        "cve": "cve",
    }
    types = frozenset(_KINDS)

    def endpoint(self, ioc: IOC) -> tuple[str, dict[str, str]]:
        """Encode the whole indicator as a path segment, including URL slashes."""
        kind = self._KINDS[ioc.type]
        return (
            f"https://otx.alienvault.com/api/v1/indicators/{kind}/"
            f"{quote(ioc.value, safe='')}/general"
        ), {}

    def parse(self, ioc: IOC, payload: dict) -> EnrichmentResult:
        """Normalize the pulse count without saving full reports or comments."""
        pulses = count(payload["pulse_info"]["count"])
        return EnrichmentResult(
            self.name,
            "ok",
            "suspicious" if pulses else "unknown",
            (f"Indicator appears in {pulses} OTX pulses; references require analyst review.",),
            {"pulse_count": pulses},
            f"https://otx.alienvault.com/indicator/{self._KINDS[ioc.type]}/"
            f"{quote(ioc.value, safe='')}",
        )
