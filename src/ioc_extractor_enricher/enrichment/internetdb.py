"""Unauthenticated Shodan InternetDB exposure context."""

import ipaddress
from urllib.parse import quote

from ..models import IOC
from .base import EnrichmentResult, HTTPPlugin


class InternetDB(HTTPPlugin):
    """Open ports alone are unknown; potential vulnerabilities are suspicious context."""

    name = "internetdb"
    requires_key = False
    types = frozenset({"ipv4"})

    def endpoint(self, ioc: IOC) -> tuple[str, dict[str, str]]:
        """Query the no-key InternetDB API, not the paid Shodan API."""
        return f"https://internetdb.shodan.io/{quote(ioc.value, safe='')}", {}

    def parse(self, ioc: IOC, payload: dict) -> EnrichmentResult:
        """Validate the IP and selected arrays before summarizing exposure."""
        if ipaddress.ip_address(payload["ip"]) != ipaddress.ip_address(ioc.value):
            raise ValueError("IP response mismatch")
        ports = payload["ports"]
        if not isinstance(ports, list) or any(
            type(port) is not int or not 1 <= port <= 65535 for port in ports
        ):
            raise ValueError("Invalid ports")
        facts = {"ports": ", ".join(map(str, ports))}
        for name in ("vulns", "hostnames", "cpes", "tags"):
            values = payload[name]
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                raise ValueError("Invalid exposure evidence")
            facts[name] = ", ".join(values)
        vulnerabilities = len(payload["vulns"])
        return EnrichmentResult(
            self.name,
            "ok",
            "suspicious" if vulnerabilities else "unknown",
            (
                f"{len(ports)} open ports; {vulnerabilities} potential vulnerabilities. "
                "Exposure does not establish compromise.",
            ),
            facts,
            f"https://www.shodan.io/host/{quote(ioc.value, safe='')}",
        )
