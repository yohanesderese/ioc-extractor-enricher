"""Canonical representations used for deduplication."""

import ipaddress
from urllib.parse import urlsplit, urlunsplit

from .models import IOCType


def normalize(kind: IOCType, value: str) -> str:
    """Normalize hosts and hashes while preserving URL path and email local case."""
    if kind in {"ipv4", "ipv6"}:
        return str(ipaddress.ip_address(value))
    if kind == "cve":
        return value.upper()
    if kind == "email":
        local, domain = value.rsplit("@", 1)
        return f"{local}@{domain.lower()}"
    if kind == "url":
        parts = urlsplit(value)
        host = (parts.hostname or "").lower()
        if ":" in host:
            host = f"[{ipaddress.ip_address(host)}]"
        port = parts.port
        if port and (parts.scheme.lower(), port) not in {("http", 80), ("https", 443)}:
            host += f":{port}"
        credentials = parts.netloc.rsplit("@", 1)[0] + "@" if "@" in parts.netloc else ""
        return urlunsplit(
            (parts.scheme.lower(), credentials + host, parts.path, parts.query, parts.fragment)
        )
    return value.lower().rstrip(".")
