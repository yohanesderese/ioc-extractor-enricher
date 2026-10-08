"""Offline domain, address and indicator validation."""

import ipaddress
import re
from urllib.parse import urlsplit

import tldextract

from .models import ExtractionOptions, IOCType

_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
_FILE_SUFFIXES = {"exe", "dll", "sys", "pdf", "doc", "docx", "txt", "zip", "js", "json"}


def valid_domain(value: str) -> bool:
    """Require a public suffix and valid DNS labels; reject filename suffixes."""
    value = value.lower().rstrip(".")
    if len(value) > 253 or value.rsplit(".", 1)[-1] in _FILE_SUFFIXES:
        return False
    labels = value.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        return False
    parts = _TLD(value)
    return bool(parts.domain and parts.suffix)


def valid(kind: IOCType, value: str, options: ExtractionOptions) -> bool:
    """Validate an indicator and apply configured reserved/zero exclusions."""
    try:
        if kind in {"ipv4", "ipv6"}:
            address = ipaddress.ip_address(value)
            return address.version == (4 if kind == "ipv4" else 6) and (
                options.include_reserved_ips or address.is_global
            )
        if kind == "domain":
            return valid_domain(value)
        if kind == "email":
            return valid_domain(value.rsplit("@", 1)[1])
        if kind == "url":
            parts = urlsplit(value)
            if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
                return False
            if parts.port is not None and not 1 <= parts.port <= 65535:
                return False
            try:
                host = ipaddress.ip_address(parts.hostname)
            except ValueError:
                return valid_domain(parts.hostname)
            return options.include_reserved_ips or host.is_global
        if kind in {"md5", "sha1", "sha256"}:
            return options.include_zero_hashes or set(value) != {"0"}
        return kind == "cve"
    except ValueError:
        return False
