"""Load and match a configurable benign host whitelist."""

import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

from .models import IOCType
from .refang import refang


def load_whitelist(path: Path) -> frozenset[str]:
    """Read one domain or IP per line, allowing comments and blank lines."""
    entries = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = refang(line.split("#", 1)[0].strip()).lower().rstrip(".")
        if entry:
            try:
                entry = str(ipaddress.ip_address(entry))
            except ValueError:
                pass
            entries.add(entry)
    return frozenset(entries)


def is_noise(kind: IOCType, value: str, whitelist: frozenset[str]) -> bool:
    """Match exact IPs or domains and their subdomains, including URL/email hosts."""
    host = value
    if kind == "url":
        host = urlsplit(value).hostname or ""
    elif kind == "email":
        host = value.rsplit("@", 1)[1]
    elif kind not in {"domain", "ipv4", "ipv6"}:
        return False
    host = host.lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(host)) in whitelist
    except ValueError:
        return any(host == item or host.endswith("." + item) for item in whitelist)
