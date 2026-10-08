"""Typed extraction inputs and results."""

from dataclasses import dataclass
from typing import Literal

IOCType = Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "cve"]


@dataclass(frozen=True)
class IOC:
    """A normalized indicator and its first original sentence."""

    type: IOCType
    value: str
    context: str


@dataclass(frozen=True)
class ExtractionOptions:
    """Controls for reserved addresses, zero hashes, and benign indicators."""

    include_reserved_ips: bool = False
    include_zero_hashes: bool = False
    filter_noise: bool = True
