"""Ordered candidate extraction, validation and deduplication."""

import re
from urllib.parse import urlsplit

from .models import IOC, ExtractionOptions, IOCType
from .noise_filter import is_noise
from .normalization import normalize
from .refang import refang
from .validation import valid

_PATTERNS: list[tuple[IOCType, re.Pattern[str]]] = [
    ("url", re.compile(r"\bhttps?://[^\s<>\"']+", re.I)),
    (
        "email",
        re.compile(
            r"(?<![\w.+-])[\w.!#$%&'*+/=?^`{|}~-]+@"
            r"[a-z0-9-]+(?:\.[a-z0-9-]+)+",
            re.I,
        ),
    ),
    ("ipv6", re.compile(r"(?<![\w:])[a-f0-9:]*:[a-f0-9:.]+(?![\w:])", re.I)),
    ("ipv4", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")),
    ("sha256", re.compile(r"\b[a-f0-9]{64}\b", re.I)),
    ("sha1", re.compile(r"\b[a-f0-9]{40}\b", re.I)),
    ("md5", re.compile(r"\b[a-f0-9]{32}\b", re.I)),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)),
    (
        "domain",
        re.compile(
            r"(?<![\w.@-])[a-z0-9-]+(?:\.[a-z0-9-]+)+"
            r"(?![\w-])",
            re.I,
        ),
    ),
]


def extract(
    text: str,
    options: ExtractionOptions | None = None,
    whitelist: frozenset[str] = frozenset(),
) -> list[IOC]:
    """Extract unique IOCs with original sentence context, retaining first occurrence."""
    options = options or ExtractionOptions()
    results: dict[tuple[IOCType, str], IOC] = {}

    def add(kind: IOCType, candidate: str, context: str) -> None:
        if not valid(kind, candidate, options):
            return
        value = normalize(kind, candidate)
        if options.filter_noise and is_noise(kind, value, whitelist):
            return
        results.setdefault((kind, value), IOC(kind, value, context))

    for sentence in re.split(r"(?<=[.!?])\s+|\n+", text):
        context = sentence.strip()
        restored = refang(context)
        occupied: list[tuple[int, int]] = []
        for kind, pattern in _PATTERNS:
            for match in pattern.finditer(restored):
                if any(match.start() < end and match.end() > start for start, end in occupied):
                    continue
                candidate = match.group().rstrip(".,;!?")
                if kind == "url":
                    occupied.append(match.span())
                    # Remove unbalanced prose closing punctuation, preserving URL brackets.
                    for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
                        while candidate.endswith(closing) and candidate.count(closing) > (
                            candidate.count(opening)
                        ):
                            candidate = candidate[:-1]
                if not valid(kind, candidate, options):
                    continue
                if kind != "url":
                    occupied.append(match.span())
                add(kind, candidate, context)
                if kind in {"url", "email"}:
                    host = (
                        urlsplit(candidate).hostname
                        if kind == "url"
                        else candidate.rsplit("@", 1)[1]
                    )
                    if host:
                        add("domain", host, context)
                        if kind == "url":
                            add("ipv4", host, context)
                            add("ipv6", host, context)
    return list(results.values())
