"""Plugin contract, normalized evidence and safe HTTP error handling."""

import asyncio
import math
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Literal, Protocol

import httpx

from ..models import IOC, IOCType

Verdict = Literal["malicious", "suspicious", "clean", "unknown"]
Status = Literal["ok", "not_found", "disabled", "unsupported", "timeout", "rate_limited", "error"]
Fact = str | int | bool | None


@dataclass(frozen=True)
class EnrichmentResult:
    """Selected evidence only; never stores request headers or raw error bodies."""

    source: str
    status: Status
    verdict: Verdict = "unknown"
    reasons: tuple[str, ...] = ()
    facts: dict[str, Fact] = field(default_factory=dict)
    link: str | None = None
    observed_at: float = field(default_factory=time.time)
    cached: bool = False
    retry_after: float | None = None

    def __post_init__(self) -> None:
        """Reject invalid normalized evidence, including corrupt cached payloads."""
        if not isinstance(self.source, str) or not self.source:
            raise ValueError("A source name is required")
        if self.status not in {
            "ok",
            "not_found",
            "disabled",
            "unsupported",
            "timeout",
            "rate_limited",
            "error",
        }:
            raise ValueError("Invalid result status")
        if self.verdict not in {"malicious", "suspicious", "clean", "unknown"}:
            raise ValueError("Invalid source verdict")
        if self.status != "ok" and self.verdict != "unknown":
            raise ValueError("Unavailable evidence must have an unknown verdict")
        if not isinstance(self.reasons, tuple) or any(
            not isinstance(reason, str) for reason in self.reasons
        ):
            raise ValueError("Reasons must be a tuple of strings")
        if not isinstance(self.facts, dict) or any(
            not isinstance(key, str) or (value is not None and type(value) not in {str, int, bool})
            for key, value in self.facts.items()
        ):
            raise ValueError("Facts must contain named scalar values")
        if self.link is not None and not isinstance(self.link, str):
            raise ValueError("Link must be a string")
        if not math.isfinite(self.observed_at) or type(self.cached) is not bool:
            raise ValueError("Invalid observation metadata")
        if self.retry_after is not None and (
            not math.isfinite(self.retry_after) or self.retry_after < 0
        ):
            raise ValueError("Invalid retry delay")


class EnrichmentPlugin(Protocol):
    """Interface for independently scheduled threat intelligence providers."""

    name: str
    interval: float

    def supports(self, ioc_type: IOCType) -> bool:
        """Whether this provider can look up the indicator type."""
        ...

    async def lookup(self, ioc: IOC) -> EnrichmentResult:
        """Fetch normalized evidence for one indicator."""
        ...


def count(value: object) -> int:
    """Require a nonnegative integer, rejecting malformed provider evidence."""
    if type(value) is not int or value < 0:
        raise ValueError("Invalid evidence count")
    return value


def selected_facts(data: dict, names: tuple[str, ...]) -> dict[str, Fact]:
    """Keep only explicitly selected scalar provider fields."""
    return {
        name: data[name]
        for name in names
        if name in data and (data[name] is None or type(data[name]) in {str, int, bool})
    }


def retry_delay(value: str | None) -> float | None:
    """Parse Retry-After seconds or an HTTP date without retaining response bodies."""
    if value is None:
        return None
    try:
        delay = float(value)
    except ValueError:
        try:
            delay = (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds()
        except (ValueError, TypeError, OverflowError):
            return None
    return max(0.0, delay) if math.isfinite(delay) else None


class HTTPPlugin(ABC):
    """Common lookup flow; the supplied client remains owned by the caller."""

    name: str
    interval: float = 1.0
    env_key: str
    auth_header: str
    types: frozenset[IOCType]
    requires_key: bool = True

    def __init__(self, client: httpx.AsyncClient, *, timeout: float = 10.0) -> None:
        """Read only this source's key from the environment; never load .env files."""
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Timeout must be positive and finite")
        self.client = client
        self.timeout = timeout
        self._key = os.environ.get(self.env_key, "").strip() if self.requires_key else ""

    def supports(self, ioc_type: IOCType) -> bool:
        """Check the source's explicitly supported types."""
        return ioc_type in self.types

    @property
    def configured(self) -> bool:
        """Whether an environment key is present rather than an example placeholder."""
        return not self.requires_key or bool(self._key and self._key != "...")

    async def request(self, ioc: IOC) -> httpx.Response:
        """Perform a fixed-endpoint GET; POST lookup adapters override this method."""
        url, params = self.endpoint(ioc)
        return await self.client.get(
            url,
            params=params,
            headers=self.headers(),
            timeout=self.timeout,
            follow_redirects=False,
        )

    def headers(self) -> dict[str, str]:
        """Omit authentication entirely for public providers."""
        return {"Accept": "application/json"} | (
            {self.auth_header: self._key} if self.requires_key else {}
        )

    @abstractmethod
    def endpoint(self, ioc: IOC) -> tuple[str, dict[str, str]]:
        """Return the fixed provider endpoint and query parameters."""

    @abstractmethod
    def parse(self, ioc: IOC, payload: dict) -> EnrichmentResult:
        """Select evidence from a successful provider response."""

    async def lookup(self, ioc: IOC) -> EnrichmentResult:
        """Handle absent keys, HTTP failures and malformed payloads safely."""

        def failure(status: Status, reason: str, **kwargs: object) -> EnrichmentResult:
            return EnrichmentResult(self.name, status, reasons=(reason,), **kwargs)

        if not self.supports(ioc.type):
            return failure("unsupported", "Indicator type is not supported by this source.")
        if not self.configured:
            return failure("disabled", "Source API key is not configured.")
        try:
            # Never forward a key across redirects, even with a redirect-enabled client.
            async with asyncio.timeout(self.timeout):
                response = await self.request(ioc)
            if response.status_code == 404:
                return failure("not_found", "Source has no report for this indicator.")
            if response.status_code == 429:
                return failure(
                    "rate_limited",
                    "Source request quota was reached.",
                    retry_after=retry_delay(response.headers.get("Retry-After")),
                )
            if response.status_code in {401, 403}:
                return failure("error", "Source rejected authentication or access.")
            if response.status_code != 200:
                return failure("error", f"Source returned HTTP {response.status_code}.")
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Invalid response shape")
            return self.parse(ioc, payload)
        except (TimeoutError, httpx.TimeoutException):
            return failure("timeout", "Source lookup timed out.")
        except httpx.RequestError:
            return failure("error", "Source could not be reached.")
        except (ValueError, TypeError, KeyError, AttributeError):
            return failure("error", "Source returned malformed evidence.")
