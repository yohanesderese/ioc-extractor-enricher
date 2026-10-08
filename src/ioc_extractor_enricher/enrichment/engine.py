"""Concurrent source enrichment with cached evidence and isolated failures."""

from __future__ import annotations

import asyncio
import math
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import TYPE_CHECKING

from ..models import IOC
from ..normalization import normalize
from ..rate_limit import RateLimiter
from .base import EnrichmentPlugin, EnrichmentResult, HTTPPlugin

if TYPE_CHECKING:
    from ..cache import SQLiteCache


class EnrichmentEngine:
    """Sources run concurrently; each source queues its own lookups in order."""

    def __init__(
        self,
        plugins: Sequence[EnrichmentPlugin],
        cache: SQLiteCache | None = None,
        *,
        timeout: float = 10.0,
        intervals: Mapping[str, float] | None = None,
    ) -> None:
        """Configure one limiter per uniquely named source; caller owns cache/client."""
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Timeout must be positive and finite")
        self.plugins = tuple(plugins)
        if len({plugin.name for plugin in plugins}) != len(plugins):
            raise ValueError("Source names must be unique")
        self.cache = cache
        self.timeout = timeout
        self._limiters = {
            plugin.name: RateLimiter((intervals or {}).get(plugin.name, plugin.interval))
            for plugin in plugins
        }

    async def _cached(self, plugin: EnrichmentPlugin, ioc: IOC) -> EnrichmentResult | None:
        """Cache failures degrade to misses rather than hiding source evidence."""
        if self.cache is None:
            return None
        try:
            return await self.cache.get(plugin.name, ioc)
        except (sqlite3.Error, OSError):
            return None

    async def _lookup(self, plugin: EnrichmentPlugin, ioc: IOC) -> EnrichmentResult:
        """Recheck cache within the queue to coalesce simultaneous identical lookups."""
        try:
            if not plugin.supports(ioc.type):
                return EnrichmentResult(
                    plugin.name,
                    "unsupported",
                    reasons=("Indicator type is not supported by this source.",),
                )
            if isinstance(plugin, HTTPPlugin) and not plugin.configured:
                return await plugin.lookup(ioc)
            cached = await self._cached(plugin, ioc)
            if cached is not None:
                return cached
            limiter = self._limiters[plugin.name]
            async with limiter.slot():
                cached = await self._cached(plugin, ioc)
                if cached is not None:
                    return cached
                await limiter.wait()
                async with asyncio.timeout(self.timeout):
                    result = await plugin.lookup(ioc)
                if result.source != plugin.name:
                    raise ValueError("Plugin returned a different source name")
                if result.status == "rate_limited":
                    limiter.defer(
                        result.retry_after
                        if result.retry_after is not None
                        else max(plugin.interval, 60.0)
                    )
                if self.cache is not None:
                    try:
                        await self.cache.put(ioc, result)
                    except (sqlite3.Error, OSError):
                        pass
                return result
        except TimeoutError:
            return EnrichmentResult(plugin.name, "timeout", reasons=("Source lookup timed out.",))
        except Exception:
            # Do not expose exceptions: they can embed authenticated request details.
            return EnrichmentResult(plugin.name, "error", reasons=("Source lookup failed.",))

    async def enrich(self, ioc: IOC) -> list[EnrichmentResult]:
        """Normalize one IOC and return results in configured source order."""
        ioc = replace(ioc, value=normalize(ioc.type, ioc.value))
        return list(await asyncio.gather(*(self._lookup(plugin, ioc) for plugin in self.plugins)))

    async def enrich_many(self, iocs: Sequence[IOC]) -> list[list[EnrichmentResult]]:
        """Enrich a batch in input order with independent queues per provider."""
        return list(await asyncio.gather(*(self.enrich(ioc) for ioc in iocs)))
