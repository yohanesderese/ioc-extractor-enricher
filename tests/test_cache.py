"""SQLite persistence, isolation, expiry and failure-cache policy tests."""

import asyncio
import sqlite3
from pathlib import Path

import pytest

from ioc_extractor_enricher.cache import SQLiteCache
from ioc_extractor_enricher.enrichment.base import EnrichmentResult, Status
from ioc_extractor_enricher.models import IOC

IP = IOC("ipv4", "8.8.8.8", "Synthetic context must not be cached")


def test_ttl_and_source_isolation(tmp_path: Path) -> None:
    """Per-type TTL overrides expire precisely and provider entries remain independent."""

    async def scenario() -> None:
        now = 100.0
        async with SQLiteCache(
            tmp_path / "cache.db", ttls={"ipv4": 10, "domain": 20}, clock=lambda: now
        ) as cache:
            domain = IOC("domain", "example.com", "")
            evidence = EnrichmentResult(
                "one", "ok", "suspicious", ("Synthetic reason",), {"count": 1}, observed_at=now
            )
            await cache.put(IP, evidence)
            await cache.put(domain, evidence)
            hit = await cache.get("one", IP)
            assert hit and hit.cached and hit.observed_at == 100
            assert hit.reasons == ("Synthetic reason",)
            assert await cache.get("two", IP) is None
            now = 110
            assert await cache.get("one", IP) is None
            assert await cache.get("one", domain) is not None
            now = 120
            assert await cache.get("one", domain) is None

    asyncio.run(scenario())


def test_cache_persistence_and_upsert(tmp_path: Path) -> None:
    """Cache survives reopening and replaces existing evidence without storing context."""
    path = tmp_path / "cache.db"

    async def scenario() -> None:
        async with SQLiteCache(path) as cache:
            await cache.put(IP, EnrichmentResult("one", "ok", "unknown"))
            await cache.put(IP, EnrichmentResult("one", "ok", "suspicious", facts={"count": 2}))
        async with SQLiteCache(path) as cache:
            hit = await cache.get("one", IP)
            assert hit and hit.verdict == "suspicious" and hit.facts == {"count": 2}

    asyncio.run(scenario())
    with sqlite3.connect(path) as connection:
        rows = connection.execute("SELECT payload FROM enrichment_cache").fetchall()
        assert len(rows) == 1
        assert IP.context not in rows[0][0]


@pytest.mark.parametrize("status", ["error", "timeout", "rate_limited", "disabled", "unsupported"])
def test_transient_failures_not_cached(status: Status) -> None:
    """Failures remain retryable rather than becoming persistent unknown evidence."""

    async def scenario() -> None:
        async with SQLiteCache(":memory:") as cache:
            await cache.put(IP, EnrichmentResult("one", status))
            assert await cache.get("one", IP) is None

    asyncio.run(scenario())


def test_not_found_and_zero_ttl() -> None:
    """Not-found reports can be cached, while a zero TTL disables caching for a type."""

    async def scenario() -> None:
        async with SQLiteCache(":memory:") as cache:
            await cache.put(IP, EnrichmentResult("one", "not_found"))
            hit = await cache.get("one", IP)
            assert hit and hit.status == "not_found" and hit.verdict == "unknown"
        async with SQLiteCache(":memory:", ttls={"ipv4": 0}) as cache:
            await cache.put(IP, EnrichmentResult("one", "ok"))
            assert await cache.get("one", IP) is None

    asyncio.run(scenario())


@pytest.mark.parametrize("payload", ["broken JSON", "[]", '{"reasons": "not a list"}'])
def test_corrupt_cache_is_a_miss(tmp_path: Path, payload: str) -> None:
    """A damaged payload is evicted so a new provider lookup can repair it."""
    path = tmp_path / "cache.db"

    async def scenario() -> None:
        async with SQLiteCache(path) as cache:
            await cache.put(IP, EnrichmentResult("one", "ok"))
            with sqlite3.connect(path) as connection:
                connection.execute("UPDATE enrichment_cache SET payload=?", (payload,))
            assert await cache.get("one", IP) is None

    asyncio.run(scenario())


@pytest.mark.parametrize("ttl", [-1, float("inf"), float("nan")])
def test_invalid_ttl(ttl: float) -> None:
    """Reject invalid lifetimes before creating a connection."""
    with pytest.raises(ValueError):
        SQLiteCache(":memory:", ttls={"ipv4": ttl})
