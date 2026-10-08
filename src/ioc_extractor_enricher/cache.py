"""Thread-safe SQLite evidence cache with per-indicator TTLs."""

from __future__ import annotations

import asyncio
import json
import math
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, replace
from pathlib import Path

from .enrichment.base import EnrichmentResult
from .models import IOC, IOCType

DEFAULT_TTLS: dict[IOCType, float] = {
    "ipv4": 3600,
    "ipv6": 3600,
    "domain": 21600,
    "url": 3600,
    "md5": 86400,
    "sha1": 86400,
    "sha256": 86400,
    "email": 3600,
    "cve": 86400,
}


class SQLiteCache:
    """Cache selected results; connection access runs off the asyncio event loop."""

    def __init__(
        self,
        path: str | Path,
        *,
        ttls: Mapping[IOCType, float] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Open a cache file (or :memory:) and validate TTL overrides in seconds."""
        self.ttls = DEFAULT_TTLS | dict(ttls or {})
        if any(not math.isfinite(ttl) or ttl < 0 for ttl in self.ttls.values()):
            raise ValueError("TTLs must be nonnegative and finite")
        self._clock = clock
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(str(path), check_same_thread=False)
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS enrichment_cache ("
            "source TEXT NOT NULL, ioc_type TEXT NOT NULL, value TEXT NOT NULL, "
            "expires_at REAL NOT NULL, payload TEXT NOT NULL, "
            "PRIMARY KEY (source, ioc_type, value))"
        )
        self._connection.commit()

    async def get(self, source: str, ioc: IOC) -> EnrichmentResult | None:
        """Return fresh evidence, marking it cached; corrupt entries become misses."""
        return await asyncio.to_thread(self._get, source, ioc)

    def _get(self, source: str, ioc: IOC) -> EnrichmentResult | None:
        """Read and expire a row while holding the connection lock."""
        key = (source, ioc.type, ioc.value)
        with self._lock:
            row = self._connection.execute(
                "SELECT expires_at, payload FROM enrichment_cache "
                "WHERE source=? AND ioc_type=? AND value=?",
                key,
            ).fetchone()
            if row is None:
                return None
            if row[0] <= self._clock():
                self._delete(key)
                return None
            try:
                payload = json.loads(row[1])
                if not isinstance(payload, dict) or not isinstance(payload.get("reasons"), list):
                    raise ValueError("Invalid cached payload")
                payload["reasons"] = tuple(payload["reasons"])
                result = EnrichmentResult(**payload)
                if result.source != source or result.status not in {"ok", "not_found"}:
                    raise ValueError("Invalid cached result")
                return replace(result, cached=True)
            except (ValueError, TypeError, KeyError):
                self._delete(key)
                return None

    def _delete(self, key: tuple[str, str, str]) -> None:
        """Delete an expired or corrupt entry with the caller holding the lock."""
        self._connection.execute(
            "DELETE FROM enrichment_cache WHERE source=? AND ioc_type=? AND value=?",
            key,
        )
        self._connection.commit()

    async def put(self, ioc: IOC, result: EnrichmentResult) -> None:
        """Store evidence and not-found results, never transient failures or disabled sources."""
        ttl = self.ttls[ioc.type]
        if result.status not in {"ok", "not_found"} or ttl == 0:
            return
        payload = json.dumps(asdict(replace(result, cached=False)), allow_nan=False)
        await asyncio.to_thread(self._put, ioc, result.source, payload, ttl)

    def _put(self, ioc: IOC, source: str, payload: str, ttl: float) -> None:
        """Upsert one normalized evidence record under the connection lock."""
        with self._lock:
            self._connection.execute(
                "INSERT INTO enrichment_cache VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(source, ioc_type, value) DO UPDATE SET "
                "expires_at=excluded.expires_at, payload=excluded.payload",
                (source, ioc.type, ioc.value, self._clock() + ttl, payload),
            )
            self._connection.commit()

    async def close(self) -> None:
        """Close the connection without blocking the event loop."""
        await asyncio.to_thread(self._close)

    def _close(self) -> None:
        """Serialize connection closure with pending cache operations."""
        with self._lock:
            self._connection.close()

    async def __aenter__(self) -> SQLiteCache:
        """Use the cache as an async context manager."""
        return self

    async def __aexit__(self, *args: object) -> None:
        """Release the SQLite connection on context exit."""
        await self.close()
