"""FIFO per-source request serialization, spacing and quota cooldowns."""

import asyncio
import math
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager


class RateLimiter:
    """A fair asyncio lock queues requests, with a monotonic start-time limit."""

    def __init__(
        self,
        interval: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """Set the minimum number of seconds between request starts."""
        if not math.isfinite(interval) or interval < 0:
            raise ValueError("Interval must be nonnegative and finite")
        self.interval = interval
        self._clock = clock
        self._sleep = sleep
        self._next_start = 0.0
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        """Queue FIFO, releasing the source even when a lookup is cancelled."""
        async with self._lock:
            yield

    async def wait(self) -> None:
        """Reserve a request start while inside slot(); cache hits need no reservation."""
        remaining = self._next_start - self._clock()
        while remaining > 0:
            await self._sleep(remaining)
            remaining = self._next_start - self._clock()
        self._next_start = self._clock() + self.interval

    def defer(self, delay: float) -> None:
        """Apply a provider Retry-After cooldown while inside slot()."""
        if not math.isfinite(delay) or delay < 0:
            raise ValueError("Cooldown must be nonnegative and finite")
        self._next_start = max(self._next_start, self._clock() + delay)
