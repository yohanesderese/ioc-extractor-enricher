"""Deterministic request queue and cancellation tests without real waiting."""

import asyncio

import pytest

from ioc_extractor_enricher.rate_limit import RateLimiter


def test_fifo_spacing() -> None:
    """Concurrent requests enter in FIFO order and respect minimum spacing."""

    async def scenario() -> None:
        now = 100.0
        starts = []

        async def advance(delay: float) -> None:
            nonlocal now
            now += delay
            await asyncio.sleep(0)

        limiter = RateLimiter(15, clock=lambda: now, sleep=advance)

        async def request(index: int) -> None:
            async with limiter.slot():
                await limiter.wait()
                starts.append((index, now))
                await asyncio.sleep(0)

        await asyncio.gather(*(request(index) for index in range(3)))
        assert starts == [(0, 100), (1, 115), (2, 130)]

    asyncio.run(scenario())


def test_cancelled_waiter_does_not_block_queue() -> None:
    """Cancelling a queued request releases its place without consuming a slot."""

    async def scenario() -> None:
        limiter = RateLimiter(0)
        async with limiter.slot():

            async def queued() -> None:
                async with limiter.slot():
                    await limiter.wait()

            task = asyncio.create_task(queued())
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        async with limiter.slot():
            await limiter.wait()

    asyncio.run(scenario())


@pytest.mark.parametrize("interval", [-1, float("inf"), float("nan")])
def test_invalid_interval(interval: float) -> None:
    """Reject configurations that could invalidate quota spacing."""
    with pytest.raises(ValueError):
        RateLimiter(interval)
