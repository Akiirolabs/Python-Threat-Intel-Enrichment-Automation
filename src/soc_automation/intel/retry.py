from __future__ import annotations

import asyncio
from typing import Callable, Awaitable, TypeVar

T = TypeVar("T")


async def retry_async(
    fn: Callable[[], Awaitable[T]],
    attempts: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 4.0,
) -> T:
    last_exc: Exception | None = None
    delay = base_delay

    for _ in range(attempts):
        try:
            return await fn()
        except Exception as e:
            last_exc = e
            await asyncio.sleep(delay)
            delay = min(delay * 2, max_delay)

    assert last_exc is not None
    raise last_exc

