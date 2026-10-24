import os
import time
from collections import defaultdict
from typing import Any

import redis.asyncio as aioredis


class TenantRateLimiter:
    """Synchronous in-memory rate limiter kept for backward compatibility."""

    def __init__(self, requests_per_window: int = 5, window_seconds: int = 60) -> None:
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self._history: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        window_start = now - self.window_seconds

        valid_timestamps = [t for t in self._history[key] if t > window_start]
        self._history[key] = valid_timestamps

        if len(valid_timestamps) >= self.requests_per_window:
            oldest = valid_timestamps[0]
            retry_after = max(1, int(self.window_seconds - (now - oldest)))
            return False, retry_after

        self._history[key].append(now)
        return True, 0

    def reset(self) -> None:
        self._history.clear()


class RedisRateLimiter:
    """
    Distributed sliding window rate limiter backed by Redis sorted sets.
    Falls back to an async in-memory sliding window if Redis is not configured or unavailable.
    """

    def __init__(
        self,
        redis_url: str | None = None,
        requests_per_window: int = 5,
        window_seconds: int = 60,
    ) -> None:
        self.redis_url = redis_url or os.getenv("REDIS_URL")
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self._memory_history: dict[str, list[float]] = defaultdict(list)
        self._redis_client: Any | None = None

        if self.redis_url:
            self._redis_client = aioredis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )

    async def is_allowed(self, key: str) -> tuple[bool, int]:
        if self._redis_client is not None:
            try:
                return await self._is_allowed_redis(key)
            except Exception:
                return self._is_allowed_memory(key)
        return self._is_allowed_memory(key)

    async def _is_allowed_redis(self, key: str) -> tuple[bool, int]:
        client = self._redis_client
        if client is None:
            return self._is_allowed_memory(key)

        redis_key = f"ratelimit:{key}"
        now = time.time()
        window_start = now - self.window_seconds

        async with client.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(redis_key, 0, window_start)
            pipe.zcard(redis_key)
            pipe.zrange(redis_key, 0, 0, withscores=True)
            results = await pipe.execute()

        current_count = results[1]
        oldest_records = results[2]

        if current_count >= self.requests_per_window:
            oldest_ts = oldest_records[0][1] if oldest_records else now
            retry_after = max(1, int(self.window_seconds - (now - oldest_ts)))
            return False, retry_after

        async with client.pipeline(transaction=True) as pipe:
            pipe.zadd(redis_key, {f"{now}": now})
            pipe.expire(redis_key, self.window_seconds + 1)
            await pipe.execute()

        return True, 0

    def _is_allowed_memory(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        window_start = now - self.window_seconds

        valid_timestamps = [t for t in self._memory_history[key] if t > window_start]
        self._memory_history[key] = valid_timestamps

        if len(valid_timestamps) >= self.requests_per_window:
            oldest = valid_timestamps[0]
            retry_after = max(1, int(self.window_seconds - (now - oldest)))
            return False, retry_after

        self._memory_history[key].append(now)
        return True, 0

    def reset(self) -> None:
        self._memory_history.clear()


default_rate_limiter = RedisRateLimiter(requests_per_window=5, window_seconds=60)