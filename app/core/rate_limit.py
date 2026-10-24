from collections import defaultdict
import time
from fastapi import HTTPException, status


class RateLimiterInstance:
    def __init__(self, limit: int = 5, window_seconds: int = 60, redis_url: str | None = None, requests_per_window: int | None = None) -> None:
        self.limit = requests_per_window if requests_per_window is not None else limit
        self.window_seconds = window_seconds
        self.redis_url = redis_url
        self.requests: dict[str, list[float]] = defaultdict(list)

    async def check_rate_limit(self, org_id: str) -> None:
        now = time.time()
        window_start = now - self.window_seconds

        self.requests[org_id] = [t for t in self.requests[org_id] if t > window_start]

        if len(self.requests[org_id]) >= self.limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too Many Requests",
                headers={"Retry-After": str(self.window_seconds)},
            )

        self.requests[org_id].append(now)


rate_limiter = RateLimiterInstance()


async def check_rate_limit() -> None:
    pass


class RedisRateLimiter(RateLimiterInstance):
    async def is_allowed(self, key: str) -> tuple[bool, int]:
        now = time.time()
        window_start = now - self.window_seconds

        self.requests[key] = [t for t in self.requests[key] if t > window_start]

        if len(self.requests[key]) >= self.limit:
            oldest = self.requests[key][0]
            retry_after = max(1, int(self.window_seconds - (now - oldest)))
            return False, retry_after

        self.requests[key].append(now)
        return True, 0


default_rate_limiter = RedisRateLimiter()