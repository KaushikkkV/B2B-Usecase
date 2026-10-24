import time
from collections import defaultdict


class TenantRateLimiter:
    def __init__(self, requests_per_window: int = 5, window_seconds: int = 60) -> None:
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self._history: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> tuple[bool, int]:
        """
        Check if request under key (e.g. org_id or org_id:user_id) is permitted.
        Returns: (allowed: bool, retry_after_seconds: int)
        """
        now = time.monotonic()
        window_start = now - self.window_seconds

        # Prune calls outside current sliding window
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


# Default limiter instance with 5 req/min threshold for integration tests
default_rate_limiter = TenantRateLimiter(requests_per_window=5, window_seconds=60)