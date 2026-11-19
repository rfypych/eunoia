"""Per-identity rate limiting (spec §5.5, Task 10).

Fixed windows, in-memory (no Redis in MVP): one minute bucket and one
calendar-day (UTC) bucket per identity. Tiers: anon 60 req/min +
1,000 req/day; free key 600 req/min + 100,000 req/day. A check both
counts and reports: callers get the per-minute limit, the remaining
budget, the reset epoch, and — when denied — seconds until retry.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone

__all__ = ["RateLimiter", "RateLimitResult"]


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    reset: int  # unix epoch when the minute window resets
    retry_after: int | None = None  # seconds until retry, when denied


class RateLimiter:
    """In-memory fixed-window limiter. One instance per app; tests build
    their own with small limits."""

    def __init__(
        self,
        *,
        anon_per_minute: int = 60,
        anon_per_day: int = 1_000,
        key_per_minute: int = 600,
        key_per_day: int = 100_000,
    ) -> None:
        self._limits = {
            "anon": (anon_per_minute, anon_per_day),
            "free": (key_per_minute, key_per_day),
        }
        self._buckets: dict[str, dict[str, tuple[int, int]]] = {}
        self._lock = threading.Lock()

    def _window(self, identity: str, kind: str, window: int) -> int:
        bucket = self._buckets.setdefault(identity, {}).get(kind)
        if bucket is None or bucket[0] != window:
            self._buckets[identity][kind] = (window, 0)
            return 0
        return bucket[1]

    def _bump(self, identity: str, kind: str, window: int) -> int:
        count = self._window(identity, kind, window) + 1
        self._buckets[identity][kind] = (window, count)
        return count

    def check(
        self, identity: str, tier: str, now: float | None = None
    ) -> RateLimitResult:
        """Count one request for ``identity``; deny when either window
        is exhausted. The minute window is checked first."""
        per_minute, per_day = self._limits.get(tier, self._limits["anon"])
        now = time.time() if now is None else now
        minute_window = int(now // 60)
        day_window = datetime.fromtimestamp(now, tz=timezone.utc).toordinal()
        reset = (minute_window + 1) * 60
        with self._lock:
            minute_count = self._window(identity, "minute", minute_window)
            day_count = self._window(identity, "day", day_window)
            if minute_count >= per_minute:
                return RateLimitResult(
                    allowed=False, limit=per_minute,
                    remaining=0, reset=reset,
                    retry_after=max(1, reset - int(now)),
                )
            if day_count >= per_day:
                midnight = (
                    datetime.fromtimestamp(now, tz=timezone.utc)
                    .replace(hour=0, minute=0, second=0, microsecond=0)
                    .timestamp()
                    + 86400
                )
                return RateLimitResult(
                    allowed=False, limit=per_minute,
                    remaining=max(0, per_minute - minute_count),
                    reset=reset,
                    retry_after=max(1, int(midnight - now)),
                )
            minute_count = self._bump(identity, "minute", minute_window)
            self._bump(identity, "day", day_window)
        return RateLimitResult(
            allowed=True, limit=per_minute,
            remaining=max(0, per_minute - minute_count), reset=reset,
        )
