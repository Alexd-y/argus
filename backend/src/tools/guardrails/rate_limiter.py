"""RateLimiter — per-key rate limiting via Redis (Phase 5)."""

import logging
import time

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Token-bucket style rate limiter.
    Uses Redis when available; falls back to in-memory when not.
    """

    def __init__(
        self,
        redis_client=None,
        max_requests: int = 60,
        window_seconds: int = 60,
    ):
        self.redis = redis_client
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._memory: dict[str, list[float]] = {}

    def is_allowed(self, key: str) -> tuple[bool, str]:
        """
        Check if request is allowed for key.
        Returns (allowed: bool, reason: str).
        """
        now = time.time()
        if self.redis:
            return self._check_redis(key, now)
        return self._check_memory(key, now)

    def _check_redis(self, key: str, now: float) -> tuple[bool, str]:
        try:
            redis_key = f"ratelimit:{key}"
            pipe = self.redis.pipeline()
            pipe.zremrangebyscore(redis_key, 0, now - self.window_seconds)
            pipe.zadd(redis_key, {str(now): now})
            pipe.zcard(redis_key)
            pipe.expire(redis_key, self.window_seconds)
            results = pipe.execute()
            count = results[2]
            if count > self.max_requests:
                return False, "Rate limit exceeded"
            return True, ""
        except Exception as e:
            logger.warning("RateLimiter Redis error, falling back to allow: %s", str(e)[:80])
            return True, ""

    def _check_memory(self, key: str, now: float) -> tuple[bool, str]:
        cutoff = now - self.window_seconds
        if key not in self._memory:
            self._memory[key] = []
        timestamps = self._memory[key]
        timestamps[:] = [t for t in timestamps if t > cutoff]
        if len(timestamps) >= self.max_requests:
            return False, "Rate limit exceeded"
        timestamps.append(now)
        return True, ""
