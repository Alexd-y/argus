"""Tests for ARGUS-007 RateLimiter — overflow, memory mode, Redis mocked (no real broker in CI)."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from src.tools.guardrails.rate_limiter import RateLimiter


class TestRateLimiterMemoryMode:
    """RateLimiter with redis=None — in-memory fallback."""

    def test_first_request_allowed(self) -> None:
        limiter = RateLimiter(redis_client=None, max_requests=3, window_seconds=60)
        allowed, reason = limiter.is_allowed("user-1")
        assert allowed is True
        assert reason == ""

    def test_under_limit_allowed(self) -> None:
        limiter = RateLimiter(redis_client=None, max_requests=5, window_seconds=60)
        for _ in range(4):
            allowed, _ = limiter.is_allowed("key")
            assert allowed is True

    def test_at_limit_blocked(self) -> None:
        limiter = RateLimiter(redis_client=None, max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter.is_allowed("key")
        allowed, reason = limiter.is_allowed("key")
        assert allowed is False
        assert "rate limit" in reason.lower()

    def test_overflow_exceeds_limit_blocked(self) -> None:
        """Exceeding max_requests triggers rate limit."""
        limiter = RateLimiter(redis_client=None, max_requests=2, window_seconds=60)
        limiter.is_allowed("overflow-key")
        limiter.is_allowed("overflow-key")
        allowed, reason = limiter.is_allowed("overflow-key")
        assert allowed is False
        assert "exceeded" in reason.lower() or "limit" in reason.lower()

    def test_different_keys_independent(self) -> None:
        limiter = RateLimiter(redis_client=None, max_requests=1, window_seconds=60)
        limiter.is_allowed("key-a")
        allowed_a, _ = limiter.is_allowed("key-a")
        allowed_b, _ = limiter.is_allowed("key-b")
        assert allowed_a is False
        assert allowed_b is True

    def test_window_expiry_allows_again(self) -> None:
        """After window expires, requests allowed again (mock time)."""
        limiter = RateLimiter(redis_client=None, max_requests=1, window_seconds=60)
        with patch("src.tools.guardrails.rate_limiter.time") as mock_time:
            mock_time.time.return_value = 100.0
            limiter.is_allowed("expiry-key")
            allowed, _ = limiter.is_allowed("expiry-key")
            assert allowed is False
            mock_time.time.return_value = 161.0
            allowed, _ = limiter.is_allowed("expiry-key")
        assert allowed is True


class TestRateLimiterRedisMode:
    """RateLimiter with mocked Redis — no real Redis in CI."""

    def test_redis_mode_uses_pipeline(self) -> None:
        """Redis path uses pipeline; no real connection."""
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.zremrangebyscore.return_value = mock_pipe
        mock_pipe.zadd.return_value = mock_pipe
        mock_pipe.zcard.return_value = mock_pipe
        mock_pipe.expire.return_value = mock_pipe
        mock_pipe.execute.return_value = [None, None, 1, None]
        mock_redis.pipeline.return_value = mock_pipe

        limiter = RateLimiter(redis_client=mock_redis, max_requests=60, window_seconds=60)
        allowed, reason = limiter.is_allowed("redis-key")
        assert allowed is True
        mock_redis.pipeline.assert_called_once()
        mock_pipe.execute.assert_called_once()

    def test_redis_mode_overflow_blocked(self) -> None:
        """Redis returns count > max_requests → blocked."""
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_pipe.zremrangebyscore.return_value = mock_pipe
        mock_pipe.zadd.return_value = mock_pipe
        mock_pipe.zcard.return_value = mock_pipe
        mock_pipe.expire.return_value = mock_pipe
        mock_pipe.execute.return_value = [None, None, 61, None]
        mock_redis.pipeline.return_value = mock_pipe

        limiter = RateLimiter(redis_client=mock_redis, max_requests=60, window_seconds=60)
        allowed, reason = limiter.is_allowed("overflow")
        assert allowed is False
        assert "rate limit" in reason.lower()

    def test_redis_error_falls_back_to_allow(self) -> None:
        """On Redis exception, fallback allows request (fail-open for availability)."""
        mock_redis = MagicMock()
        mock_redis.pipeline.side_effect = ConnectionError("Redis unavailable")

        limiter = RateLimiter(redis_client=mock_redis, max_requests=60, window_seconds=60)
        allowed, reason = limiter.is_allowed("key")
        assert allowed is True
        assert reason == ""
