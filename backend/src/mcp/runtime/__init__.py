"""MCP runtime — request-path infrastructure shared by every tool.

The :mod:`runtime` package owns concerns that wrap *every* MCP request
(rate limiting, future quota tracking, etc.) but are independent of any
single tool. Implementations live alongside the typed contracts so the
server / dispatcher layers can depend on a small, well-defined surface.
"""

from src.mcp.runtime.rate_limiter import (
    DEFAULT_BUCKET_BURST,
    DEFAULT_BUCKET_RATE_PER_SECOND,
    BucketBudget,
    BucketDecision,
    InMemoryTokenBucket,
    RateLimitedDecision,
    RedisTokenBucket,
    TokenBucketLimiter,
    build_rate_limiter,
)

__all__ = [
    "DEFAULT_BUCKET_BURST",
    "DEFAULT_BUCKET_RATE_PER_SECOND",
    "BucketBudget",
    "BucketDecision",
    "InMemoryTokenBucket",
    "RateLimitedDecision",
    "RedisTokenBucket",
    "TokenBucketLimiter",
    "build_rate_limiter",
]
