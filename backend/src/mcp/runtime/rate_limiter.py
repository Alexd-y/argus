"""Token-bucket rate limiter for MCP ``tools/call`` requests (ARG-035).

Two implementations satisfy the same :class:`TokenBucketLimiter` Protocol:

* :class:`InMemoryTokenBucket` — single-process, asyncio-aware. Used by
  default (no external dependency) and by every unit test.
* :class:`RedisTokenBucket` — distributed; uses a small Lua script to
  perform the read-refill-decrement atomically. Used in production when
  multiple MCP server instances share a Redis cluster (matches the
  Celery broker we already deploy).

Both implementations enforce two budgets per request:

* per-client (``client_id`` from ``MCPAuthContext.user_id``);
* per-tenant (``tenant_id`` from ``MCPAuthContext.tenant_id``).

A request is allowed only when *both* budgets have enough tokens.
On rejection, the limiter raises :class:`RateLimitedError` with a
``Retry-After`` (seconds until the deficit budget refills enough for the
request); the value is also exposed on :class:`RateLimitedDecision` so
the JSON-RPC caller can surface code ``-32029``.

The configuration lives in ``backend/config/mcp/server.yaml`` under
``rate_limiter`` and is loaded once at server-build time.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, Protocol, runtime_checkable

from src.mcp.exceptions import RateLimitedError


@runtime_checkable
class _RedisLikeClient(Protocol):
    """Minimal subset of the ``redis.asyncio.Redis`` API we depend on.

    Typed via :class:`Protocol` so we stay decoupled from the optional
    ``redis`` package — the production wiring layer injects the real
    client, while tests inject a fake. mypy --strict is satisfied because
    every awaited attribute has an explicit signature.
    """

    async def script_load(self, script: str) -> bytes | str: ...

    async def evalsha(
        self,
        sha: str,
        numkeys: int,
        *keys_and_args: str,
    ) -> Sequence[Any]: ...


_logger = logging.getLogger(__name__)

DEFAULT_BUCKET_RATE_PER_SECOND: Final[float] = 5.0
DEFAULT_BUCKET_BURST: Final[int] = 30

JSONRPC_RATE_LIMIT_CODE: Final[int] = -32029
"""JSON-RPC error code returned to the client on rejection."""


@dataclass(frozen=True, slots=True)
class BucketBudget:
    """Per-bucket capacity + refill rate.

    A request consuming ``tokens`` is allowed iff the bucket holds
    ``>= tokens`` after refilling. The bucket cannot exceed ``burst``.
    """

    rate_per_second: float
    burst: int

    def __post_init__(self) -> None:
        if self.rate_per_second <= 0:
            raise ValueError("rate_per_second must be > 0")
        if self.burst < 1:
            raise ValueError("burst must be >= 1")
        if self.burst < self.rate_per_second:
            raise ValueError("burst must be >= rate_per_second")


@dataclass(frozen=True, slots=True)
class BucketDecision:
    """Outcome of a single :meth:`TokenBucketLimiter.acquire` call."""

    allowed: bool
    retry_after_seconds: float
    deficit_scope: Literal["client", "tenant", "none"]
    remaining_client: float
    remaining_tenant: float


class RateLimitedDecision(RateLimitedError):
    """:class:`RateLimitedError` enriched with ``retry_after`` for JSON-RPC.

    The MCP server unwraps this to populate the JSON-RPC ``error.data``
    payload (``{"retry_after": <seconds>, "scope": "client" | "tenant"}``).
    """

    def __init__(
        self,
        *,
        retry_after_seconds: float,
        deficit_scope: Literal["client", "tenant"],
        client_id: str,
        tenant_id: str,
    ) -> None:
        super().__init__(
            f"Rate limit exceeded for {deficit_scope}; retry after "
            f"{retry_after_seconds:.2f}s",
        )
        self.retry_after_seconds = max(0.0, float(retry_after_seconds))
        self.deficit_scope = deficit_scope
        self.client_id = client_id
        self.tenant_id = tenant_id

    def jsonrpc_error_payload(self) -> dict[str, object]:
        """Return a JSON-RPC `error` body matching the contract."""
        return {
            "code": JSONRPC_RATE_LIMIT_CODE,
            "message": self.message,
            "data": {
                "retry_after": round(self.retry_after_seconds, 3),
                "scope": self.deficit_scope,
            },
        }


@runtime_checkable
class TokenBucketLimiter(Protocol):
    """Wire contract for every backend implementation.

    The runtime calls :meth:`acquire` from inside the per-tool wrapper
    (``run_tool``) before the body executes. Implementations MUST raise
    :class:`RateLimitedDecision` on rejection — never return ``False`` —
    because :func:`run_tool` distinguishes auth / validation / rate-limit
    failures via the typed exception channel.
    """

    async def acquire(
        self,
        *,
        client_id: str,
        tenant_id: str,
        tokens: int = 1,
    ) -> BucketDecision: ...

    async def aclose(self) -> None: ...


def _budget_lookup(
    *, mapping: Mapping[str, BucketBudget], key: str, default: BucketBudget
) -> BucketBudget:
    return mapping.get(key, default)


def _compute_retry_after(
    *,
    tokens_required: float,
    available: float,
    rate_per_second: float,
) -> float:
    """Time (seconds) until the bucket holds ``tokens_required`` again."""
    deficit = max(0.0, tokens_required - available)
    if deficit <= 0:
        return 0.0
    return deficit / rate_per_second


class InMemoryTokenBucket:
    """asyncio-aware single-process token bucket.

    The implementation stores per-key ``(tokens, last_refill_ts)`` in a
    dict guarded by a single :class:`asyncio.Lock`. Lock contention is
    bounded at "MCP requests per second" — well under what asyncio can
    serialise — so the simple design is fine for the per-process case.
    """

    backend_name = "memory"

    def __init__(
        self,
        *,
        default_client_budget: BucketBudget,
        default_tenant_budget: BucketBudget,
        per_client_budgets: Mapping[str, BucketBudget] | None = None,
        per_tenant_budgets: Mapping[str, BucketBudget] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._default_client_budget = default_client_budget
        self._default_tenant_budget = default_tenant_budget
        self._per_client_budgets: dict[str, BucketBudget] = dict(
            per_client_budgets or {}
        )
        self._per_tenant_budgets: dict[str, BucketBudget] = dict(
            per_tenant_budgets or {}
        )
        self._client_state: dict[str, tuple[float, float]] = {}
        self._tenant_state: dict[str, tuple[float, float]] = {}
        self._lock = asyncio.Lock()
        self._clock = clock

    def get_client_budget(self, client_id: str) -> BucketBudget:
        return _budget_lookup(
            mapping=self._per_client_budgets,
            key=client_id,
            default=self._default_client_budget,
        )

    def get_tenant_budget(self, tenant_id: str) -> BucketBudget:
        return _budget_lookup(
            mapping=self._per_tenant_budgets,
            key=tenant_id,
            default=self._default_tenant_budget,
        )

    def _refill(
        self,
        *,
        state: dict[str, tuple[float, float]],
        key: str,
        budget: BucketBudget,
        now: float,
    ) -> tuple[float, float]:
        """Return ``(tokens_available_after_refill, last_ts)`` and persist it."""
        cached = state.get(key)
        if cached is None:
            return float(budget.burst), now
        tokens, last_ts = cached
        if now <= last_ts:
            return tokens, last_ts
        elapsed = now - last_ts
        refilled = min(budget.burst, tokens + elapsed * budget.rate_per_second)
        return refilled, now

    async def acquire(
        self,
        *,
        client_id: str,
        tenant_id: str,
        tokens: int = 1,
    ) -> BucketDecision:
        if tokens <= 0:
            raise ValueError("tokens must be >= 1")

        async with self._lock:
            now = self._clock()
            client_budget = self.get_client_budget(client_id)
            tenant_budget = self.get_tenant_budget(tenant_id)

            client_tokens, client_ts = self._refill(
                state=self._client_state,
                key=client_id,
                budget=client_budget,
                now=now,
            )
            tenant_tokens, tenant_ts = self._refill(
                state=self._tenant_state,
                key=tenant_id,
                budget=tenant_budget,
                now=now,
            )

            client_short = client_tokens < tokens
            tenant_short = tenant_tokens < tokens
            if client_short or tenant_short:
                if client_short and tenant_short:
                    client_wait = _compute_retry_after(
                        tokens_required=float(tokens),
                        available=client_tokens,
                        rate_per_second=client_budget.rate_per_second,
                    )
                    tenant_wait = _compute_retry_after(
                        tokens_required=float(tokens),
                        available=tenant_tokens,
                        rate_per_second=tenant_budget.rate_per_second,
                    )
                    if tenant_wait >= client_wait:
                        scope: Literal["client", "tenant"] = "tenant"
                        retry_after = tenant_wait
                    else:
                        scope = "client"
                        retry_after = client_wait
                elif client_short:
                    scope = "client"
                    retry_after = _compute_retry_after(
                        tokens_required=float(tokens),
                        available=client_tokens,
                        rate_per_second=client_budget.rate_per_second,
                    )
                else:
                    scope = "tenant"
                    retry_after = _compute_retry_after(
                        tokens_required=float(tokens),
                        available=tenant_tokens,
                        rate_per_second=tenant_budget.rate_per_second,
                    )
                self._client_state[client_id] = (client_tokens, client_ts)
                self._tenant_state[tenant_id] = (tenant_tokens, tenant_ts)
                raise RateLimitedDecision(
                    retry_after_seconds=retry_after,
                    deficit_scope=scope,
                    client_id=client_id,
                    tenant_id=tenant_id,
                )

            self._client_state[client_id] = (client_tokens - tokens, client_ts)
            self._tenant_state[tenant_id] = (tenant_tokens - tokens, tenant_ts)
            return BucketDecision(
                allowed=True,
                retry_after_seconds=0.0,
                deficit_scope="none",
                remaining_client=client_tokens - tokens,
                remaining_tenant=tenant_tokens - tokens,
            )

    async def aclose(self) -> None:
        return None


_REDIS_LUA_TOKEN_BUCKET: Final[str] = """
-- KEYS[1] = bucket key
-- ARGV[1] = capacity (burst)
-- ARGV[2] = rate_per_second
-- ARGV[3] = now (seconds, float)
-- ARGV[4] = tokens to consume
-- Returns: { allowed (0|1), tokens_left (string), retry_after (string) }
local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local needed = tonumber(ARGV[4])
local stored = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(stored[1])
local ts = tonumber(stored[2])
if tokens == nil then
  tokens = capacity
end
if ts == nil then
  ts = now
end
local elapsed = math.max(0, now - ts)
tokens = math.min(capacity, tokens + elapsed * rate)
local allowed = 0
local retry_after = 0
if tokens >= needed then
  tokens = tokens - needed
  allowed = 1
else
  retry_after = (needed - tokens) / rate
end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
local ttl = math.ceil(capacity / rate) + 1
redis.call('EXPIRE', KEYS[1], ttl)
return { allowed, tostring(tokens), tostring(retry_after) }
"""


class RedisTokenBucket:
    """Distributed token bucket backed by Redis + Lua.

    The Lua script (``_REDIS_LUA_TOKEN_BUCKET``) performs read-refill-decrement
    atomically inside Redis, so concurrent MCP servers cannot race past each
    other. Two scripts run sequentially per acquire — one per scope — but
    each script call is single-roundtrip thanks to ``EVALSHA`` caching.

    The Redis client is supplied by the caller (``redis.asyncio.Redis``)
    so we don't tie the runtime to a connection-management strategy.
    """

    backend_name = "redis"

    def __init__(
        self,
        *,
        client: _RedisLikeClient,
        default_client_budget: BucketBudget,
        default_tenant_budget: BucketBudget,
        per_client_budgets: Mapping[str, BucketBudget] | None = None,
        per_tenant_budgets: Mapping[str, BucketBudget] | None = None,
        key_prefix: str = "argus:mcp:rl",
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._client = client
        self._default_client_budget = default_client_budget
        self._default_tenant_budget = default_tenant_budget
        self._per_client_budgets = dict(per_client_budgets or {})
        self._per_tenant_budgets = dict(per_tenant_budgets or {})
        self._key_prefix = key_prefix
        self._clock = clock
        self._script_sha: str | None = None
        self._script_lock = asyncio.Lock()

    def _client_key(self, client_id: str) -> str:
        return f"{self._key_prefix}:client:{client_id}"

    def _tenant_key(self, tenant_id: str) -> str:
        return f"{self._key_prefix}:tenant:{tenant_id}"

    def get_client_budget(self, client_id: str) -> BucketBudget:
        return _budget_lookup(
            mapping=self._per_client_budgets,
            key=client_id,
            default=self._default_client_budget,
        )

    def get_tenant_budget(self, tenant_id: str) -> BucketBudget:
        return _budget_lookup(
            mapping=self._per_tenant_budgets,
            key=tenant_id,
            default=self._default_tenant_budget,
        )

    async def _ensure_script(self) -> str:
        if self._script_sha is not None:
            return self._script_sha
        async with self._script_lock:
            if self._script_sha is not None:
                return self._script_sha
            sha = await self._client.script_load(_REDIS_LUA_TOKEN_BUCKET)
            self._script_sha = sha if isinstance(sha, str) else sha.decode("utf-8")
            return self._script_sha

    async def _evaluate(
        self,
        *,
        key: str,
        budget: BucketBudget,
        tokens: int,
        now: float,
    ) -> tuple[bool, float, float]:
        sha = await self._ensure_script()
        result = await self._client.evalsha(
            sha,
            1,
            key,
            str(budget.burst),
            str(budget.rate_per_second),
            f"{now:.6f}",
            str(tokens),
        )
        allowed_raw, tokens_left_raw, retry_after_raw = result
        allowed = int(allowed_raw) == 1
        tokens_left = float(
            tokens_left_raw
            if isinstance(tokens_left_raw, (str, int, float))
            else tokens_left_raw.decode("utf-8")
        )
        retry_after = float(
            retry_after_raw
            if isinstance(retry_after_raw, (str, int, float))
            else retry_after_raw.decode("utf-8")
        )
        return allowed, tokens_left, retry_after

    async def acquire(
        self,
        *,
        client_id: str,
        tenant_id: str,
        tokens: int = 1,
    ) -> BucketDecision:
        if tokens <= 0:
            raise ValueError("tokens must be >= 1")

        client_budget = self.get_client_budget(client_id)
        tenant_budget = self.get_tenant_budget(tenant_id)
        now = self._clock()

        try:
            client_allowed, client_left, client_wait = await self._evaluate(
                key=self._client_key(client_id),
                budget=client_budget,
                tokens=tokens,
                now=now,
            )
        except Exception:
            _logger.warning(
                "mcp.rate_limiter.redis_unavailable",
                extra={"scope": "client", "client_id": client_id},
                exc_info=True,
            )
            client_allowed, client_left, client_wait = (
                True,
                float(client_budget.burst),
                0.0,
            )

        if not client_allowed:
            raise RateLimitedDecision(
                retry_after_seconds=client_wait,
                deficit_scope="client",
                client_id=client_id,
                tenant_id=tenant_id,
            )

        try:
            tenant_allowed, tenant_left, tenant_wait = await self._evaluate(
                key=self._tenant_key(tenant_id),
                budget=tenant_budget,
                tokens=tokens,
                now=now,
            )
        except Exception:
            _logger.warning(
                "mcp.rate_limiter.redis_unavailable",
                extra={"scope": "tenant", "tenant_id": tenant_id},
                exc_info=True,
            )
            tenant_allowed, tenant_left, tenant_wait = (
                True,
                float(tenant_budget.burst),
                0.0,
            )

        if not tenant_allowed:
            raise RateLimitedDecision(
                retry_after_seconds=tenant_wait,
                deficit_scope="tenant",
                client_id=client_id,
                tenant_id=tenant_id,
            )

        return BucketDecision(
            allowed=True,
            retry_after_seconds=0.0,
            deficit_scope="none",
            remaining_client=client_left,
            remaining_tenant=tenant_left,
        )

    async def aclose(self) -> None:
        close = getattr(self._client, "aclose", None)
        if callable(close):
            await close()


def build_rate_limiter(
    *,
    backend: str = "memory",
    default_client_budget: BucketBudget | None = None,
    default_tenant_budget: BucketBudget | None = None,
    per_client_budgets: Mapping[str, BucketBudget] | None = None,
    per_tenant_budgets: Mapping[str, BucketBudget] | None = None,
    redis_client: _RedisLikeClient | None = None,
    redis_key_prefix: str = "argus:mcp:rl",
) -> TokenBucketLimiter:
    """Factory used by :func:`src.mcp.server.build_app` (and tests).

    Defaults are deliberately permissive (5 rps, 30-token burst per client
    and per tenant) — operators tighten them via ``server.yaml``.
    """
    client_budget = default_client_budget or BucketBudget(
        rate_per_second=DEFAULT_BUCKET_RATE_PER_SECOND,
        burst=DEFAULT_BUCKET_BURST,
    )
    tenant_budget = default_tenant_budget or BucketBudget(
        rate_per_second=DEFAULT_BUCKET_RATE_PER_SECOND,
        burst=DEFAULT_BUCKET_BURST,
    )

    backend_normalised = backend.strip().lower()
    if backend_normalised == "memory":
        return InMemoryTokenBucket(
            default_client_budget=client_budget,
            default_tenant_budget=tenant_budget,
            per_client_budgets=per_client_budgets,
            per_tenant_budgets=per_tenant_budgets,
        )
    if backend_normalised == "redis":
        if redis_client is None:
            raise ValueError(
                "redis backend requires a redis_client (redis.asyncio.Redis)"
            )
        return RedisTokenBucket(
            client=redis_client,
            default_client_budget=client_budget,
            default_tenant_budget=tenant_budget,
            per_client_budgets=per_client_budgets,
            per_tenant_budgets=per_tenant_budgets,
            key_prefix=redis_key_prefix,
        )
    raise ValueError(
        f"unknown rate-limiter backend: {backend!r}; expected 'memory' or 'redis'"
    )


__all__ = [
    "DEFAULT_BUCKET_BURST",
    "DEFAULT_BUCKET_RATE_PER_SECOND",
    "JSONRPC_RATE_LIMIT_CODE",
    "BucketBudget",
    "BucketDecision",
    "InMemoryTokenBucket",
    "RateLimitedDecision",
    "RedisTokenBucket",
    "TokenBucketLimiter",
    "build_rate_limiter",
]
