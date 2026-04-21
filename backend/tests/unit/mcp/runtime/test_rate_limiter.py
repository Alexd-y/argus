"""Unit tests for :mod:`src.mcp.runtime.rate_limiter` (ARG-035).

Twenty-plus cases covering:

* :class:`BucketBudget` validation guards (rate / burst sanity).
* :class:`InMemoryTokenBucket` token math: refill, burst clamp, mixed
  client / tenant deficits, retry-after correctness.
* Per-client and per-tenant isolation (two clients in the same tenant,
  two tenants for the same client).
* Race-conditions: 50 concurrent acquires resolve consistently with the
  serialised expectation.
* :class:`RedisTokenBucket` end-to-end behaviour against a small Lua
  evaluator stub (we don't bring up a real Redis — the goal is to assert
  the wire shape and that the Lua return-value parser is correct).
* :func:`build_rate_limiter` factory selection / error paths.
* :class:`RateLimitedDecision` JSON-RPC payload contract (code -32029
  + retry_after).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest

from src.mcp.exceptions import RateLimitedError
from src.mcp.runtime.rate_limiter import (
    JSONRPC_RATE_LIMIT_CODE,
    BucketBudget,
    BucketDecision,
    InMemoryTokenBucket,
    RateLimitedDecision,
    RedisTokenBucket,
    build_rate_limiter,
)


def _budget(rate: float = 5.0, burst: int = 10) -> BucketBudget:
    return BucketBudget(rate_per_second=rate, burst=burst)


class _FrozenClock:
    def __init__(self, t0: float = 0.0) -> None:
        self.t = t0

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


# ---------------------------------------------------------------------------
# BucketBudget validation
# ---------------------------------------------------------------------------


class TestBucketBudget:
    def test_rate_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="rate_per_second"):
            BucketBudget(rate_per_second=0, burst=5)

    def test_burst_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="burst must be >= 1"):
            BucketBudget(rate_per_second=5.0, burst=0)

    def test_burst_must_cover_one_second_of_rate(self) -> None:
        with pytest.raises(ValueError, match="burst must be >= rate_per_second"):
            BucketBudget(rate_per_second=10.0, burst=5)

    def test_valid_budget_round_trips(self) -> None:
        b = BucketBudget(rate_per_second=2.5, burst=20)
        assert b.rate_per_second == 2.5
        assert b.burst == 20


# ---------------------------------------------------------------------------
# InMemoryTokenBucket
# ---------------------------------------------------------------------------


class TestInMemoryTokenBucket:
    def _make(
        self,
        *,
        client_budget: BucketBudget | None = None,
        tenant_budget: BucketBudget | None = None,
        per_client: dict[str, BucketBudget] | None = None,
        per_tenant: dict[str, BucketBudget] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> InMemoryTokenBucket:
        return InMemoryTokenBucket(
            default_client_budget=client_budget or _budget(rate=5.0, burst=10),
            default_tenant_budget=tenant_budget or _budget(rate=5.0, burst=10),
            per_client_budgets=per_client,
            per_tenant_budgets=per_tenant,
            clock=clock or _FrozenClock(0.0),
        )

    def test_first_acquire_succeeds(self) -> None:
        bucket = self._make()
        decision = asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        assert decision.allowed
        assert decision.deficit_scope == "none"
        assert decision.remaining_client == pytest.approx(9.0)
        assert decision.remaining_tenant == pytest.approx(9.0)

    def test_burst_drains_then_rejects(self) -> None:
        bucket = self._make()
        for _ in range(10):
            asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        with pytest.raises(RateLimitedDecision) as ei:
            asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        assert ei.value.deficit_scope in {"client", "tenant"}
        assert ei.value.retry_after_seconds == pytest.approx(1 / 5.0, abs=1e-6)

    def test_refill_after_clock_advances(self) -> None:
        clock = _FrozenClock(0.0)
        bucket = self._make(clock=clock)
        for _ in range(10):
            asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        with pytest.raises(RateLimitedDecision):
            asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        clock.advance(1.0)
        decision = asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        assert decision.allowed

    def test_refill_clamps_at_burst(self) -> None:
        clock = _FrozenClock(0.0)
        bucket = self._make(clock=clock)
        asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        clock.advance(10_000)
        decision = asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        assert decision.remaining_client <= 9.0
        assert decision.remaining_client >= 8.999

    def test_per_client_isolation(self) -> None:
        bucket = self._make(
            client_budget=_budget(rate=5.0, burst=10),
            tenant_budget=_budget(rate=100.0, burst=200),
        )
        for _ in range(10):
            asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        decision = asyncio.run(bucket.acquire(client_id="c2", tenant_id="t1", tokens=1))
        assert decision.allowed

    def test_per_tenant_overlap_visible(self) -> None:
        bucket = self._make()
        for _ in range(10):
            asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        with pytest.raises(RateLimitedDecision) as ei:
            asyncio.run(bucket.acquire(client_id="c2", tenant_id="t1", tokens=1))
        assert ei.value.deficit_scope == "tenant"

    def test_per_tenant_isolation(self) -> None:
        bucket = self._make(
            client_budget=_budget(rate=100.0, burst=200),
            tenant_budget=_budget(rate=5.0, burst=10),
        )
        for _ in range(10):
            asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        decision = asyncio.run(bucket.acquire(client_id="c1", tenant_id="t2", tokens=1))
        assert decision.allowed

    def test_tokens_must_be_positive(self) -> None:
        bucket = self._make()
        with pytest.raises(ValueError):
            asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=0))

    def test_per_client_override_takes_priority(self) -> None:
        bucket = self._make(
            client_budget=_budget(rate=5.0, burst=10),
            tenant_budget=_budget(rate=200.0, burst=500),
            per_client={"vip": _budget(rate=100.0, burst=200)},
        )
        for _ in range(50):
            asyncio.run(bucket.acquire(client_id="vip", tenant_id="t1", tokens=1))
        assert bucket.get_client_budget("vip").burst == 200
        assert bucket.get_client_budget("normal").burst == 10

    def test_per_tenant_override_takes_priority(self) -> None:
        bucket = self._make(
            per_tenant={"premium": _budget(rate=50.0, burst=100)},
        )
        assert bucket.get_tenant_budget("premium").burst == 100
        assert bucket.get_tenant_budget("free").burst == 10

    def test_retry_after_chooses_tenant_when_both_short(self) -> None:
        clock = _FrozenClock(0.0)
        bucket = InMemoryTokenBucket(
            default_client_budget=_budget(rate=10.0, burst=10),
            default_tenant_budget=_budget(rate=2.0, burst=10),
            clock=clock,
        )
        for _ in range(10):
            asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        with pytest.raises(RateLimitedDecision) as ei:
            asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        assert ei.value.deficit_scope == "tenant"
        assert ei.value.retry_after_seconds == pytest.approx(0.5, abs=1e-3)

    def test_retry_after_chooses_client_when_both_short(self) -> None:
        clock = _FrozenClock(0.0)
        bucket = InMemoryTokenBucket(
            default_client_budget=_budget(rate=2.0, burst=10),
            default_tenant_budget=_budget(rate=10.0, burst=10),
            clock=clock,
        )
        for _ in range(10):
            asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        with pytest.raises(RateLimitedDecision) as ei:
            asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        assert ei.value.deficit_scope == "client"
        assert ei.value.retry_after_seconds == pytest.approx(0.5, abs=1e-3)

    def test_concurrent_acquires_serialise_correctly(self) -> None:
        clock = _FrozenClock(0.0)
        bucket = self._make(clock=clock)

        async def runner() -> int:
            successes = 0
            results = await asyncio.gather(
                *(
                    bucket.acquire(client_id="c1", tenant_id="t1", tokens=1)
                    for _ in range(50)
                ),
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, BucketDecision) and r.allowed:
                    successes += 1
            return successes

        successes = asyncio.run(runner())
        assert successes == 10

    def test_aclose_is_noop(self) -> None:
        bucket = self._make()
        asyncio.run(bucket.aclose())


class TestRateLimitedDecisionContract:
    def test_inherits_rate_limited_error(self) -> None:
        exc = RateLimitedDecision(
            retry_after_seconds=1.5,
            deficit_scope="client",
            client_id="c1",
            tenant_id="t1",
        )
        assert isinstance(exc, RateLimitedError)
        assert exc.code == "mcp_rate_limited"
        assert exc.http_status == 429

    def test_payload_contract(self) -> None:
        exc = RateLimitedDecision(
            retry_after_seconds=2.345,
            deficit_scope="tenant",
            client_id="c1",
            tenant_id="t1",
        )
        payload = exc.jsonrpc_error_payload()
        assert payload["code"] == JSONRPC_RATE_LIMIT_CODE == -32029
        assert payload["message"].startswith("Rate limit exceeded")
        data = payload["data"]
        assert isinstance(data, dict)
        assert data["scope"] == "tenant"
        assert data["retry_after"] == pytest.approx(2.345, abs=1e-3)

    def test_negative_retry_after_clamped(self) -> None:
        exc = RateLimitedDecision(
            retry_after_seconds=-1.0,
            deficit_scope="client",
            client_id="c1",
            tenant_id="t1",
        )
        assert exc.retry_after_seconds == 0.0


# ---------------------------------------------------------------------------
# build_rate_limiter
# ---------------------------------------------------------------------------


class TestBuildRateLimiter:
    def test_default_backend_is_memory(self) -> None:
        limiter = build_rate_limiter()
        assert isinstance(limiter, InMemoryTokenBucket)

    def test_memory_backend_accepts_overrides(self) -> None:
        limiter = build_rate_limiter(
            backend="memory",
            default_client_budget=_budget(rate=2.0, burst=10),
        )
        assert isinstance(limiter, InMemoryTokenBucket)
        assert limiter.get_client_budget("any").rate_per_second == 2.0

    def test_redis_requires_client(self) -> None:
        with pytest.raises(ValueError, match="redis backend requires"):
            build_rate_limiter(backend="redis")

    def test_unknown_backend_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown rate-limiter backend"):
            build_rate_limiter(backend="dynamodb")


# ---------------------------------------------------------------------------
# RedisTokenBucket — script wire shape
# ---------------------------------------------------------------------------


class _FakeRedis:
    """Tiny stub that records script_load + evalsha calls.

    We don't replicate Redis semantics — the unit test just asserts the
    adapter calls EVALSHA with the right argv shape and decodes the
    response correctly.
    """

    def __init__(self, response: tuple[int, str, str]) -> None:
        self.script_load_calls: list[str] = []
        self.evalsha_calls: list[tuple[Any, ...]] = []
        self._response = response

    async def script_load(self, script: str) -> str:
        self.script_load_calls.append(script)
        return "fakesha"

    async def evalsha(self, sha: str, *args: Any) -> tuple[int, str, str]:
        self.evalsha_calls.append((sha, *args))
        return self._response


class TestRedisTokenBucket:
    def test_script_load_caches_sha(self) -> None:
        fake = _FakeRedis(response=(1, "9", "0"))
        bucket = RedisTokenBucket(
            client=fake,
            default_client_budget=_budget(rate=5.0, burst=10),
            default_tenant_budget=_budget(rate=5.0, burst=10),
        )
        asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        assert len(fake.script_load_calls) == 1

    def test_evalsha_called_per_scope(self) -> None:
        fake = _FakeRedis(response=(1, "9", "0"))
        bucket = RedisTokenBucket(
            client=fake,
            default_client_budget=_budget(rate=5.0, burst=10),
            default_tenant_budget=_budget(rate=5.0, burst=10),
        )
        asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        assert len(fake.evalsha_calls) == 2
        first, second = fake.evalsha_calls
        assert first[0] == "fakesha"
        assert "client" in first[2]
        assert "tenant" in second[2]

    def test_redis_rejection_raises_rate_limited(self) -> None:
        fake = _FakeRedis(response=(0, "0", "1.5"))
        bucket = RedisTokenBucket(
            client=fake,
            default_client_budget=_budget(rate=5.0, burst=10),
            default_tenant_budget=_budget(rate=5.0, burst=10),
        )
        with pytest.raises(RateLimitedDecision) as ei:
            asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        assert ei.value.deficit_scope == "client"
        assert ei.value.retry_after_seconds == pytest.approx(1.5, abs=1e-3)

    def test_redis_outage_fails_open(self) -> None:
        class _Boom:
            async def script_load(self, script: str) -> str:
                raise RuntimeError("redis down")

            async def evalsha(self, *_args: Any, **_kwargs: Any) -> tuple[Any, ...]:
                raise RuntimeError("redis down")

        bucket = RedisTokenBucket(
            client=_Boom(),
            default_client_budget=_budget(rate=5.0, burst=10),
            default_tenant_budget=_budget(rate=5.0, burst=10),
        )
        decision = asyncio.run(bucket.acquire(client_id="c1", tenant_id="t1", tokens=1))
        assert decision.allowed
        assert decision.deficit_scope == "none"

    def test_aclose_calls_underlying_aclose(self) -> None:
        called = {"hit": False}

        class _R:
            async def aclose(self) -> None:
                called["hit"] = True

        bucket = RedisTokenBucket(
            client=_R(),
            default_client_budget=_budget(rate=5.0, burst=10),
            default_tenant_budget=_budget(rate=5.0, burst=10),
        )
        asyncio.run(bucket.aclose())
        assert called["hit"] is True
