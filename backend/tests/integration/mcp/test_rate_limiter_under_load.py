"""Integration tests for the MCP rate limiter (ARG-035).

Exercises :class:`InMemoryTokenBucket` end-to-end through the
:class:`TokenBucketLimiter` Protocol that the runtime sees, including:

* concurrency under hundreds of simultaneous requests,
* per-tenant fairness when one client floods,
* JSON-RPC error contract (``-32029`` + ``Retry-After``),
* dual-budget interaction (both client and tenant must allow the call).
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest

from src.mcp.runtime.rate_limiter import (
    JSONRPC_RATE_LIMIT_CODE,
    BucketBudget,
    InMemoryTokenBucket,
    RateLimitedDecision,
    build_rate_limiter,
)

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]


@pytest.fixture()
def time_source() -> Iterator[list[float]]:
    """Deterministic monotonic clock: tests advance ``ts[0]`` manually."""
    ts: list[float] = [1_000.0]
    yield ts


def _make_limiter(
    *,
    ts: list[float],
    client_rate: float = 5.0,
    client_burst: int = 10,
    tenant_rate: float = 50.0,
    tenant_burst: int = 100,
    per_client: dict[str, BucketBudget] | None = None,
    per_tenant: dict[str, BucketBudget] | None = None,
) -> InMemoryTokenBucket:
    return InMemoryTokenBucket(
        default_client_budget=BucketBudget(
            rate_per_second=client_rate, burst=client_burst
        ),
        default_tenant_budget=BucketBudget(
            rate_per_second=tenant_rate, burst=tenant_burst
        ),
        per_client_budgets=per_client,
        per_tenant_budgets=per_tenant,
        clock=lambda: ts[0],
    )


class TestConcurrentBurst:
    async def test_500_concurrent_requests_respect_burst(
        self, time_source: list[float]
    ) -> None:
        limiter = _make_limiter(ts=time_source, client_burst=10, tenant_burst=10_000)

        async def _try_acquire() -> bool:
            try:
                await limiter.acquire(client_id="solo", tenant_id="t1", tokens=1)
                return True
            except RateLimitedDecision:
                return False

        outcomes = await asyncio.gather(*[_try_acquire() for _ in range(500)])
        allowed = sum(1 for ok in outcomes if ok)
        assert allowed == 10, "burst should cap concurrent allowed at the client budget"

    async def test_per_tenant_burst_respected_under_concurrency(
        self, time_source: list[float]
    ) -> None:
        limiter = _make_limiter(
            ts=time_source,
            client_rate=1_000.0,
            client_burst=1_000,
            tenant_rate=20.0,
            tenant_burst=20,
        )

        async def _try_acquire(client_id: str) -> bool:
            try:
                await limiter.acquire(client_id=client_id, tenant_id="t1", tokens=1)
                return True
            except RateLimitedDecision:
                return False

        coros = [_try_acquire(f"c{i % 50}") for i in range(500)]
        outcomes = await asyncio.gather(*coros)
        allowed = sum(1 for ok in outcomes if ok)
        assert allowed == 20, (
            "tenant burst should cap concurrent allowed across clients"
        )


class TestRefillProgression:
    async def test_burst_then_refill_then_pass(self, time_source: list[float]) -> None:
        limiter = _make_limiter(ts=time_source, client_burst=2, client_rate=2.0)
        await limiter.acquire(client_id="c1", tenant_id="t1")
        await limiter.acquire(client_id="c1", tenant_id="t1")
        with pytest.raises(RateLimitedDecision):
            await limiter.acquire(client_id="c1", tenant_id="t1")
        time_source[0] += 1.0
        decision = await limiter.acquire(client_id="c1", tenant_id="t1")
        assert decision.allowed
        decision_2 = await limiter.acquire(client_id="c1", tenant_id="t1")
        assert decision_2.allowed
        with pytest.raises(RateLimitedDecision):
            await limiter.acquire(client_id="c1", tenant_id="t1")

    async def test_retry_after_decreases_with_time(
        self, time_source: list[float]
    ) -> None:
        limiter = _make_limiter(ts=time_source, client_burst=2, client_rate=1.0)
        await limiter.acquire(client_id="c1", tenant_id="t1")
        await limiter.acquire(client_id="c1", tenant_id="t1")
        with pytest.raises(RateLimitedDecision) as first:
            await limiter.acquire(client_id="c1", tenant_id="t1")
        time_source[0] += 0.5
        with pytest.raises(RateLimitedDecision) as second:
            await limiter.acquire(client_id="c1", tenant_id="t1")
        assert second.value.retry_after_seconds < first.value.retry_after_seconds


class TestJsonRpcContract:
    async def test_decision_payload_matches_jsonrpc_contract(
        self, time_source: list[float]
    ) -> None:
        limiter = _make_limiter(ts=time_source, client_burst=1, client_rate=1.0)
        await limiter.acquire(client_id="c1", tenant_id="t1")
        with pytest.raises(RateLimitedDecision) as info:
            await limiter.acquire(client_id="c1", tenant_id="t1")
        payload = info.value.jsonrpc_error_payload()
        assert payload["code"] == JSONRPC_RATE_LIMIT_CODE
        assert "retry_after" in payload["data"]
        assert payload["data"]["scope"] == "client"
        assert isinstance(payload["data"]["retry_after"], float)
        assert payload["data"]["retry_after"] > 0

    async def test_tenant_deficit_reports_tenant_scope(
        self, time_source: list[float]
    ) -> None:
        limiter = _make_limiter(
            ts=time_source,
            client_rate=1_000.0,
            client_burst=1_000,
            tenant_rate=1.0,
            tenant_burst=1,
        )
        await limiter.acquire(client_id="c1", tenant_id="t1")
        with pytest.raises(RateLimitedDecision) as info:
            await limiter.acquire(client_id="c2", tenant_id="t1")
        payload = info.value.jsonrpc_error_payload()
        assert payload["data"]["scope"] == "tenant"


class TestPerClientOverride:
    async def test_explicit_override_takes_priority_over_default(
        self, time_source: list[float]
    ) -> None:
        limiter = _make_limiter(
            ts=time_source,
            tenant_burst=10_000,
            tenant_rate=10_000,
            per_client={"vip": BucketBudget(rate_per_second=10.0, burst=100)},
        )
        for _ in range(100):
            await limiter.acquire(client_id="vip", tenant_id="t1")
        with pytest.raises(RateLimitedDecision) as info:
            await limiter.acquire(client_id="vip", tenant_id="t1")
        assert info.value.deficit_scope == "client"


class TestFactory:
    async def test_build_in_memory_default(self) -> None:
        limiter = build_rate_limiter(backend="memory")
        decision = await limiter.acquire(client_id="c1", tenant_id="t1")
        assert decision.allowed

    async def test_build_unknown_backend_raises(self) -> None:
        with pytest.raises(ValueError):
            build_rate_limiter(backend="cassandra")

    async def test_build_redis_without_client_raises(self) -> None:
        with pytest.raises(ValueError):
            build_rate_limiter(backend="redis")
