"""Real-Postgres atomicity tests for the budget ledger (§7 / §14.D).

Marked ``requires_postgres`` — needs a live PostgreSQL. Run against the dev
stack, e.g.:

    $env:ARGUS_TEST_PG_DSN = "postgresql+asyncpg://argus:argus_test@localhost:55440/argus_test"
    pytest tests/integration/budget/test_budget_ledger_pg.py -m requires_postgres -p no:cacheprovider

Two *independent* engines/session factories model two competing workers; row
locks (``SELECT … FOR UPDATE``) — not a shared Python object — provide atomicity.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from src.orchestration.agent_contracts import AgentUsage
from src.orchestration.budget_ledger import (
    BudgetLedger,
    BudgetScope,
    ReservationState,
)
from src.orchestration.budget_ledger_pg import (
    PostgresBudgetStore,
    create_budget_tables,
)

pytestmark = pytest.mark.requires_postgres

_DSN = os.environ.get("ARGUS_TEST_PG_DSN")


def _new_engine():
    return create_async_engine(_DSN, pool_pre_ping=True)


async def _tables_ready(engine) -> None:
    await create_budget_tables(engine)


@pytest.fixture(scope="module", autouse=True)
def _require_dsn():
    if not _DSN:
        pytest.skip("ARGUS_TEST_PG_DSN not set — live Postgres required")


async def test_tables_created_once():
    engine = _new_engine()
    try:
        await _tables_ready(engine)
    finally:
        await engine.dispose()


async def test_two_workers_cannot_over_reserve():
    scan = f"scan-{uuid.uuid4().hex[:8]}"
    e1, e2 = _new_engine(), _new_engine()
    try:
        await _tables_ready(e1)
        sf1 = async_sessionmaker(e1, expire_on_commit=False)
        sf2 = async_sessionmaker(e2, expire_on_commit=False)
        store1, store2 = PostgresBudgetStore(sf1), PostgresBudgetStore(sf2)
        led1, led2 = BudgetLedger(store1), BudgetLedger(store2)
        await store1.set_limits(f"scan:{scan}", max_tokens=250)

        async def _try(led):
            res = await led._store.try_reserve(BudgetScope(scan_id=scan), 100, 0.0, 300)
            return res is not None

        # Six competing reservations across two workers; only two fit in 250.
        results = await asyncio.gather(
            *[_try(led1) for _ in range(3)], *[_try(led2) for _ in range(3)]
        )
        assert sum(results) == 2
        snap = await store1.snapshot(f"scan:{scan}")
        assert snap.reserved_tokens == 200
        assert snap.reserved_tokens <= snap.limit_tokens
    finally:
        await e1.dispose()
        await e2.dispose()


async def test_settle_idempotent_across_connections():
    scan = f"scan-{uuid.uuid4().hex[:8]}"
    e1, e2 = _new_engine(), _new_engine()
    try:
        await _tables_ready(e1)
        sf1 = async_sessionmaker(e1, expire_on_commit=False)
        sf2 = async_sessionmaker(e2, expire_on_commit=False)
        store1, store2 = PostgresBudgetStore(sf1), PostgresBudgetStore(sf2)
        await store1.set_limits(f"scan:{scan}", max_tokens=10000)
        res = await store1.try_reserve(BudgetScope(scan_id=scan), 100, 0.0, 300)
        assert res is not None
        usage = AgentUsage(input_tokens=40, output_tokens=60)
        # Two different connections both try to settle the same reservation.
        r1, r2 = await asyncio.gather(
            store1.settle(res.reservation_id, usage),
            store2.settle(res.reservation_id, usage),
        )
        assert {r1, r2} == {True, False}  # exactly one booking wins
        snap = await store1.snapshot(f"scan:{scan}")
        assert snap.used_tokens == 100
        assert snap.reserved_tokens == 0
    finally:
        await e1.dispose()
        await e2.dispose()


async def test_usage_durable_across_reconnect():
    scan = f"scan-{uuid.uuid4().hex[:8]}"
    e1 = _new_engine()
    try:
        await _tables_ready(e1)
        sf1 = async_sessionmaker(e1, expire_on_commit=False)
        store1 = PostgresBudgetStore(sf1)
        await store1.set_limits(f"scan:{scan}", max_tokens=10000)
        res = await store1.try_reserve(BudgetScope(scan_id=scan), 100, 0.0, 300)
        await store1.settle(res.reservation_id, AgentUsage(input_tokens=70, output_tokens=30))
    finally:
        await e1.dispose()

    # Fresh engine == "restart": budget state must survive, not reset.
    e2 = _new_engine()
    try:
        sf2 = async_sessionmaker(e2, expire_on_commit=False)
        store2 = PostgresBudgetStore(sf2)
        snap = await store2.snapshot(f"scan:{scan}")
        assert snap.used_tokens == 100
    finally:
        await e2.dispose()


async def test_stuck_reservation_recovered():
    scan = f"scan-{uuid.uuid4().hex[:8]}"
    e1 = _new_engine()
    try:
        await _tables_ready(e1)
        sf1 = async_sessionmaker(e1, expire_on_commit=False)
        store1 = PostgresBudgetStore(sf1)
        await store1.set_limits(f"scan:{scan}", max_tokens=500)
        res = await store1.try_reserve(BudgetScope(scan_id=scan), 300, 0.0, 0)
        recovered = await store1.reconcile_stale(ttl_seconds=0)
        assert res.reservation_id in {r.reservation_id for r in recovered}
        snap = await store1.snapshot(f"scan:{scan}")
        assert snap.reserved_tokens == 0
        assert any(
            r.reservation_id == res.reservation_id and r.state == ReservationState.RELEASED
            for r in recovered
        )
    finally:
        await e1.dispose()


async def test_multi_scope_tenant_limit_binds():
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    task = f"tk-{uuid.uuid4().hex[:8]}"
    e1 = _new_engine()
    try:
        await _tables_ready(e1)
        sf1 = async_sessionmaker(e1, expire_on_commit=False)
        store1 = PostgresBudgetStore(sf1)
        await store1.set_limits(f"tenant:{tenant}", max_tokens=150)
        scope = BudgetScope(tenant_id=tenant, task_id=task)
        assert await store1.try_reserve(scope, 100, 0.0, 300) is not None
        # Tenant cap (150) blocks the second even though the task is fresh.
        assert await store1.try_reserve(scope, 100, 0.0, 300) is None
    finally:
        await e1.dispose()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v", "-m", "requires_postgres"]))
