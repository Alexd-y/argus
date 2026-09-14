"""Real-Postgres reserve-before-call tests for the provider guard (§8.3).

Marked ``requires_postgres`` — needs a live PostgreSQL. Run, e.g.:

    $env:ARGUS_TEST_PG_DSN = "postgresql+asyncpg://argus:argus_test@localhost:55440/argus_test"
    pytest tests/integration/budget/test_facade_reserve_before_call_pg.py -m requires_postgres -p no:cacheprovider

Verifies that with a Postgres-backed ledger registered for the scan the
:func:`src.llm.provider_guard.provider_guard` context manager:
* denies a call that would exceed the scan cap (reserve BEFORE spend);
* settles provider-metadata usage on success;
* leaves an ``uncertain`` reservation after a post-send failure.
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from src.core.config import settings
from src.llm.provider_guard import CallScope, provider_guard, reset_call_scope, set_call_scope
from src.orchestration.agent_contracts import AgentUsage
from src.orchestration.budget_ledger import BudgetDeniedError, BudgetLedger
from src.orchestration.budget_ledger_pg import PostgresBudgetStore, create_budget_tables
from src.orchestration.budget_scan_registry import register_scan_ledger, unregister_scan_ledger

pytestmark = pytest.mark.requires_postgres

_DSN = os.environ.get("ARGUS_TEST_PG_DSN")


@pytest.fixture(scope="module", autouse=True)
def _require_dsn():
    if not _DSN:
        pytest.skip("ARGUS_TEST_PG_DSN not set — live Postgres required")


@pytest.fixture
async def _pg(monkeypatch):
    monkeypatch.setattr(settings, "budget_ledger_enabled", True)
    monkeypatch.setattr(settings, "lease_enabled", False)
    engine = create_async_engine(_DSN, pool_pre_ping=True)
    await create_budget_tables(engine)
    sf = async_sessionmaker(engine, expire_on_commit=False)
    store = PostgresBudgetStore(sf)
    scan_id = f"scan-{uuid.uuid4().hex[:10]}"
    register_scan_ledger(scan_id, BudgetLedger(store))
    try:
        yield store, scan_id
    finally:
        unregister_scan_ledger(scan_id)
        await engine.dispose()


def _scope(scan_id: str, est_tokens: int):
    return CallScope(tenant_id="t1", scan_id=scan_id, est_tokens=est_tokens, est_cost_usd=0.0)


async def test_settle_books_actual_usage(_pg):
    store, scan_id = _pg
    await store.set_limits(f"scan:{scan_id}", max_tokens=1000)
    token = set_call_scope(_scope(scan_id, est_tokens=200))
    try:
        async with provider_guard("wrb") as run:
            run.record_usage(AgentUsage(input_tokens=40, output_tokens=25, estimated=False))
    finally:
        reset_call_scope(token)
    snap = await store.snapshot(f"scan:{scan_id}")
    assert snap.used_tokens == 65
    assert snap.reserved_tokens == 0


async def test_reserve_denies_over_cap_before_call(_pg):
    store, scan_id = _pg
    await store.set_limits(f"scan:{scan_id}", max_tokens=50)
    token = set_call_scope(_scope(scan_id, est_tokens=200))
    entered = False
    try:
        with pytest.raises(BudgetDeniedError):
            async with provider_guard("wrb"):
                entered = True
    finally:
        reset_call_scope(token)
    assert entered is False
    snap = await store.snapshot(f"scan:{scan_id}")
    assert snap.used_tokens == 0
    assert snap.reserved_tokens == 0


async def test_post_send_failure_leaves_uncertain(_pg):
    store, scan_id = _pg
    await store.set_limits(f"scan:{scan_id}", max_tokens=1000)
    token = set_call_scope(_scope(scan_id, est_tokens=150))
    try:
        with pytest.raises(RuntimeError):
            async with provider_guard("wrb"):
                raise RuntimeError("provider dropped after send")
    finally:
        reset_call_scope(token)
    # Uncertain: the reservation is held (reserved, not settled or released) so a
    # reconciler can later resolve it against provider metadata — never silently
    # freed as if the call were free.
    snap = await store.snapshot(f"scan:{scan_id}")
    assert snap.reserved_tokens == 150
    assert snap.used_tokens == 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v", "-m", "requires_postgres"]))
