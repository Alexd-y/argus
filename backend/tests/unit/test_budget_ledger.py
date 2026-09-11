"""Offline tests for the authoritative budget ledger (§7 / §14.D).

Cross-worker atomicity is exercised here with two independent async clients
sharing one store (the store's lock models a DB transaction). True durability
across a process restart is a DB-store concern and is listed as unverified
offline — it is NOT asserted here.
"""

from __future__ import annotations

import asyncio

import pytest
from src.orchestration.agent_contracts import AgentUsage
from src.orchestration.budget_ledger import (
    BudgetDeniedError,
    BudgetLedger,
    BudgetScope,
    BudgetUnavailableError,
    InMemoryBudgetStore,
    ReservationState,
)


async def _make_ledger(**limits) -> tuple[BudgetLedger, InMemoryBudgetStore]:
    store = InMemoryBudgetStore()
    for key, (tokens, cost) in limits.items():
        await store.set_limits(key, max_tokens=tokens, max_cost_usd=cost)
    return BudgetLedger(store), store


async def test_two_clients_cannot_over_reserve_shared_budget():
    ledger, store = await _make_ledger(**{"scan:s1": (250, None)})

    async def _client() -> bool:
        try:
            await ledger.reserve(BudgetScope(scan_id="s1"), tokens=100)
            return True
        except BudgetDeniedError:
            return False

    results = await asyncio.gather(*[_client() for _ in range(5)])
    # 250 // 100 -> exactly two reservations fit; the rest are denied.
    assert sum(results) == 2
    snap = await store.snapshot("scan:s1")
    assert snap.reserved_tokens == 200
    assert snap.reserved_tokens <= snap.limit_tokens


async def test_settle_is_idempotent_no_double_charge():
    ledger, store = await _make_ledger(**{"scan:s1": (1000, None)})
    res = await ledger.reserve(BudgetScope(scan_id="s1"), tokens=100)
    usage = AgentUsage(input_tokens=40, output_tokens=60)
    assert await ledger.settle(res, usage) is True
    # Second settle must be a no-op.
    assert await ledger.settle(res, usage) is False
    snap = await store.snapshot("scan:s1")
    assert snap.used_tokens == 100
    assert snap.reserved_tokens == 0


async def test_retries_are_counted_separately():
    ledger, store = await _make_ledger(**{"task:tk": (10000, None)})
    r1 = await ledger.reserve(BudgetScope(task_id="tk"), tokens=100)
    await ledger.settle(r1, AgentUsage(input_tokens=50, output_tokens=50))
    r2 = await ledger.reserve(BudgetScope(task_id="tk"), tokens=100)
    await ledger.settle(r2, AgentUsage(input_tokens=60, output_tokens=60))
    snap = await store.snapshot("task:tk")
    assert snap.used_tokens == 220


async def test_uncertain_reservation_not_freed():
    ledger, store = await _make_ledger(**{"scan:s1": (500, None)})
    res = await ledger.reserve(BudgetScope(scan_id="s1"), tokens=300)
    # Provider may have run; usage unknown -> keep the hold, don't free as $0.
    assert await ledger.mark_uncertain(res) is True
    snap = await store.snapshot("scan:s1")
    assert snap.reserved_tokens == 300  # still held
    assert snap.available_tokens == 200
    # A settle can still resolve it later.
    assert await ledger.settle(res, AgentUsage(input_tokens=150, output_tokens=150)) is True


async def test_release_only_when_not_started():
    ledger, store = await _make_ledger(**{"scan:s1": (500, None)})
    res = await ledger.reserve(BudgetScope(scan_id="s1"), tokens=100)
    assert await ledger.release(res) is True
    snap = await store.snapshot("scan:s1")
    assert snap.reserved_tokens == 0
    assert snap.used_tokens == 0
    # Releasing again (already released) is a no-op, and settle after release fails.
    assert await ledger.release(res) is False
    assert await ledger.settle(res, AgentUsage(input_tokens=1, output_tokens=1)) is False


async def test_multi_scope_limits_enforced_simultaneously():
    # Task limit is generous but the tenant limit is the binding constraint.
    ledger, store = await _make_ledger(
        **{"tenant:t1": (150, None), "task:tk": (100000, None)}
    )
    scope = BudgetScope(tenant_id="t1", task_id="tk")
    await ledger.reserve(scope, tokens=100)
    with pytest.raises(BudgetDeniedError):
        await ledger.reserve(scope, tokens=100)  # tenant cap (150) blocks it


async def test_available_never_negative_even_if_provider_overshoots():
    ledger, store = await _make_ledger(**{"scan:s1": (100, None)})
    res = await ledger.reserve(BudgetScope(scan_id="s1"), tokens=100)
    # Provider reports more than reserved (real overshoot). We book actual usage;
    # available floors at zero rather than going negative.
    await ledger.settle(res, AgentUsage(input_tokens=200, output_tokens=50))
    snap = await store.snapshot("scan:s1")
    assert snap.used_tokens == 250
    assert snap.available_tokens == 0.0


async def test_stuck_reservation_recovered_by_reconcile():
    ledger, store = await _make_ledger(**{"scan:s1": (500, None)})
    # Lease of 0s -> immediately eligible for stale reconciliation.
    res = await ledger.reserve(BudgetScope(scan_id="s1"), tokens=300, lease_seconds=0)
    recovered = await ledger.reconcile_stale(ttl_seconds=0)
    assert res.reservation_id in {r.reservation_id for r in recovered}
    snap = await store.snapshot("scan:s1")
    assert snap.reserved_tokens == 0  # hung hold recovered
    assert res.state == ReservationState.RELEASED


async def test_uncertain_surfaced_but_not_auto_freed_by_reconcile():
    ledger, store = await _make_ledger(**{"scan:s1": (500, None)})
    res = await ledger.reserve(BudgetScope(scan_id="s1"), tokens=300, lease_seconds=0)
    await ledger.mark_uncertain(res)
    recovered = await ledger.reconcile_stale(ttl_seconds=0)
    assert res.reservation_id in {r.reservation_id for r in recovered}
    snap = await store.snapshot("scan:s1")
    # UNCERTAIN holds are surfaced for reconciliation, NOT auto-released.
    assert snap.reserved_tokens == 300


async def test_no_store_denies_new_paid_calls():
    ledger = BudgetLedger(store=None)
    assert ledger.available is False
    with pytest.raises(BudgetUnavailableError):
        await ledger.reserve(BudgetScope(scan_id="s1"), tokens=1)


async def test_cost_limit_enforced_independently_of_tokens():
    ledger, store = await _make_ledger(**{"scan:s1": (1_000_000, 0.10)})
    await ledger.reserve(BudgetScope(scan_id="s1"), tokens=10, est_cost_usd=0.08)
    with pytest.raises(BudgetDeniedError):
        await ledger.reserve(BudgetScope(scan_id="s1"), tokens=10, est_cost_usd=0.05)


async def test_budgeted_cm_settles_on_recorded_usage():
    ledger, store = await _make_ledger(**{"scan:s1": (1000, None)})
    async with ledger.budgeted(BudgetScope(scan_id="s1"), tokens=100) as run:
        run.mark_started()
        run.record_usage(AgentUsage(input_tokens=30, output_tokens=30))
    snap = await store.snapshot("scan:s1")
    assert snap.used_tokens == 60
    assert snap.reserved_tokens == 0


async def test_budgeted_cm_releases_when_never_started():
    ledger, store = await _make_ledger(**{"scan:s1": (1000, None)})
    async with ledger.budgeted(BudgetScope(scan_id="s1"), tokens=100):
        pass  # nothing ran
    snap = await store.snapshot("scan:s1")
    assert snap.reserved_tokens == 0
    assert snap.used_tokens == 0


async def test_budgeted_cm_marks_uncertain_when_started_without_usage():
    ledger, store = await _make_ledger(**{"scan:s1": (1000, None)})
    with pytest.raises(RuntimeError):
        async with ledger.budgeted(BudgetScope(scan_id="s1"), tokens=100) as run:
            run.mark_started()  # provider call may have hit the wire
            raise RuntimeError("timeout after send")
    snap = await store.snapshot("scan:s1")
    # Held (uncertain), NOT freed as if it were free.
    assert snap.reserved_tokens == 100


def test_migration_064_matches_budget_metadata():
    """Drift guard: the Alembic migration must define the same tables/columns."""
    import pathlib

    from src.orchestration.budget_ledger_pg import budget_metadata

    migration = (
        pathlib.Path(__file__).parents[2] / "alembic" / "versions" / "064_agent_budget.py"
    ).read_text(encoding="utf-8")
    for table in budget_metadata.tables.values():
        assert table.name in migration, f"table {table.name} missing from migration"
        for col in table.columns:
            assert col.name in migration, f"column {table.name}.{col.name} missing"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
