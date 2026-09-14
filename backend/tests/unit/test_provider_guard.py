"""Offline tests for the §8.3 provider guard (reserve → call → settle).

Uses the in-memory budget store + per-scan registry — no Redis/Postgres. Real
Postgres reserve/settle/uncertain behaviour is covered under ``requires_postgres``
in ``tests/integration/budget/test_facade_reserve_before_call_pg.py``.
"""

from __future__ import annotations

import pytest
from src.core.config import settings
from src.llm.provider_guard import (
    CallScope,
    provider_guard,
    reset_call_scope,
    set_call_scope,
)
from src.orchestration.agent_contracts import AgentUsage
from src.orchestration.budget_ledger import (
    BudgetDeniedError,
    BudgetLedger,
    InMemoryBudgetStore,
)
from src.orchestration.budget_scan_registry import (
    register_scan_ledger,
    unregister_scan_ledger,
)


@pytest.fixture
async def _ledger(monkeypatch):
    monkeypatch.setattr(settings, "budget_ledger_enabled", True)
    monkeypatch.setattr(settings, "lease_enabled", False)  # isolate budget from leasing
    store = InMemoryBudgetStore()
    ledger = BudgetLedger(store)
    register_scan_ledger("s1", ledger)
    yield store
    unregister_scan_ledger("s1")


def _scope(est_tokens: int = 100):
    return CallScope(tenant_id="t1", scan_id="s1", est_tokens=est_tokens, est_cost_usd=0.01)


async def test_settle_books_provider_usage(_ledger):
    await _ledger.set_limits("scan:s1", max_tokens=1000)
    token = set_call_scope(_scope())
    try:
        async with provider_guard("wrb") as run:
            run.record_usage(AgentUsage(input_tokens=50, output_tokens=30, estimated=False))
    finally:
        reset_call_scope(token)
    snap = await _ledger.snapshot("scan:s1")
    assert snap.used_tokens == 80
    assert snap.reserved_tokens == 0  # reservation converted to used


async def test_settle_books_cost_usd(_ledger):
    # §8.3: settle must book provider-metadata cost (not only tokens) so the
    # scan cost cap accumulates across calls, not just the transient reservation.
    await _ledger.set_limits("scan:s1", max_tokens=1000, max_cost_usd=1.0)
    token = set_call_scope(_scope())
    try:
        async with provider_guard("wrb") as run:
            run.record_usage(
                AgentUsage(input_tokens=50, output_tokens=30, cost_usd=0.02, estimated=False)
            )
    finally:
        reset_call_scope(token)
    snap = await _ledger.snapshot("scan:s1")
    assert snap.used_cost == pytest.approx(0.02)
    assert snap.reserved_cost == 0.0  # reservation converted to used


async def test_reserve_denies_when_over_cap(_ledger):
    await _ledger.set_limits("scan:s1", max_tokens=10)
    token = set_call_scope(_scope(est_tokens=100))
    try:
        with pytest.raises(BudgetDeniedError):
            async with provider_guard("wrb"):
                pytest.fail("must not enter the guarded block when reservation is denied")
    finally:
        reset_call_scope(token)
    snap = await _ledger.snapshot("scan:s1")
    assert snap.reserved_tokens == 0
    assert snap.used_tokens == 0


async def test_started_without_usage_leaves_uncertain(_ledger):
    await _ledger.set_limits("scan:s1", max_tokens=1000)
    token = set_call_scope(_scope(est_tokens=100))
    try:
        with pytest.raises(ValueError):
            async with provider_guard("wrb"):
                raise ValueError("provider crashed after send")
    finally:
        reset_call_scope(token)
    snap = await _ledger.snapshot("scan:s1")
    # Uncertain: the reservation is held (not freed) for reconciliation.
    assert snap.reserved_tokens == 100
    assert snap.used_tokens == 0


async def test_no_ledger_registered_is_passthrough(monkeypatch):
    monkeypatch.setattr(settings, "budget_ledger_enabled", True)
    monkeypatch.setattr(settings, "lease_enabled", False)
    unregister_scan_ledger("s-none")
    token = set_call_scope(CallScope(tenant_id="t1", scan_id="s-none", est_tokens=100))
    try:
        async with provider_guard("wrb") as run:
            run.record_usage(AgentUsage(input_tokens=5, output_tokens=5))
    finally:
        reset_call_scope(token)
    # No ledger → no error, nothing booked (behaviour identical to pre-feature).


async def test_disabled_flag_skips_budget(_ledger, monkeypatch):
    await _ledger.set_limits("scan:s1", max_tokens=5)
    monkeypatch.setattr(settings, "budget_ledger_enabled", False)
    token = set_call_scope(_scope(est_tokens=100))
    try:
        # Flag off → no reservation, so an over-cap estimate does NOT deny.
        async with provider_guard("wrb") as run:
            run.record_usage(AgentUsage(input_tokens=50, output_tokens=50))
    finally:
        reset_call_scope(token)
    snap = await _ledger.snapshot("scan:s1")
    assert snap.used_tokens == 0  # budgeting skipped entirely


async def test_paid_call_denied_when_ledger_unavailable(monkeypatch):
    # §8.3 fail-closed: flag on, scan-scoped, but no usable ledger → a PAID
    # (cloud) call must be denied rather than proceed unbounded.
    monkeypatch.setattr(settings, "budget_ledger_enabled", True)
    monkeypatch.setattr(settings, "lease_enabled", False)
    unregister_scan_ledger("s-down")
    token = set_call_scope(CallScope(tenant_id="t1", scan_id="s-down", est_tokens=100))
    try:
        with pytest.raises(BudgetDeniedError):
            async with provider_guard("cloud"):
                pytest.fail("paid call must not proceed when the ledger store is unavailable")
    finally:
        reset_call_scope(token)


async def test_zero_cost_call_passes_when_ledger_unavailable(monkeypatch):
    # A store outage must never block the local, zero-cost primary engine (WRB)
    # or a local OpenAI-compatible server — only paid calls fail closed.
    monkeypatch.setattr(settings, "budget_ledger_enabled", True)
    monkeypatch.setattr(settings, "lease_enabled", False)
    unregister_scan_ledger("s-down2")
    token = set_call_scope(CallScope(tenant_id="t1", scan_id="s-down2", est_tokens=100))
    entered = False
    try:
        async with provider_guard("local"):
            entered = True
    finally:
        reset_call_scope(token)
    assert entered is True


async def test_paid_call_without_scan_scope_is_passthrough(monkeypatch):
    # No scan_id → not scan-scoped; there is no per-scan budget to enforce, so a
    # cloud call (e.g. standalone report generation) proceeds even with the flag on.
    monkeypatch.setattr(settings, "budget_ledger_enabled", True)
    monkeypatch.setattr(settings, "lease_enabled", False)
    token = set_call_scope(CallScope(tenant_id="t1", scan_id="", est_tokens=100))
    entered = False
    try:
        async with provider_guard("cloud"):
            entered = True
    finally:
        reset_call_scope(token)
    assert entered is True


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
