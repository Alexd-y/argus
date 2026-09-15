"""Tests for the ledger-backed cost tracker adapter (§7 item 3)."""

from __future__ import annotations

import pytest
from src.orchestration.budget_ledger import BudgetLedger, InMemoryBudgetStore
from src.orchestration.budget_ledger_adapter import (
    InMemoryUsageSink,
    LedgerBackedCostTracker,
    drain_sink_to_ledger,
)
from src.orchestration.cost_aware_reasoning import (
    TokenUsageRecord,
    get_cost_tracker,
    register_cost_tracker,
    unregister_cost_tracker,
)


def _rec(prompt=40, completion=60, cost=0.01):
    return TokenUsageRecord(
        phase="vuln",
        tier="large",
        model="wrb",
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=prompt + completion,
        estimated_cost_usd=cost,
    )


def test_adapter_preserves_cost_tracker_surface_and_feeds_sink():
    sink = InMemoryUsageSink()
    tracker = LedgerBackedCostTracker(sink, scan_id="s1")
    tracker.record(_rec())
    # CostTracker behaviour intact.
    assert tracker.total_tokens == 100
    assert tracker.total_cost_usd == pytest.approx(0.01)
    # And the usage was buffered for the ledger.
    assert sink.pending == 1


async def test_drain_books_into_ledger():
    sink = InMemoryUsageSink()
    tracker = LedgerBackedCostTracker(sink, scan_id="s1")
    tracker.record(_rec(prompt=50, completion=50))
    tracker.record(_rec(prompt=10, completion=20))

    ledger = BudgetLedger(InMemoryBudgetStore())
    booked = await drain_sink_to_ledger(sink, ledger)
    assert booked == 2
    assert sink.pending == 0
    snap = await ledger.snapshot("scan:s1")
    assert snap.used_tokens == 130  # 100 + 30


async def test_drain_noop_when_ledger_unavailable():
    sink = InMemoryUsageSink()
    LedgerBackedCostTracker(sink, scan_id="s1").record(_rec())
    ledger = BudgetLedger(store=None)  # unavailable
    booked = await drain_sink_to_ledger(sink, ledger)
    assert booked == 0
    # Events are retained (not silently dropped) when the ledger is unavailable.
    assert sink.pending == 1


def test_facade_registration_path_reaches_sink():
    # The facade calls get_cost_tracker(scan_id).record(...). If a
    # LedgerBackedCostTracker is registered, that path feeds the ledger sink
    # with NO facade change.
    sink = InMemoryUsageSink()
    tracker = LedgerBackedCostTracker(sink, scan_id="scan-xyz")
    register_cost_tracker(tracker)
    try:
        got = get_cost_tracker("scan-xyz")
        assert got is tracker
        got.record(_rec())
        assert sink.pending == 1
    finally:
        unregister_cost_tracker("scan-xyz")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
