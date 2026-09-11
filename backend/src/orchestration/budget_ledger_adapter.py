"""Ledger-backed cost tracker adapter (platform-hardening A, §7 item 3).

Staged, opt-in unification of the per-scan cost tracker with the authoritative
budget ledger. ``LedgerBackedCostTracker`` keeps the exact ``CostTracker`` public
surface used by ``llm.facade`` (``record`` / ``is_budget_exceeded`` / ``summary``
/ ``total_tokens`` / ``total_cost_usd``), so registering it via
``register_cost_tracker`` requires NO facade change — the facade already calls
``get_cost_tracker(scan_id).record(...)``.

Because ``CostTracker.record`` is synchronous and the ledger is async, each
recorded usage is buffered synchronously into a ``UsageSink`` and later drained
into the durable ledger by an async caller (the scan runner) via
``drain_sink_to_ledger``. This avoids sync→async bridging in the hot LLM path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from src.orchestration.agent_contracts import AgentUsage
from src.orchestration.budget_ledger import BudgetLedger, BudgetScope
from src.orchestration.cost_aware_reasoning import CostTracker, TokenUsageRecord


@dataclass
class UsageEvent:
    scan_id: str
    usage: AgentUsage


class UsageSink(Protocol):
    def record_usage(self, scan_id: str, usage: AgentUsage) -> None: ...


class InMemoryUsageSink:
    """Buffers usage events synchronously for later async drain to the ledger."""

    def __init__(self) -> None:
        self._events: list[UsageEvent] = []

    def record_usage(self, scan_id: str, usage: AgentUsage) -> None:
        self._events.append(UsageEvent(scan_id=scan_id, usage=usage))

    def drain(self) -> list[UsageEvent]:
        events, self._events = self._events, []
        return events

    @property
    def pending(self) -> int:
        return len(self._events)


class LedgerBackedCostTracker(CostTracker):
    """``CostTracker`` that also books each usage into a ``UsageSink``."""

    def __init__(
        self,
        sink: UsageSink,
        scan_id: str = "",
        max_cost_usd: float = 50.0,
        max_total_tokens: int = 2_000_000,
    ) -> None:
        super().__init__(
            scan_id=scan_id, max_cost_usd=max_cost_usd, max_total_tokens=max_total_tokens
        )
        self._sink = sink

    def record(self, record: TokenUsageRecord) -> None:
        super().record(record)
        # Usage is estimated here (facade-side); provider-metadata truth is the
        # ``estimated=False`` path used by callers that adopt reserve→settle.
        self._sink.record_usage(
            self._scan_id,
            AgentUsage(
                input_tokens=record.prompt_tokens,
                output_tokens=record.completion_tokens,
                cost_usd=record.estimated_cost_usd,
                model=record.model,
                estimated=True,
            ),
        )


async def drain_sink_to_ledger(sink: InMemoryUsageSink, ledger: BudgetLedger) -> int:
    """Drain buffered usage events into the durable ledger. Returns count booked."""
    if not ledger.available:
        return 0
    events = sink.drain()
    for ev in events:
        await ledger.record_usage(BudgetScope(scan_id=ev.scan_id), ev.usage)
    return len(events)


__all__ = [
    "InMemoryUsageSink",
    "LedgerBackedCostTracker",
    "UsageEvent",
    "UsageSink",
    "drain_sink_to_ledger",
]
