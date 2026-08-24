"""Cost-aware reasoning — token budget tracking and confidence-based tier escalation.

Tracks LLM token usage per scan/phase/tier, enforces budget limits,
and provides dynamic model escalation when confidence is low.

Ось D п.7 из Развитие2.md: cost-aware reasoning.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TokenUsageRecord:
    phase: str
    tier: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


class CostTracker:
    def __init__(self, scan_id: str = "", max_cost_usd: float = 50.0, max_total_tokens: int = 2000000) -> None:
        self._scan_id = scan_id
        self._max_cost_usd = max_cost_usd
        self._max_total_tokens = max_total_tokens
        self._records: list[TokenUsageRecord] = []
        self._total_tokens = 0
        self._total_cost_usd = 0.0

    def record(self, record: TokenUsageRecord) -> None:
        self._records.append(record)
        self._total_tokens += record.total_tokens
        self._total_cost_usd += record.estimated_cost_usd

    def is_budget_exceeded(self) -> bool:
        return self._total_cost_usd >= self._max_cost_usd or self._total_tokens >= self._max_total_tokens

    @property
    def total_tokens(self) -> int:
        return self._total_tokens

    @property
    def total_cost_usd(self) -> float:
        return round(self._total_cost_usd, 4)

    @property
    def records(self) -> list[TokenUsageRecord]:
        return list(self._records)

    def summary(self) -> dict[str, Any]:
        by_phase: dict[str, dict[str, int]] = {}
        for r in self._records:
            if r.phase not in by_phase:
                by_phase[r.phase] = {"tokens": 0, "cost": 0.0}
            by_phase[r.phase]["tokens"] += r.total_tokens
            by_phase[r.phase]["cost"] += r.estimated_cost_usd
        return {
            "scan_id": self._scan_id,
            "total_tokens": self._total_tokens,
            "total_cost_usd": self.total_cost_usd,
            "budget_remaining_usd": max(0, self._max_cost_usd - self._total_cost_usd),
            "by_phase": by_phase,
        }


class BudgetExceededError(Exception):
    pass


class BudgetEnforcer:
    def __init__(self, tracker: CostTracker) -> None:
        self._tracker = tracker

    def check(self) -> None:
        if self._tracker.is_budget_exceeded():
            raise BudgetExceededError(
                f"Budget exceeded: ${self._tracker.total_cost_usd:.2f} / "
                f"${self._tracker._max_cost_usd:.2f}, "
                f"{self._tracker.total_tokens} / {self._tracker._max_total_tokens} tokens"
            )


class ConfidenceEscalator:
    def __init__(self, confidence_threshold: float = 0.7) -> None:
        self._threshold = confidence_threshold

    def should_escalate(self, confidence: float, current_tier: str) -> bool:
        if confidence >= self._threshold:
            return False
        tier_order = {"small": 0, "medium": 1, "large": 2}
        current_idx = tier_order.get(current_tier, 0)
        return current_idx < 2


_scan_cost_trackers: dict[str, CostTracker] = {}


def register_cost_tracker(tracker: CostTracker) -> None:
    """Register a CostTracker for a scan so LLM facade can record into it."""
    if tracker._scan_id:
        _scan_cost_trackers[tracker._scan_id] = tracker


def unregister_cost_tracker(scan_id: str) -> None:
    """Remove a CostTracker after scan completes."""
    _scan_cost_trackers.pop(scan_id, None)


def get_cost_tracker(scan_id: str) -> CostTracker | None:
    """Look up the CostTracker for a scan (used by LLM facade)."""
    return _scan_cost_trackers.get(scan_id)


__all__ = [
    "BudgetEnforcer",
    "BudgetExceededError",
    "ConfidenceEscalator",
    "CostTracker",
    "TokenUsageRecord",
    "register_cost_tracker",
    "unregister_cost_tracker",
    "get_cost_tracker",
]
