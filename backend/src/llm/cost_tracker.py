"""LLM cost tracking per scan — token counting, budget enforcement, phase breakdown."""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.core.observability import record_llm_tokens

logger = logging.getLogger(__name__)


def _provider_from_model(model: str) -> str:
    """Extract a provider label from a free-form model identifier."""
    if not model:
        return "_other"
    m = model.lower()
    if m.startswith("anthropic/") or "claude" in m:
        return "anthropic"
    if m.startswith("openai/") or m.startswith("gpt") or m.startswith("o1") or m.startswith("o3"):
        return "openai"
    if "deepseek" in m:
        return "deepseek"
    if "gemini" in m or "google/" in m:
        return "gemini"
    if "sonar" in m or "perplexity" in m:
        return "perplexity"
    if "moonshot" in m or "kimi" in m:
        return "moonshot"
    if m.startswith("meta-llama/") or "llama" in m:
        return "meta"
    return "_other"

COST_PER_1K_TOKENS: dict[str, dict[str, float]] = {
    "deepseek-chat": {"input": 0.00014, "output": 0.00028},
    "deepseek-reasoner": {"input": 0.00055, "output": 0.00219},
    "gpt-4o": {"input": 0.0025, "output": 0.010},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-4o-2024-08-06": {"input": 0.0025, "output": 0.010},
    "anthropic/claude-3.5-sonnet": {"input": 0.003, "output": 0.015},
    "anthropic/claude-3-haiku": {"input": 0.00025, "output": 0.00125},
    "sonar-pro": {"input": 0.003, "output": 0.015},
    "sonar": {"input": 0.001, "output": 0.001},
    "llama-3.1-sonar-huge-online": {"input": 0.005, "output": 0.005},
    "moonshot-v1-8k": {"input": 0.001, "output": 0.003},
    "moonshot-v1-32k": {"input": 0.002, "output": 0.006},
    "moonshot-v1-128k": {"input": 0.008, "output": 0.008},
    "openai/gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "meta-llama/llama-3.1-70b-instruct": {"input": 0.00059, "output": 0.00079},
}

DEFAULT_COST: dict[str, float] = {"input": 0.002, "output": 0.008}


class ScanBudgetExceededError(RuntimeError):
    """Raised when a scan's cumulative LLM spend exceeds the configured budget."""


@dataclass
class LLMCallRecord:
    """Single LLM invocation record within a scan."""

    phase: str
    task: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ScanCostTracker:
    """Per-scan LLM cost tracker with budget enforcement."""

    def __init__(self, scan_id: str, max_cost_usd: float | None = None) -> None:
        self.scan_id = scan_id
        self.max_cost_usd = max_cost_usd or float(
            os.environ.get("MAX_COST_PER_SCAN_USD", "10.0")
        )
        self.calls: list[LLMCallRecord] = []

    def record(
        self,
        phase: str,
        task: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> float:
        """Record an LLM call and return its cost. Raises ScanBudgetExceededError if budget blown."""
        cost = calc_cost(model, prompt_tokens, completion_tokens)
        self.calls.append(
            LLMCallRecord(
                phase=phase,
                task=task,
                model=model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                cost_usd=cost,
            )
        )
        # ARG-041 — emit token counters (defensive: never break the call path).
        try:
            provider = _provider_from_model(model)
            record_llm_tokens(
                provider=provider,
                model=model,
                direction="in",
                tokens=int(max(0, prompt_tokens)),
            )
            record_llm_tokens(
                provider=provider,
                model=model,
                direction="out",
                tokens=int(max(0, completion_tokens)),
            )
        except Exception:  # pragma: no cover — defensive
            logger.debug("cost_tracker.metrics_emit_failed", exc_info=True)
        total = self.total_cost_usd
        if total > self.max_cost_usd:
            logger.warning(
                "Scan budget exceeded",
                extra={
                    "event": "argus.scan_budget_exceeded",
                    "scan_id": self.scan_id,
                    "total_cost": total,
                    "max_cost": self.max_cost_usd,
                },
            )
            raise ScanBudgetExceededError(
                f"Scan {self.scan_id} exceeded budget: ${total:.4f} > ${self.max_cost_usd}"
            )
        return cost

    @property
    def total_cost_usd(self) -> float:
        return sum(c.cost_usd for c in self.calls)

    @property
    def total_tokens(self) -> int:
        return sum(c.prompt_tokens + c.completion_tokens for c in self.calls)

    def breakdown(self) -> dict[str, Any]:
        """Generate cost breakdown by phase."""
        by_phase: dict[str, dict[str, Any]] = {}
        for c in self.calls:
            entry = by_phase.setdefault(
                c.phase, {"cost": 0.0, "tokens": 0, "calls": 0}
            )
            entry["cost"] += c.cost_usd
            entry["tokens"] += c.prompt_tokens + c.completion_tokens
            entry["calls"] += 1

        cheapest = min(self.calls, key=lambda c: c.cost_usd) if self.calls else None
        most_expensive = max(self.calls, key=lambda c: c.cost_usd) if self.calls else None

        return {
            "scan_id": self.scan_id,
            "total_cost_usd": round(self.total_cost_usd, 5),
            "total_tokens": self.total_tokens,
            "total_calls": len(self.calls),
            "by_phase": {
                k: {
                    "cost": round(v["cost"], 5),
                    "tokens": v["tokens"],
                    "calls": v["calls"],
                }
                for k, v in by_phase.items()
            },
            "cheapest_call": {
                "model": cheapest.model,
                "cost": round(cheapest.cost_usd, 6),
                "task": cheapest.task,
            }
            if cheapest
            else None,
            "most_expensive_call": {
                "model": most_expensive.model,
                "cost": round(most_expensive.cost_usd, 6),
                "task": most_expensive.task,
            }
            if most_expensive
            else None,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize for DB storage (JSON column)."""
        return self.breakdown()


def calc_cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Calculate cost in USD for given model and token counts."""
    rates = COST_PER_1K_TOKENS.get(model, DEFAULT_COST)
    return (prompt_tokens * rates["input"] + completion_tokens * rates["output"]) / 1000


_tracker_registry: dict[str, ScanCostTracker] = {}
_tracker_lock = threading.Lock()


def get_tracker(scan_id: str, *, max_cost_usd: float | None = None) -> ScanCostTracker:
    """Return the per-scan ``ScanCostTracker``, creating it on first access.

    Trackers are stored in a process-local registry so every LLM call made
    during the same scan shares the same budget bookkeeping. Callers must
    use :func:`pop_tracker` once the scan finalizes to release the entry.

    The optional ``max_cost_usd`` only applies the first time the tracker
    is created; subsequent calls for the same ``scan_id`` ignore it to
    keep budgets stable across the scan lifecycle.
    """
    with _tracker_lock:
        tracker = _tracker_registry.get(scan_id)
        if tracker is None:
            tracker = ScanCostTracker(scan_id, max_cost_usd=max_cost_usd)
            _tracker_registry[scan_id] = tracker
        return tracker


def pop_tracker(scan_id: str) -> ScanCostTracker | None:
    """Detach and return the tracker for ``scan_id`` or ``None`` if absent.

    Used by the orchestrator at scan finalization to flush per-scan cost
    state to the database and release the registry slot.
    """
    with _tracker_lock:
        return _tracker_registry.pop(scan_id, None)
