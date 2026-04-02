"""LLM cost tracking per scan — token counting, budget enforcement, phase breakdown."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

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
