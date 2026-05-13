"""Cost-Aware Router — budget enforcement and provider selection by cost.

Ensures: per-scan budget enforcement, soft-limit warnings, provider fallback
to cheapest available when budget constrained.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_SOFT_LIMIT_RATIO = 0.80


class CostRouter:
    def __init__(self, max_cost_usd: float = 0.0) -> None:
        self._max_cost = max_cost_usd
        self._soft_limit = max_cost_usd * _SOFT_LIMIT_RATIO
        self._spent = 0.0

    @property
    def remaining(self) -> float:
        return max(0.0, self._max_cost - self._spent)

    @property
    def over_soft_limit(self) -> bool:
        return self._spent >= self._soft_limit and self._max_cost > 0

    def can_afford(self, estimated_cost: float) -> bool:
        return self._spent + estimated_cost <= self._max_cost or self._max_cost <= 0

    def select_cheapest(
        self, providers: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        available = sorted(
            [p for p in providers if p.get("base_url")],
            key=lambda p: max(
                p.get("price", {}).get("input_per_million_usd", 0),
                p.get("price", {}).get("output_per_million_usd", 0),
            ),
        )
        for p in available:
            cost_est = p.get("price", {}).get("input_per_million_usd", 0) / 500
            if self.can_afford(cost_est):
                return p
        return None

    def record_spend(self, cost: float) -> None:
        self._spent += cost
        if self._spent >= self._max_cost > 0:
            logger.warning("budget_exceeded", extra={"spent": self._spent, "max": self._max_cost})
        elif self.over_soft_limit:
            logger.info("soft_limit_reached", extra={"spent": self._spent, "soft": self._soft_limit})


def build_cost_router(scan_budget: dict[str, Any] | None) -> CostRouter:
    if not scan_budget:
        return CostRouter(max_cost_usd=0.5)
    return CostRouter(
        max_cost_usd=float(scan_budget.get("max_cost_usd", 0.5)),
    )
