"""Scan-quota domain logic (Block 4.6).

Pure, DB-free quota state + math so it is fully unit-testable, mirroring the
frontend ``ScanQuota`` contract (``src/lib/scan-quota.ts``): monthly included
scans per tier plus purchasable bonus credits, with automatic monthly period
roll-over. The DB model (``ScanQuota``) and async service wrappers persist this
state; all decisions live here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

# Included scans per billing period, per tier (mirror of scan-tiers.ts).
TIER_SCANS: dict[str, int] = {"free": 1, "standard": 4, "premium": 6}
# Max purchasable extra scans on top of the included allowance (mirror of frontend).
MAX_EXTRA_SCANS = 3

# Consumption source when a scan credit is spent.
SOURCE_INCLUDED = "included"
SOURCE_BONUS = "bonus"


def add_one_month(from_dt: datetime) -> datetime:
    """Return ``from_dt`` advanced by one calendar month (clamps day overflow)."""
    year = from_dt.year + (from_dt.month // 12)
    month = from_dt.month % 12 + 1
    # Clamp day to 28 to avoid month-length overflow (e.g. Jan 31 -> Feb).
    day = min(from_dt.day, 28)
    return from_dt.replace(year=year, month=month, day=day)


def included_for_tier(tier: str) -> int:
    return TIER_SCANS.get(str(tier).lower(), 0)


@dataclass
class QuotaState:
    """Mutable quota state for one tenant/period. Pure — no I/O."""

    tier: str
    period_start: datetime
    period_end: datetime
    used_this_period: int = 0
    bonus_credits: int = 0
    bonus_used_this_period: int = 0

    def refresh(self, now: datetime | None = None) -> bool:
        """Roll the period forward while expired, resetting per-period counters.

        Returns True when at least one roll happened (state mutated).
        """
        now = now or datetime.now(UTC)
        rolled = False
        while now >= self.period_end:
            self.period_start = self.period_end
            self.period_end = add_one_month(self.period_start)
            self.used_this_period = 0
            self.bonus_used_this_period = 0
            rolled = True
        return rolled

    @property
    def included(self) -> int:
        return included_for_tier(self.tier)

    @property
    def included_remaining(self) -> int:
        return max(0, self.included - self.used_this_period)

    @property
    def remaining(self) -> int:
        return self.included_remaining + self.bonus_credits

    def snapshot(self) -> dict[str, object]:
        """Serialize to the frontend ``ScanQuota`` shape (camelCase)."""
        extra = self.bonus_credits + self.bonus_used_this_period
        used = self.used_this_period + self.bonus_used_this_period
        remaining = self.remaining
        return {
            "included": self.included,
            "extra": extra,
            "extraCap": MAX_EXTRA_SCANS,
            "used": used,
            "remaining": remaining,
            "capacity": self.included + extra,
            "periodEnd": self.period_end.isoformat(),
            "canRetest": remaining > 0,
            "canBuyExtra": remaining == 0 and extra < MAX_EXTRA_SCANS,
        }

    def consume(self) -> tuple[bool, str | None]:
        """Spend one credit (included first, then bonus). Returns (ok, source)."""
        if self.included_remaining > 0:
            self.used_this_period += 1
            return True, SOURCE_INCLUDED
        if self.bonus_credits > 0:
            self.bonus_credits -= 1
            self.bonus_used_this_period += 1
            return True, SOURCE_BONUS
        return False, None

    def add_bonus(self, quantity: int) -> int:
        """Grant up to ``MAX_EXTRA_SCANS`` bonus credits; returns granted count."""
        extra_in_play = self.bonus_credits + self.bonus_used_this_period
        room = max(0, MAX_EXTRA_SCANS - extra_in_play)
        grant = min(max(0, quantity), room)
        self.bonus_credits += grant
        return grant


def new_state(tier: str, *, now: datetime | None = None, used_this_period: int = 0) -> QuotaState:
    """Create a fresh quota state whose period starts now."""
    now = now or datetime.now(UTC)
    return QuotaState(
        tier=str(tier).lower(),
        period_start=now,
        period_end=add_one_month(now),
        used_this_period=used_this_period,
    )


__all__ = [
    "MAX_EXTRA_SCANS",
    "SOURCE_BONUS",
    "SOURCE_INCLUDED",
    "TIER_SCANS",
    "QuotaState",
    "add_one_month",
    "included_for_tier",
    "new_state",
]
