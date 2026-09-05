"""Block 4.6 — scan-quota domain logic tests (pure, DB-free)."""

from __future__ import annotations

from datetime import UTC, datetime

from src.quota.service import (
    MAX_EXTRA_SCANS,
    QuotaState,
    add_one_month,
    included_for_tier,
    new_state,
)

_NOW = datetime(2026, 1, 15, tzinfo=UTC)


def _state(tier: str, **kw) -> QuotaState:
    return new_state(tier, now=_NOW, **kw)


class TestTierMath:
    def test_included_per_tier(self):
        assert included_for_tier("free") == 1
        assert included_for_tier("standard") == 4
        assert included_for_tier("premium") == 6
        assert included_for_tier("unknown") == 0

    def test_add_one_month_clamps_day(self):
        jan31 = datetime(2026, 1, 31, tzinfo=UTC)
        nxt = add_one_month(jan31)
        assert (nxt.year, nxt.month, nxt.day) == (2026, 2, 28)

    def test_add_one_month_year_rollover(self):
        dec = datetime(2026, 12, 10, tzinfo=UTC)
        assert add_one_month(dec).year == 2027
        assert add_one_month(dec).month == 1


class TestSnapshot:
    def test_fresh_standard(self):
        snap = _state("standard").snapshot()
        assert snap["included"] == 4
        assert snap["remaining"] == 4
        assert snap["used"] == 0
        assert snap["capacity"] == 4
        assert snap["canRetest"] is True
        assert snap["canBuyExtra"] is False

    def test_exhausted_can_buy_extra(self):
        s = _state("standard", used_this_period=4)
        snap = s.snapshot()
        assert snap["remaining"] == 0
        assert snap["canRetest"] is False
        assert snap["canBuyExtra"] is True

    def test_camel_case_period_end_iso(self):
        assert "periodEnd" in _state("premium").snapshot()


class TestConsume:
    def test_consume_included_then_bonus(self):
        s = _state("free")  # included=1
        ok, src = s.consume()
        assert ok and src == "included"
        # included exhausted, no bonus
        ok2, src2 = s.consume()
        assert ok2 is False and src2 is None
        # grant bonus, then consume from bonus
        s.add_bonus(2)
        ok3, src3 = s.consume()
        assert ok3 and src3 == "bonus"

    def test_add_bonus_capped(self):
        s = _state("standard")
        assert s.add_bonus(10) == MAX_EXTRA_SCANS
        assert s.add_bonus(1) == 0  # already at cap


class TestPeriodRoll:
    def test_refresh_rolls_and_resets(self):
        s = _state("standard", used_this_period=4)
        s.bonus_used_this_period = 1
        # two months later
        later = datetime(2026, 3, 20, tzinfo=UTC)
        rolled = s.refresh(now=later)
        assert rolled is True
        assert s.used_this_period == 0
        assert s.bonus_used_this_period == 0
        assert s.remaining == 4

    def test_refresh_noop_within_period(self):
        s = _state("standard", used_this_period=2)
        assert s.refresh(now=datetime(2026, 1, 20, tzinfo=UTC)) is False
        assert s.used_this_period == 2
