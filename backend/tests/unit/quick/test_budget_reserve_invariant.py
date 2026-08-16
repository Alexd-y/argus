"""QUICK-002 — stage+reserve invariant and discovery cannot eat verification reserve."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src.quick.budget import (
    DiscoveryReserveProtectedError,
    QuickBudgetManager,
    assert_reserve_invariant,
    reserve_seconds,
    stage_budget_sum,
)
from src.quick.clock import FrozenClock
from src.quick.profiles import DeploymentQuickClamps, load_quick_profiles
from src.quick.resolver import QuickProfileResolver
from src.quick.schemas import QuickBudgetKind, QuickProfileName

_TENANT_ID = "tenant-quick-002-reserve-01"
_SCAN_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
_STARTED = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
_CATALOG = load_quick_profiles()
_CLAMPS = DeploymentQuickClamps()
_RESOLVER = QuickProfileResolver(catalog=_CATALOG, clamps=_CLAMPS)


def _manager(clock: FrozenClock | None = None) -> QuickBudgetManager:
    return QuickBudgetManager(
        clock=clock if clock is not None else FrozenClock(_STARTED),
        catalog=_CATALOG,
        clamps=_CLAMPS,
    )


@pytest.mark.parametrize(
    ("profile", "wall_clock"),
    [
        (QuickProfileName.COMPACT, 300),
        (QuickProfileName.BALANCED, 900),
        (QuickProfileName.EXTENDED, 1800),
    ],
)
def test_stage_plus_reserve_equals_wall_clock_within_one_second(
    profile: QuickProfileName,
    wall_clock: int,
) -> None:
    config = _RESOLVER.resolve(_TENANT_ID, profile)
    budget = _manager().build_budget(config)
    assert budget.wall_clock_budget_seconds == wall_clock
    reserved = reserve_seconds(
        budget.wall_clock_budget_seconds,
        budget.reserve_for_validation_percent,
    )
    assert reserved > 0
    delta = abs(stage_budget_sum(budget) + reserved - budget.wall_clock_budget_seconds)
    assert delta <= 1
    assert_reserve_invariant(budget)


@pytest.mark.parametrize("profile", list(QuickProfileName))
def test_open_scan_budget_keeps_reserve_invariant(profile: QuickProfileName) -> None:
    manager = _manager()
    snapshot = manager.open_scan(
        tenant_id=_TENANT_ID,
        scan_id=f"{profile.value}-scan-id-000000000000000000"[:36],
        config=_RESOLVER.resolve(_TENANT_ID, profile),
        started_at=_STARTED,
    )
    assert_reserve_invariant(snapshot.budget)
    reserved = reserve_seconds(
        snapshot.budget.wall_clock_budget_seconds,
        snapshot.budget.reserve_for_validation_percent,
    )
    assert (
        abs(stage_budget_sum(snapshot.budget) + reserved - snapshot.budget.wall_clock_budget_seconds)
        <= 1
    )


def test_discovery_cannot_consume_verification_reserve() -> None:
    clock = FrozenClock(_STARTED)
    manager = _manager(clock)
    snapshot = manager.open_scan(
        tenant_id=_TENANT_ID,
        scan_id=_SCAN_ID,
        config=_RESOLVER.resolve(_TENANT_ID, QuickProfileName.BALANCED),
        started_at=_STARTED,
    )
    reserved = reserve_seconds(
        snapshot.budget.wall_clock_budget_seconds,
        snapshot.budget.reserve_for_validation_percent,
    )
    discovery_left = manager.remaining(_SCAN_ID, QuickBudgetKind.DISCOVERY)
    assert discovery_left > 0
    assert reserved > 0

    # Elapse until only the validation/report reserve remains on the wall clock.
    clock.advance(snapshot.budget.wall_clock_budget_seconds - reserved)
    assert manager.deadline_reached(_SCAN_ID) is False
    assert manager.should_stop_discovery(_SCAN_ID) is True
    assert manager.remaining(_SCAN_ID, QuickBudgetKind.DISCOVERY) == discovery_left

    with pytest.raises(DiscoveryReserveProtectedError, match="discovery_reserve_protected") as exc_info:
        manager.acquire_lease(
            scan_id=_SCAN_ID,
            kind=QuickBudgetKind.DISCOVERY,
            amount=1,
        )
    assert exc_info.value.code == "discovery_reserve_protected"

    verification = manager.acquire_lease(
        scan_id=_SCAN_ID,
        kind=QuickBudgetKind.VERIFICATION,
        amount=1,
    )
    assert verification.granted == 1
    report = manager.acquire_lease(
        scan_id=_SCAN_ID,
        kind=QuickBudgetKind.REPORT,
        amount=1,
    )
    assert report.granted == 1


def test_discovery_blocked_when_requested_amount_would_eat_reserve() -> None:
    clock = FrozenClock(_STARTED)
    manager = _manager(clock)
    snapshot = manager.open_scan(
        tenant_id=_TENANT_ID,
        scan_id=_SCAN_ID,
        config=_RESOLVER.resolve(_TENANT_ID, QuickProfileName.COMPACT),
        started_at=_STARTED,
    )
    reserved = reserve_seconds(
        snapshot.budget.wall_clock_budget_seconds,
        snapshot.budget.reserve_for_validation_percent,
    )
    discovery_left = manager.remaining(_SCAN_ID, QuickBudgetKind.DISCOVERY)
    # Leave less wall-clock headroom than the discovery pool, but more than zero.
    clock.advance(snapshot.budget.wall_clock_budget_seconds - reserved - 5)
    assert discovery_left > 5
    with pytest.raises(DiscoveryReserveProtectedError, match="discovery_reserve_protected"):
        manager.acquire_lease(
            scan_id=_SCAN_ID,
            kind=QuickBudgetKind.DISCOVERY,
            amount=discovery_left,
        )
    small = manager.acquire_lease(
        scan_id=_SCAN_ID,
        kind=QuickBudgetKind.DISCOVERY,
        amount=1,
    )
    assert small.granted == 1
