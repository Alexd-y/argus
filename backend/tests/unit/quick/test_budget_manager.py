"""QUICK-002 — QuickBudgetManager: deadline, leases, FrozenClock, expiry."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from src.quick.budget import (
    BudgetLease,
    LeaseExpiredError,
    LeaseStatus,
    QuickBudgetError,
    QuickBudgetManager,
    QuickBudgetSnapshot,
    compute_deadline_at,
)
from src.quick.clock import FrozenClock, SystemClock
from src.quick.profiles import DeploymentQuickClamps, load_quick_profiles
from src.quick.resolver import QuickProfileResolver
from src.quick.schemas import QuickBudgetKind, QuickProfileName, QuickTaskStatus

_TENANT_ID = "tenant-quick-002-budget-01"
_SCAN_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_TASK_ID = "11111111-2222-3333-4444-555555555555"
_STARTED = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
_CATALOG = load_quick_profiles()
_CLAMPS = DeploymentQuickClamps()


def _config(profile: QuickProfileName = QuickProfileName.BALANCED):
    return QuickProfileResolver(catalog=_CATALOG, clamps=_CLAMPS).resolve(_TENANT_ID, profile)


def _manager(clock: FrozenClock | None = None) -> QuickBudgetManager:
    return QuickBudgetManager(
        clock=clock if clock is not None else FrozenClock(_STARTED),
        catalog=_CATALOG,
        clamps=_CLAMPS,
    )


def _open(
    manager: QuickBudgetManager,
    *,
    scan_id: str = _SCAN_ID,
    started_at: datetime = _STARTED,
    profile: QuickProfileName = QuickProfileName.BALANCED,
) -> QuickBudgetSnapshot:
    return manager.open_scan(
        tenant_id=_TENANT_ID,
        scan_id=scan_id,
        config=_config(profile),
        started_at=started_at,
    )


def test_deadline_at_is_started_at_plus_wall_clock_not_worker_clock() -> None:
    worker_now = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
    clock = FrozenClock(worker_now)
    manager = _manager(clock)
    snapshot = _open(manager, started_at=_STARTED)

    assert snapshot.started_at == _STARTED
    assert snapshot.deadline_at == _STARTED + timedelta(seconds=900)
    assert snapshot.deadline_at == compute_deadline_at(_STARTED, 900)
    assert snapshot.deadline_at != worker_now + timedelta(seconds=900)
    assert snapshot.budget.wall_clock_budget_seconds == 900


def test_compute_deadline_at_accepts_naive_started_at_as_utc() -> None:
    naive = datetime(2026, 8, 16, 12, 0)
    deadline = compute_deadline_at(naive, 300)
    assert deadline.tzinfo is not None
    assert deadline == datetime(2026, 8, 16, 12, 5, tzinfo=UTC)


def test_manager_compute_deadline_matches_module_helper() -> None:
    manager = _manager()
    assert manager.compute_deadline(_STARTED, 1800) == compute_deadline_at(_STARTED, 1800)


def test_lease_grant_consume_release() -> None:
    manager = _manager()
    snapshot = _open(manager)
    discovery_pool = snapshot.budget.discovery_budget_seconds
    assert discovery_pool > 10

    lease = manager.acquire_lease(
        scan_id=_SCAN_ID,
        kind=QuickBudgetKind.DISCOVERY,
        amount=10,
        task_id=_TASK_ID,
    )
    assert isinstance(lease, BudgetLease)
    assert lease.status is LeaseStatus.ACTIVE
    assert lease.granted == 10
    assert lease.consumed == 0
    assert lease.kind is QuickBudgetKind.DISCOVERY
    assert manager.remaining(_SCAN_ID, QuickBudgetKind.DISCOVERY) == discovery_pool - 10

    partial = manager.consume(lease.lease_id, 4)
    assert partial.consumed == 4
    assert partial.status is LeaseStatus.ACTIVE
    assert manager.get_lease(lease.lease_id).consumed == 4

    released = manager.release(lease.lease_id)
    assert released.status is LeaseStatus.RELEASED
    # Unused granted units (6) return to the pool; consumed 4 stay spent.
    assert manager.remaining(_SCAN_ID, QuickBudgetKind.DISCOVERY) == discovery_pool - 4

    again = manager.release(lease.lease_id)
    assert again.status is LeaseStatus.RELEASED


def test_consume_none_exhausts_remaining_granted() -> None:
    manager = _manager()
    _open(manager)
    lease = manager.acquire_lease(
        scan_id=_SCAN_ID,
        kind=QuickBudgetKind.FINGERPRINT,
        amount=8,
        task_id=_TASK_ID,
    )
    exhausted = manager.consume(lease.lease_id)
    assert exhausted.consumed == 8
    assert exhausted.status is LeaseStatus.EXHAUSTED


def test_frozen_clock_advance_does_not_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args, **_kwargs) -> None:
        raise AssertionError("sleep must not be called")

    monkeypatch.setattr("time.sleep", _boom)
    clock = FrozenClock(_STARTED)
    before = clock.now()
    advanced = clock.advance(3600)
    assert advanced == before + timedelta(seconds=3600)
    assert clock.now() == _STARTED + timedelta(hours=1)
    clock.set(_STARTED)
    assert clock.now() == _STARTED


def test_lease_expire_raises_timed_out_lease_expired_error() -> None:
    clock = FrozenClock(_STARTED)
    manager = _manager(clock)
    _open(manager)
    lease = manager.acquire_lease(
        scan_id=_SCAN_ID,
        kind=QuickBudgetKind.DISCOVERY,
        amount=5,
        task_id=_TASK_ID,
    )
    assert manager.assert_startable(lease.lease_id).status is LeaseStatus.ACTIVE

    clock.advance(5)
    with pytest.raises(LeaseExpiredError, match="lease_expired") as exc_info:
        manager.assert_startable(lease.lease_id)
    assert exc_info.value.code == "lease_expired"
    assert exc_info.value.task_status is QuickTaskStatus.TIMED_OUT
    assert exc_info.value.task_status.value == "timed_out"
    assert manager.get_lease(lease.lease_id).status is LeaseStatus.EXPIRED


def test_consume_after_expiry_raises_lease_expired_error() -> None:
    clock = FrozenClock(_STARTED)
    manager = _manager(clock)
    _open(manager)
    lease = manager.acquire_lease(
        scan_id=_SCAN_ID,
        kind=QuickBudgetKind.AI,
        amount=3,
        task_id=_TASK_ID,
    )
    clock.advance(3)
    with pytest.raises(LeaseExpiredError, match="lease_expired") as exc_info:
        manager.consume(lease.lease_id, 1)
    assert exc_info.value.task_status is QuickTaskStatus.TIMED_OUT
    assert manager.get_lease(lease.lease_id).status is LeaseStatus.EXPIRED


def test_acquire_after_deadline_raises_lease_expired_error() -> None:
    clock = FrozenClock(_STARTED)
    manager = _manager(clock)
    snapshot = _open(manager)
    clock.advance(snapshot.budget.wall_clock_budget_seconds)
    assert manager.deadline_reached(_SCAN_ID) is True
    with pytest.raises(LeaseExpiredError, match="lease_expired"):
        manager.acquire_lease(
            scan_id=_SCAN_ID,
            kind=QuickBudgetKind.DISCOVERY,
            amount=1,
            task_id=_TASK_ID,
        )


def test_unknown_scan_and_lease_raise_quick_budget_error() -> None:
    manager = _manager()
    with pytest.raises(QuickBudgetError, match="unknown_quick_scan_budget") as scan_exc:
        manager.remaining("missing-scan-id-000000000000000000", QuickBudgetKind.DISCOVERY)
    assert scan_exc.value.code == "unknown_quick_scan_budget"

    with pytest.raises(QuickBudgetError, match="unknown_quick_lease") as lease_exc:
        manager.get_lease("00000000-0000-0000-0000-000000000000")
    assert lease_exc.value.code == "unknown_quick_lease"


def test_negative_lease_amount_rejected() -> None:
    manager = _manager()
    _open(manager)
    with pytest.raises(QuickBudgetError, match="lease_amount_negative") as exc_info:
        manager.acquire_lease(
            scan_id=_SCAN_ID,
            kind=QuickBudgetKind.DISCOVERY,
            amount=-1,
        )
    assert exc_info.value.code == "lease_amount_negative"


def test_system_clock_now_is_timezone_aware_utc() -> None:
    instant = SystemClock().now()
    assert instant.tzinfo is not None
    assert instant.utcoffset() == timedelta(0)
