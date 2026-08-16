"""QUICK-002 — per-host token bucket and concurrency cap leases."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src.quick.budget import (
    BudgetExhaustedError,
    ConcurrencyLimitError,
    LeaseStatus,
    QuickBudgetManager,
    normalize_host_key,
)
from src.quick.clock import FrozenClock
from src.quick.profiles import DeploymentQuickClamps, TenantQuickLimits, load_quick_profiles
from src.quick.resolver import QuickProfileResolver
from src.quick.schemas import QuickBudgetKind, QuickProfileName

_TENANT_ID = "tenant-quick-002-host-conc-01"
_SCAN_A = "cccccccc-dddd-eeee-ffff-000000000001"
_SCAN_B = "cccccccc-dddd-eeee-ffff-000000000002"
_STARTED = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
_CATALOG = load_quick_profiles()
_HOST_A = "https://app.example.com/login"
_HOST_B = "https://api.example.net/v1"


def _manager(
    clock: FrozenClock | None = None,
    clamps: DeploymentQuickClamps | None = None,
) -> QuickBudgetManager:
    return QuickBudgetManager(
        clock=clock if clock is not None else FrozenClock(_STARTED),
        catalog=_CATALOG,
        clamps=clamps if clamps is not None else DeploymentQuickClamps(),
    )


def _open(
    manager: QuickBudgetManager,
    *,
    scan_id: str,
    tenant_id: str = _TENANT_ID,
    profile: QuickProfileName = QuickProfileName.COMPACT,
    tenant_limits: TenantQuickLimits | None = None,
):
    config = QuickProfileResolver(
        catalog=_CATALOG,
        clamps=DeploymentQuickClamps(),
    ).resolve(tenant_id, profile)
    return manager.open_scan(
        tenant_id=tenant_id,
        scan_id=scan_id,
        config=config,
        started_at=_STARTED,
        tenant_limits=tenant_limits,
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://app.example.com/login", "app.example.com"),
        ("https://user:secret@app.example.com:8443/x", "app.example.com"),
        ("APP.EXAMPLE.COM", "app.example.com"),
        ("", "unknown-host"),
        ("   ", "unknown-host"),
    ],
)
def test_normalize_host_key_strips_userinfo_and_path(raw: str, expected: str) -> None:
    assert normalize_host_key(raw) == expected
    assert "secret" not in normalize_host_key(raw)
    assert "@" not in normalize_host_key(raw)


def test_per_host_token_bucket_exhausts_then_refills_without_sleep() -> None:
    clock = FrozenClock(_STARTED)
    manager = _manager(clock)
    snapshot = _open(manager, scan_id=_SCAN_A)
    capacity = snapshot.budget.per_host_budget
    wall = snapshot.budget.wall_clock_budget_seconds
    assert capacity == 400
    assert wall == 300

    granted = manager.acquire_lease(
        scan_id=_SCAN_A,
        kind=QuickBudgetKind.PER_HOST,
        amount=capacity,
        host_key=_HOST_A,
    )
    assert granted.host_key == "app.example.com"
    assert granted.granted == capacity

    with pytest.raises(BudgetExhaustedError, match="per_host_budget_exhausted") as exc_info:
        manager.acquire_lease(
            scan_id=_SCAN_A,
            kind=QuickBudgetKind.PER_HOST,
            amount=1,
            host_key="https://app.example.com/other",
        )
    assert exc_info.value.code == "budget_exhausted"

    other_host = manager.acquire_lease(
        scan_id=_SCAN_A,
        kind=QuickBudgetKind.PER_HOST,
        amount=capacity,
        host_key=_HOST_B,
    )
    assert other_host.host_key == "api.example.net"

    # compact refill_per_second = 400/300; 75s restores exactly 100 tokens.
    clock.advance(75)
    refilled = manager.acquire_lease(
        scan_id=_SCAN_A,
        kind=QuickBudgetKind.PER_HOST,
        amount=100,
        host_key=_HOST_A,
    )
    assert refilled.granted == 100
    with pytest.raises(BudgetExhaustedError, match="per_host_budget_exhausted"):
        manager.acquire_lease(
            scan_id=_SCAN_A,
            kind=QuickBudgetKind.PER_HOST,
            amount=1,
            host_key=_HOST_A,
        )


def test_per_host_release_returns_unused_tokens() -> None:
    manager = _manager()
    snapshot = _open(manager, scan_id=_SCAN_A)
    capacity = snapshot.budget.per_host_budget
    lease = manager.acquire_lease(
        scan_id=_SCAN_A,
        kind=QuickBudgetKind.PER_HOST,
        amount=capacity,
        host_key=_HOST_A,
    )
    manager.consume(lease.lease_id, 10)
    released = manager.release(lease.lease_id)
    assert released.status is LeaseStatus.RELEASED

    restored = manager.acquire_lease(
        scan_id=_SCAN_A,
        kind=QuickBudgetKind.PER_HOST,
        amount=capacity - 10,
        host_key=_HOST_A,
    )
    assert restored.granted == capacity - 10


def test_per_host_lease_host_key_never_contains_credentials() -> None:
    manager = _manager()
    _open(manager, scan_id=_SCAN_A)
    lease = manager.acquire_lease(
        scan_id=_SCAN_A,
        kind=QuickBudgetKind.PER_HOST,
        amount=1,
        host_key="https://user:super-secret-token@app.example.com/admin",
    )
    assert lease.host_key == "app.example.com"
    dumped = lease.model_dump()
    assert "super-secret-token" not in str(dumped)
    assert "user:" not in str(dumped)


def test_scan_concurrency_cap_blocks_then_release_frees_slot() -> None:
    manager = _manager()
    snapshot = _open(manager, scan_id=_SCAN_A, profile=QuickProfileName.COMPACT)
    cap = snapshot.budget.concurrency_budget
    assert cap == 4

    leases = [
        manager.acquire_lease(
            scan_id=_SCAN_A,
            kind=QuickBudgetKind.CONCURRENCY,
            amount=1,
            task_id=f"task-{index:02d}-0000000000000000000000"[:36],
        )
        for index in range(cap)
    ]
    assert all(item.status is LeaseStatus.ACTIVE for item in leases)

    with pytest.raises(ConcurrencyLimitError, match="scan_concurrency_exhausted") as exc_info:
        manager.acquire_lease(
            scan_id=_SCAN_A,
            kind=QuickBudgetKind.CONCURRENCY,
            amount=1,
        )
    assert exc_info.value.code == "concurrency_limit"

    manager.release(leases[-1].lease_id)
    freed = manager.acquire_lease(
        scan_id=_SCAN_A,
        kind=QuickBudgetKind.CONCURRENCY,
        amount=1,
    )
    assert freed.status is LeaseStatus.ACTIVE


def test_tenant_concurrency_cap_across_scans() -> None:
    clamps = DeploymentQuickClamps(max_concurrency=2)
    manager = _manager(clamps=clamps)
    limits = TenantQuickLimits(tenant_id=_TENANT_ID, max_concurrency=2)
    _open(manager, scan_id=_SCAN_A, tenant_limits=limits)
    _open(manager, scan_id=_SCAN_B, tenant_limits=limits)

    manager.acquire_lease(scan_id=_SCAN_A, kind=QuickBudgetKind.CONCURRENCY, amount=2)
    with pytest.raises(ConcurrencyLimitError, match="tenant_concurrency_exhausted") as exc_info:
        manager.acquire_lease(scan_id=_SCAN_B, kind=QuickBudgetKind.CONCURRENCY, amount=1)
    assert exc_info.value.code == "concurrency_limit"


def test_concurrency_budget_clamped_to_deployment_max() -> None:
    clamps = DeploymentQuickClamps(max_concurrency=2)
    manager = _manager(clamps=clamps)
    config = QuickProfileResolver(catalog=_CATALOG, clamps=clamps).resolve(
        _TENANT_ID, QuickProfileName.EXTENDED
    )
    budget = manager.build_budget(config)
    # YAML extended concurrency_budget is 8; deployment clamp wins.
    assert budget.concurrency_budget == 2
    assert _CATALOG.extended.concurrency_budget == 8
