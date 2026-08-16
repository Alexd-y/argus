"""CONT-004 — execution mode metrics + kill-switch lease revocation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from src.execution_mode import evaluate_with_execution_mode
from src.execution_mode.lab_lease import (
    LabExecutionLease,
    LabLeaseService,
    LabLeaseStatus,
)
from src.execution_mode.lab_scope import LabScopeManifest
from src.execution_mode.metrics import (
    get_lab_boundary_denials_total,
    get_lab_executions_total,
    increment_lab_boundary_denial,
    increment_lab_execution,
    reset_execution_mode_metrics,
)
from src.execution_mode.mode import ExecutionMode
from src.execution_mode.repository import (
    InMemoryExecutionModeRepository,
    set_execution_mode_repository,
)
from src.policy.kill_switch import KillSwitchService, revoke_lab_leases_for_tenant


def _manifest(**overrides):
    base = {
        "tenant_id": "t-1",
        "engagement_id": "e-1",
        "cidrs": ("10.90.0.0/16",),
        "dns_suffixes": ("lab.argus",),
        "k8s_namespace": "argus-lab-42",
        "vm_network_ids": ("labnet-42",),
        "capture_full": True,
        "expires_at": datetime.now(tz=UTC) + timedelta(hours=4),
        "created_by": "u-1",
    }
    base.update(overrides)
    return LabScopeManifest(**base)


@pytest.fixture
def repo() -> InMemoryExecutionModeRepository:
    store = InMemoryExecutionModeRepository()
    set_execution_mode_repository(store)
    yield store
    set_execution_mode_repository(InMemoryExecutionModeRepository())
    reset_execution_mode_metrics()


def test_metrics_increment_helpers():
    reset_execution_mode_metrics()
    assert increment_lab_execution() == 1
    assert get_lab_executions_total() == 1
    assert increment_lab_boundary_denial() == 1
    assert get_lab_boundary_denials_total() == 1


def test_policy_bridge_increments_lab_execution_on_allow():
    reset_execution_mode_metrics()
    manifest = _manifest()
    lease = LabLeaseService().issue(manifest, boundary_proof="proof-1")
    before = get_lab_executions_total()
    decision = evaluate_with_execution_mode(
        mode=ExecutionMode.LAB_UNRESTRICTED,
        target="10.90.1.5",
        lease=lease,
        tenant_id="t-1",
    )
    assert decision.allowed
    assert get_lab_executions_total() == before + 1


def test_policy_bridge_increments_boundary_denial():
    reset_execution_mode_metrics()
    manifest = _manifest()
    before = get_lab_boundary_denials_total()
    decision = evaluate_with_execution_mode(
        mode=ExecutionMode.LAB_UNRESTRICTED,
        target="https://evil.example/",
        manifest=manifest,
        tenant_id="t-1",
        engagement_id="e-1",
        k8s_namespace="argus-lab-42",
        vm_network_id="labnet-42",
    )
    assert not decision.allowed
    assert get_lab_boundary_denials_total() == before + 1


@pytest.mark.asyncio
async def test_kill_switch_revoke_makes_lease_not_usable(repo: InMemoryExecutionModeRepository):
    manifest = _manifest()
    await repo.save_manifest(manifest)
    lease = LabLeaseService().issue(manifest, boundary_proof="proof-abc")
    assert lease.is_usable()

    await repo.save_lease("idem-kill", lease.to_storage_dict())

    revoked_count = await revoke_lab_leases_for_tenant("t-1", repo=repo)
    assert revoked_count == 1

    cached_after = await repo.get_lease_by_idempotency_key("idem-kill")
    assert cached_after is not None
    assert cached_after["status"] == LabLeaseStatus.KILL_SWITCHED.value

    killed = LabExecutionLease.from_storage_dict(
        {k: v for k, v in cached_after.items() if k != "_idempotency_key"}
    )
    assert killed.is_usable() is False


@pytest.mark.asyncio
async def test_kill_switch_service_set_tenant_throttle_revokes_leases(
    repo: InMemoryExecutionModeRepository,
):
    manifest = _manifest(tenant_id="tenant-kill")
    lease = LabLeaseService().issue(manifest, boundary_proof="proof-x")
    await repo.save_lease("idem-t", lease.to_storage_dict())

    fake_redis = MagicMock()
    fake_redis.set.return_value = True
    svc = KillSwitchService(fake_redis)

    svc.set_tenant_throttle(
        "tenant-kill",
        duration_seconds=300,
        reason="test throttle",
        operator_subject="operator@test",
    )

    cached = await repo.get_lease_by_idempotency_key("idem-t")
    assert cached is not None
    assert cached["status"] == LabLeaseStatus.KILL_SWITCHED.value
