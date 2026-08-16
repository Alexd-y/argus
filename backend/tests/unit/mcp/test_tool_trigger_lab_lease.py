"""WIRE-007 — MCP tool trigger + tools.executor LAB lease gates."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from src.core.unified_ai_metrics import get_lab_executions_total, reset_unified_ai_metrics
from src.execution_mode import (
    LabBoundaryVerifier,
    LabLeaseService,
    LabLeaseStatus,
    LabScopeManifest,
)
from src.mcp.schemas.scan import ScanCreateInput, ScanProfile
from src.mcp.schemas.tool_run import (
    ToolRunStatus,
    ToolRunTriggerInput,
)
from src.mcp.services.scan_service import lab_lease_skips_deep_justification
from src.mcp.services.tool_service import (
    reset_registry_for_tests,
    trigger_tool_run,
)
from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel
from src.sandbox.adapter_base import (
    NetworkPolicyRef,
    ParseStrategy,
    ToolCategory,
    ToolDescriptor,
)
from src.tools.executor import execute_command


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


def _usable_lease(manifest: LabScopeManifest | None = None):
    m = manifest or _manifest()
    verdict = LabBoundaryVerifier().verify(
        "10.90.2.2",
        m,
        tenant_id="t-1",
        engagement_id="e-1",
        k8s_namespace="argus-lab-42",
        vm_network_id="labnet-42",
    )
    assert verdict.allowed
    return LabLeaseService().issue(m, boundary_proof=verdict.proof)


def _lab_options_with_lease(lease) -> dict:
    return {
        "execution_mode": "lab_unrestricted",
        "tenant_id": "t-1",
        "engagement_id": "e-1",
        "lab_scope": _manifest().to_storage_dict(),
        "lab_lease": lease.to_storage_dict(),
        "k8s_namespace": "argus-lab-42",
        "vm_network_id": "labnet-42",
        "target": "https://app.lab.argus/login",
    }


def _make_descriptor(
    *,
    tool_id: str,
    risk: RiskLevel,
    requires_approval: bool = False,
) -> ToolDescriptor:
    return ToolDescriptor(
        tool_id=tool_id,
        category=ToolCategory.WEB_VA,
        phase=ScanPhase.EXPLOITATION,
        risk_level=risk,
        requires_approval=requires_approval,
        network_policy=NetworkPolicyRef(name="default"),
        seccomp_profile="default.json",
        default_timeout_s=60,
        cpu_limit="500m",
        memory_limit="256Mi",
        image="argus/example:1.0",
        command_template=["example", "{target.url}"],
        parse_strategy=ParseStrategy.JSON_LINES,
        description="stub tool",
    )


class _StubRegistry:
    def __init__(self, descriptors: list[ToolDescriptor]) -> None:
        self._by_id = {d.tool_id: d for d in descriptors}

    def get(self, tool_id: str) -> ToolDescriptor | None:
        return self._by_id.get(tool_id)

    def all_descriptors(self) -> list[ToolDescriptor]:
        return [self._by_id[k] for k in sorted(self._by_id)]


@pytest.fixture(autouse=True)
def stub_registry() -> Iterator[None]:
    reset_registry_for_tests(
        _StubRegistry(  # type: ignore[arg-type]
            [
                _make_descriptor(
                    tool_id="sqlmap",
                    risk=RiskLevel.HIGH,
                    requires_approval=True,
                ),
                _make_descriptor(tool_id="nmap", risk=RiskLevel.LOW),
            ]
        )
    )
    yield
    reset_registry_for_tests(None)


def test_mcp_high_risk_lab_lease_queued_without_approval() -> None:
    reset_unified_ai_metrics()
    lease = _usable_lease()
    result = trigger_tool_run(
        payload=ToolRunTriggerInput(
            tool_id="sqlmap",
            target="https://app.lab.argus/login",
            scan_options=_lab_options_with_lease(lease),
        ),
        actor="alice",
        tenant_id="t-1",
    )
    assert result.requires_approval is False
    assert result.status is ToolRunStatus.QUEUED
    assert result.tool_run_id is not None
    assert result.approval_request_id is None
    assert get_lab_executions_total() >= 1


def test_mcp_high_risk_production_approval_pending() -> None:
    result = trigger_tool_run(
        payload=ToolRunTriggerInput(
            tool_id="sqlmap",
            target="https://prod.example/login",
            justification="Customer reported SQLi on login form, ticket SEC-1234",
            scan_options={"execution_mode": "production"},
        ),
        actor="alice",
        tenant_id="t-1",
    )
    assert result.requires_approval is True
    assert result.status is ToolRunStatus.APPROVAL_PENDING
    assert result.approval_request_id is not None
    assert result.tool_run_id is None


def test_executor_lab_without_lease_raises_permission_error() -> None:
    with pytest.raises(PermissionError, match="lab_lease_required"):
        execute_command(
            "sqlmap -u https://app.lab.argus/login --batch",
            use_cache=False,
            scan_options={
                "execution_mode": "lab_unrestricted",
                "tenant_id": "t-1",
            },
            tenant_id="t-1",
            target="https://app.lab.argus/login",
        )


def test_executor_kill_switched_lease_denies() -> None:
    lease = _usable_lease()
    killed = lease.revoke(reason=LabLeaseStatus.KILL_SWITCHED)
    options = _lab_options_with_lease(killed)
    with pytest.raises(PermissionError):
        execute_command(
            "sqlmap -u https://app.lab.argus/login --batch",
            use_cache=False,
            scan_options=options,
            tenant_id="t-1",
            engagement_id="e-1",
            target="https://app.lab.argus/login",
        )


def test_deep_justification_not_required_with_valid_lab_lease() -> None:
    lease = _usable_lease()
    options = _lab_options_with_lease(lease)
    assert lab_lease_skips_deep_justification(options, tenant_id="t-1") is True
    payload = ScanCreateInput(
        target="https://app.lab.argus",
        profile=ScanProfile.DEEP,
        scan_options=options,
    )
    assert payload.justification is None


def test_deep_justification_still_required_in_production() -> None:
    assert (
        lab_lease_skips_deep_justification(
            {"execution_mode": "production"},
            tenant_id="t-1",
        )
        is False
    )
