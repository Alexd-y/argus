"""LAB-001 — sandbox execution_lease_gate fail-closed for LAB mode."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from src.execution_mode import (
    LabBoundaryVerifier,
    LabLeaseService,
    LabLeaseStatus,
    LabScopeManifest,
)
from src.recon.mcp.kal_executor import run_kal_mcp_tool
from src.recon.mcp.policy import evaluate_tool_approval_for_scan
from src.sandbox.execution_lease_gate import assert_execution_allowed


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
    }


def test_production_mode_gate_is_noop():
    assert_execution_allowed(
        "sqlmap",
        "https://prod.example/",
        {"execution_mode": "production"},
        tenant_id="t-1",
    )


def test_lab_missing_lease_denies_before_exec():
    with pytest.raises(PermissionError, match="lab_lease_required"):
        assert_execution_allowed(
            "sqlmap",
            "https://app.lab.argus/",
            {"execution_mode": "lab_unrestricted", "tenant_id": "t-1"},
            tenant_id="t-1",
        )


def test_lab_kill_switched_lease_denies():
    lease = _usable_lease()
    killed = lease.revoke(reason=LabLeaseStatus.KILL_SWITCHED)
    options = _lab_options_with_lease(killed)
    with pytest.raises(PermissionError):
        assert_execution_allowed(
            "sqlmap",
            "https://app.lab.argus/",
            options,
            tenant_id="t-1",
            engagement_id="e-1",
        )


def test_kal_mcp_denies_lab_without_lease(monkeypatch):
    monkeypatch.setattr(
        "src.recon.mcp.kal_executor.evaluate_kal_mcp_policy",
        lambda **kwargs: type("D", (), {"allowed": True, "reason": "allowed", "policy_id": "x"})(),
    )

    result = run_kal_mcp_tool(
        category="dns_enumeration",
        argv=["subfinder", "-d", "lab.argus", "-silent"],
        target="lab.argus",
        tenant_id="t-1",
        scan_id="s-1",
        password_audit_opt_in=False,
        scan_options={"execution_mode": "lab_unrestricted", "tenant_id": "t-1"},
    )
    assert result["success"] is False
    assert "lab_lease_required" in (result.get("stderr") or "")


def test_evaluate_tool_approval_for_scan_production_requires_approval():
    decision = evaluate_tool_approval_for_scan(
        "sqlmap",
        {"execution_mode": "production"},
        target="https://prod.example/",
    )
    assert decision.allowed is False
    assert decision.reason in {
        "requires_lab_mode",
        "requires_approval",
        "active_injection_quick_blocks_destructive",
    }
