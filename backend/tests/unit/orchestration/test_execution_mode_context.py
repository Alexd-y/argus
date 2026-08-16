"""T1 — execution_mode_context: LAB lease allow-all vs production gates."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from src.execution_mode import (
    ExecutionMode,
    LabBoundaryVerifier,
    LabLeaseService,
    LabLeaseStatus,
    LabScopeManifest,
)
from src.orchestration.execution_mode_context import (
    is_lab_lease_active_from_options,
    resolve_mode_context_from_options,
    resolve_tool_policy,
    resolve_tool_policy_from_options,
)
from src.recon.mcp.policy import evaluate_tool_approval_for_scan


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


@pytest.mark.parametrize(
    "tool_name",
    ["sqlmap", "nuclei", "custom_script"],
)
def test_lab_usable_lease_allows_without_approval(tool_name: str):
    lease = _usable_lease()
    decision = resolve_tool_policy(
        tool_name,
        mode=ExecutionMode.LAB_UNRESTRICTED,
        lease=lease,
        target="https://app.lab.argus/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert decision.allowed is True
    assert decision.requires_approval is False
    assert decision.lab_lease_active is True
    assert decision.deny_code is None
    assert decision.reason == "verified_lab_unrestricted"


def test_lab_usable_lease_from_options():
    lease = _usable_lease()
    options = {
        "execution_mode": "lab_unrestricted",
        "tenant_id": "t-1",
        "engagement_id": "e-1",
        "lab_lease": lease.to_storage_dict(),
    }
    assert is_lab_lease_active_from_options(options, tenant_id="t-1") is True
    decision = resolve_tool_policy_from_options(
        "sqlmap",
        options,
        target="https://app.lab.argus/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert decision.allowed is True
    assert decision.requires_approval is False
    assert decision.lab_lease_active is True

    mcp = evaluate_tool_approval_for_scan(
        "sqlmap",
        options,
        target="https://app.lab.argus/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert mcp.allowed is True
    assert mcp.reason == "verified_lab_unrestricted"


def test_production_destructive_denied_without_flags():
    decision = resolve_tool_policy(
        "sqlmap",
        mode=ExecutionMode.PRODUCTION,
        scan_approval_flags=None,
        target="https://prod.example/",
    )
    assert decision.allowed is False
    assert decision.lab_lease_active is False
    assert decision.requires_approval is True
    assert decision.reason in {
        "requires_lab_mode",
        "requires_approval",
        "active_injection_quick_blocks_destructive",
    }


def test_production_path_via_options_defaults():
    ctx = resolve_mode_context_from_options({"scan_id": "s-1"}, tenant_id="t-1", engagement_id="e-1")
    assert ctx.mode is ExecutionMode.PRODUCTION
    assert ctx.is_lab is False

    decision = resolve_tool_policy_from_options(
        "sqlmap",
        {"execution_mode": "production"},
        target="https://prod.example/",
    )
    assert decision.allowed is False
    assert decision.lab_lease_active is False


def test_lab_missing_lease_denies_outside_lab():
    decision = resolve_tool_policy(
        "sqlmap",
        mode=ExecutionMode.LAB_UNRESTRICTED,
        lease=None,
        manifest=None,
        target="https://app.lab.argus/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert decision.allowed is False
    assert decision.lab_lease_active is False
    assert decision.deny_code == "DENY_OUTSIDE_LAB"
    assert decision.requires_approval is True


def test_lab_outside_boundary_denies_outside_lab():
    m = _manifest()
    # Unusable / no lease; outside target + manifest → boundary deny.
    decision = resolve_tool_policy(
        "nuclei",
        mode=ExecutionMode.LAB_UNRESTRICTED,
        lease=None,
        manifest=m,
        target="https://evil.example/",
        tenant_id="t-1",
        engagement_id="e-1",
        k8s_namespace="argus-lab-42",
        vm_network_id="labnet-42",
    )
    assert decision.allowed is False
    assert decision.deny_code == "DENY_OUTSIDE_LAB"
    assert decision.lab_lease_active is False


def test_lab_kill_switched_lease_not_active():
    lease = _usable_lease()
    killed = lease.revoke(reason=LabLeaseStatus.KILL_SWITCHED)
    assert killed.is_usable() is False

    decision = resolve_tool_policy(
        "sqlmap",
        mode=ExecutionMode.LAB_UNRESTRICTED,
        lease=killed,
        target="https://app.lab.argus/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert decision.allowed is False
    assert decision.deny_code == "DENY_OUTSIDE_LAB"
    assert decision.lab_lease_active is False

    mcp = evaluate_tool_approval_for_scan(
        "sqlmap",
        {
            "execution_mode": "lab_unrestricted",
            "tenant_id": "t-1",
            "engagement_id": "e-1",
            "lab_lease": killed.to_storage_dict(),
        },
        target="https://app.lab.argus/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert mcp.allowed is False
    assert mcp.reason == "lab_lease_required"


def test_aggressive_exploit_skips_outside_boundary_not_policy_in_lab(monkeypatch):
    from src.orchestration import aggressive_exploit_tools as aet

    enqueued: list[tuple] = []

    class _FakeTask:
        def delay(self, *args, **kwargs):
            enqueued.append(args)

    monkeypatch.setattr(
        "src.tasks.tools.run_sqlmap",
        _FakeTask(),
        raising=False,
    )
    # Patch import path used inside maybe_run_aggressive_exploit_tools
    import src.tasks.tools as tools_mod

    monkeypatch.setattr(tools_mod, "run_sqlmap", _FakeTask(), raising=False)

    lease = _usable_lease()
    findings = [{"title": "SQL Injection", "cwe": "CWE-89"}]
    aet.maybe_run_aggressive_exploit_tools(
        findings,
        "t-1",
        "s-1",
        "https://app.lab.argus/login",
        scan_approval_flags=None,
        scan_options={
            "execution_mode": "lab_unrestricted",
            "lab_lease": lease.to_storage_dict(),
            "engagement_id": "e-1",
        },
    )
    assert len(enqueued) == 1

    # Outside boundary / missing lease — no enqueue even in LAB mode.
    enqueued.clear()
    aet.maybe_run_aggressive_exploit_tools(
        findings,
        "t-1",
        "s-1",
        "https://app.lab.argus/login",
        scan_approval_flags=None,
        scan_options={
            "execution_mode": "lab_unrestricted",
            "engagement_id": "e-1",
        },
    )
    assert enqueued == []
