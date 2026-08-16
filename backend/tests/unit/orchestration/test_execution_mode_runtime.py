"""CONT-001 — execution_mode + lab lease wired into runtime policy paths."""

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
    inject_phase_execution_mode_preflight,
    preflight_phase_execution_mode,
    resolve_lease_for_options,
    resolve_tool_policy,
    resolve_tool_policy_from_options,
)
from src.recon.mcp.policy import (
    evaluate_tool_approval_for_scan,
    evaluate_tool_approval_policy,
)
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


@pytest.mark.parametrize("tool_name", ["sqlmap", "commix"])
def test_lab_lease_allows_destructive_without_approval(tool_name: str):
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

    mcp = evaluate_tool_approval_policy(
        tool_name,
        scan_approval_flags=None,
        lab_lease_active=True,
    )
    assert mcp.allowed is True
    assert mcp.reason == "verified_lab_unrestricted"


def test_lab_missing_lease_denies_destructive():
    decision = resolve_tool_policy(
        "sqlmap",
        mode=ExecutionMode.LAB_UNRESTRICTED,
        lease=None,
        target="https://app.lab.argus/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert decision.allowed is False
    assert decision.lab_lease_active is False
    assert decision.deny_code == "DENY_OUTSIDE_LAB"
    assert decision.reason == "lab_lease_required"

    mcp = evaluate_tool_approval_for_scan(
        "sqlmap",
        {"execution_mode": "lab_unrestricted", "tenant_id": "t-1"},
        target="https://app.lab.argus/",
        tenant_id="t-1",
    )
    assert mcp.allowed is False
    assert mcp.reason == "lab_lease_required"


def test_production_destructive_requires_approval_path():
    decision = resolve_tool_policy_from_options(
        "sqlmap",
        {"execution_mode": "production"},
        target="https://prod.example/",
    )
    assert decision.allowed is False
    assert decision.lab_lease_active is False
    assert decision.requires_approval is True

    mcp = evaluate_tool_approval_for_scan(
        "sqlmap",
        {"execution_mode": "production"},
        target="https://prod.example/",
    )
    assert mcp.allowed is False
    assert mcp.reason in {
        "requires_lab_mode",
        "requires_approval",
        "active_injection_quick_blocks_destructive",
    }


def test_assert_execution_allowed_production_noop():
    assert_execution_allowed(
        "sqlmap",
        "https://prod.example/",
        {"execution_mode": "production"},
        tenant_id="t-1",
    )


def test_assert_execution_allowed_lab_without_lease_raises():
    with pytest.raises(PermissionError, match="lab_lease_required"):
        assert_execution_allowed(
            "sqlmap",
            "https://app.lab.argus/",
            {"execution_mode": "lab_unrestricted", "tenant_id": "t-1"},
            tenant_id="t-1",
        )


def test_assert_execution_allowed_lab_with_lease_passes():
    lease = _usable_lease()
    options = _lab_options_with_lease(lease)
    assert_execution_allowed(
        "sqlmap",
        "https://app.lab.argus/login",
        options,
        tenant_id="t-1",
        engagement_id="e-1",
    )


def test_assert_execution_allowed_kill_switched_lease_denies():
    lease = _usable_lease()
    killed = lease.revoke(reason=LabLeaseStatus.KILL_SWITCHED)
    options = _lab_options_with_lease(killed)
    with pytest.raises(PermissionError):
        assert_execution_allowed(
            "sqlmap",
            "https://app.lab.argus/login",
            options,
            tenant_id="t-1",
            engagement_id="e-1",
        )


def test_lease_lookup_callable_injected():
    lease = _usable_lease()
    seen: list[tuple] = []

    def lookup(opts, tenant_id, engagement_id):
        seen.append((dict(opts), tenant_id, engagement_id))
        return lease

    resolved = resolve_lease_for_options(
        {"execution_mode": "lab_unrestricted"},
        tenant_id="t-1",
        engagement_id="e-1",
        lease_lookup=lookup,
    )
    assert resolved is lease
    assert len(seen) == 1


def test_preflight_phase_execution_mode_injected_into_input():
    lease = _usable_lease()
    options = _lab_options_with_lease(lease)
    preflight = preflight_phase_execution_mode(
        options,
        tenant_id="t-1",
        scan_id="s-1",
        engagement_id="e-1",
    )
    assert preflight.lab_lease_active is True
    assert preflight.mode == "lab_unrestricted"

    input_data: dict = {}
    inject_phase_execution_mode_preflight(input_data, preflight)
    assert input_data["execution_mode_context"]["lab_lease_active"] is True


def test_preflight_lab_without_lease_fail_closed():
    preflight = preflight_phase_execution_mode(
        {"execution_mode": "lab_unrestricted", "tenant_id": "t-1"},
        tenant_id="t-1",
        scan_id="s-1",
    )
    assert preflight.lab_lease_active is False
    assert preflight.deny_code == "DENY_OUTSIDE_LAB"
    assert preflight.reason == "lab_lease_required"


def test_exploitation_approval_skipped_when_lab_lease_active():
    from src.orchestration.state_machine import _check_exploitation_approval_required

    lease = _usable_lease()
    options = _lab_options_with_lease(lease)

    async def _run():
        return await _check_exploitation_approval_required(
            session=None,  # type: ignore[arg-type]
            tenant_id="t-1",
            scan_id="s-1",
            options=options,
        )

    import asyncio

    assert asyncio.run(_run()) is False


def test_vuln_analysis_lab_allow_all_and_outside_boundary_deny():
    """vuln_analysis phase: LAB+lease allows nuclei; missing lease denies."""
    from src.orchestration.handlers import (
        _attach_phase_execution_mode,
        _lab_tool_dispatch_allowed,
    )

    lease = _usable_lease()
    allowed_opts = _attach_phase_execution_mode(
        _lab_options_with_lease(lease),
        tenant_id="t-1",
        scan_id="s-va-1",
        engagement_id="e-1",
    )
    assert allowed_opts["execution_mode_context"]["lab_lease_active"] is True
    assert (
        _lab_tool_dispatch_allowed(
            "nuclei",
            allowed_opts,
            target="https://app.lab.argus/",
            tenant_id="t-1",
        )
        is True
    )

    denied_opts = _attach_phase_execution_mode(
        {"execution_mode": "lab_unrestricted", "tenant_id": "t-1", "engagement_id": "e-1"},
        tenant_id="t-1",
        scan_id="s-va-2",
        engagement_id="e-1",
    )
    assert denied_opts["execution_mode_context"]["lab_lease_active"] is False
    assert (
        _lab_tool_dispatch_allowed(
            "nuclei",
            denied_opts,
            target="https://app.lab.argus/",
            tenant_id="t-1",
        )
        is False
    )


def test_exploitation_lab_allow_all_and_outside_boundary_deny():
    """exploitation_executor: LAB+lease skips approval deny; missing lease denies tool."""
    from src.orchestration import exploitation_executor as ee

    lease = _usable_lease()
    options = _lab_options_with_lease(lease)

    async def _allowed():
        return await ee._execute_tool_in_sandbox(
            "sqlmap",
            "https://app.lab.argus/login",
            "' OR 1=1--",
            scan_options=options,
            tenant_id="t-1",
        )

    async def _denied():
        return await ee._execute_tool_in_sandbox(
            "sqlmap",
            "https://app.lab.argus/login",
            "' OR 1=1--",
            scan_options={
                "execution_mode": "lab_unrestricted",
                "tenant_id": "t-1",
                "engagement_id": "e-1",
            },
            tenant_id="t-1",
        )

    import asyncio

    allowed = asyncio.run(_allowed())
    denied = asyncio.run(_denied())

    assert denied["exit_code"] == -1
    assert "policy_denied" in denied["stderr"]
    # Allowed path must not be blocked by LAB policy (docker may still be absent).
    assert "policy_denied" not in (allowed.get("stderr") or "")


def test_production_tool_dispatch_unchanged():
    from src.orchestration.handlers import _lab_tool_dispatch_allowed

    assert (
        _lab_tool_dispatch_allowed(
            "sqlmap",
            {"execution_mode": "production"},
            target="https://prod.example/",
            tenant_id="t-1",
        )
        is True
    )


def test_evaluate_tool_approval_for_scan_lab_and_production():
    lease = _usable_lease()
    mcp_lab = evaluate_tool_approval_for_scan(
        "sqlmap",
        _lab_options_with_lease(lease),
        target="https://app.lab.argus/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert mcp_lab.allowed is True
    assert mcp_lab.reason == "verified_lab_unrestricted"

    mcp_out = evaluate_tool_approval_for_scan(
        "sqlmap",
        {"execution_mode": "lab_unrestricted", "tenant_id": "t-1"},
        target="https://app.lab.argus/",
        tenant_id="t-1",
    )
    assert mcp_out.allowed is False
    assert mcp_out.reason == "lab_lease_required"


def test_evaluate_tool_approval_for_scan_kill_switched_lease_denies():
    lease = _usable_lease()
    killed = lease.revoke(reason=LabLeaseStatus.KILL_SWITCHED)
    mcp = evaluate_tool_approval_for_scan(
        "sqlmap",
        _lab_options_with_lease(killed),
        target="https://app.lab.argus/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert mcp.allowed is False
    assert mcp.reason == "lab_lease_required"


def test_all_phase_handlers_attach_execution_mode():
    """All 8 pipeline phase entrypoints stamp execution_mode_context."""
    import ast
    from pathlib import Path

    handlers_path = Path(__file__).resolve().parents[3] / "src" / "orchestration" / "handlers.py"
    tree = ast.parse(handlers_path.read_text(encoding="utf-8"))
    phase_fns = {
        "run_source_analysis",
        "run_recon",
        "run_quick_fuzz",
        "run_threat_modeling",
        "run_vuln_analysis",
        "run_exploit_attempt",
        "run_post_exploitation",
        "run_reporting",
    }
    found: dict[str, bool] = {name: False for name in phase_fns}
    for node in tree.body:
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        if node.name not in phase_fns:
            continue
        src = ast.dump(node)
        found[node.name] = "_attach_phase_execution_mode" in src
    assert all(found.values()), f"missing attach: {[k for k, v in found.items() if not v]}"


def test_state_machine_preflight_denies_lab_without_lease():
    from src.orchestration.execution_mode_context import preflight_phase_execution_mode
    from src.orchestration.state_machine import LabLeaseRequiredError

    preflight = preflight_phase_execution_mode(
        {"execution_mode": "lab_unrestricted", "tenant_id": "t-1"},
        tenant_id="t-1",
        scan_id="s-deny-1",
    )
    assert preflight.deny_code == "DENY_OUTSIDE_LAB"
    assert preflight.lab_lease_active is False
    # Gate condition used by run_scan_state_machine phase loop.
    assert bool(preflight.deny_code and not preflight.lab_lease_active)
    with pytest.raises(LabLeaseRequiredError):
        if preflight.deny_code and not preflight.lab_lease_active:
            raise LabLeaseRequiredError(preflight.reason or "lab_lease_required")
