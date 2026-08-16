"""QUICK-009 — LAB unrestricted allow-all path is unregressed; Quick is not LAB."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from src.execution_mode import (
    LAB_ALLOW_ALL,
    ExecutionMode,
    LabBoundaryVerifier,
    LabLeaseService,
    LabScopeManifest,
    evaluate_with_execution_mode,
)
from src.execution_mode.mode import ALLOWED_EXECUTION_MODES, ModeContext
from src.orchestration.execution_mode_context import (
    is_lab_lease_active_from_options,
    preflight_phase_execution_mode,
    resolve_tool_policy,
)


def _manifest() -> LabScopeManifest:
    return LabScopeManifest(
        tenant_id="t-1",
        engagement_id="e-1",
        cidrs=("10.90.0.0/16",),
        dns_suffixes=("lab.argus",),
        k8s_namespace="argus-lab-42",
        vm_network_ids=("labnet-42",),
        capture_full=True,
        expires_at=datetime.now(tz=UTC) + timedelta(hours=4),
        created_by="u-1",
    )


def test_lab_unrestricted_still_allow_all() -> None:
    manifest = _manifest()
    verdict = LabBoundaryVerifier().verify(
        "10.90.2.2",
        manifest,
        tenant_id="t-1",
        engagement_id="e-1",
        k8s_namespace="argus-lab-42",
        vm_network_id="labnet-42",
    )
    assert verdict.allowed
    lease = LabLeaseService().issue(manifest, boundary_proof=verdict.proof)
    decision = evaluate_with_execution_mode(
        mode=ExecutionMode.LAB_UNRESTRICTED,
        target="10.90.2.2",
        lease=lease,
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert decision is LAB_ALLOW_ALL
    assert decision.allowed is True
    assert decision.requires_approval is False


def test_quick_is_not_lab_and_not_in_allow_all_set() -> None:
    assert ExecutionMode.QUICK.value == "quick"
    assert ExecutionMode.QUICK in ALLOWED_EXECUTION_MODES or ExecutionMode.QUICK.value in ALLOWED_EXECUTION_MODES
    ctx = ModeContext(
        tenant_id="t-1",
        engagement_id="e-1",
        mode=ExecutionMode.QUICK,
    )
    assert ctx.is_quick is True
    assert ctx.is_lab is False
    assert ctx.is_production is False

    def production_evaluator(payload: dict) -> dict:
        return {"path": "production", **payload}

    result = evaluate_with_execution_mode(
        mode=ExecutionMode.QUICK,
        target="https://app.example/",
        production_evaluator=production_evaluator,
        production_context={"scan_id": "s-1"},
    )
    assert result is not LAB_ALLOW_ALL
    assert result == {"path": "production", "scan_id": "s-1"}


def test_quick_preflight_never_activates_lab_lease() -> None:
    preflight = preflight_phase_execution_mode(
        {"execution_mode": "quick"},
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert preflight.lab_lease_active is False
    assert is_lab_lease_active_from_options({"execution_mode": "quick"}) is False
    decision = resolve_tool_policy(
        "nuclei",
        mode=ExecutionMode.QUICK,
        target="https://app.example/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert decision.lab_lease_active is False
    assert decision.reason != "verified_lab_unrestricted"
