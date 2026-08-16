"""QUICK-001 — Quick must use production_evaluator, never LAB_ALLOW_ALL."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.execution_mode import (
    LAB_ALLOW_ALL,
    ExecutionMode,
    LabBoundaryVerifier,
    LabLeaseService,
    LabScopeManifest,
    evaluate_with_execution_mode,
)
from src.orchestration.execution_mode_context import (
    extract_execution_mode,
    is_lab_lease_active_from_options,
    preflight_phase_execution_mode,
    resolve_tool_policy,
    resolve_tool_policy_from_options,
)


def _manifest(**overrides):
    base = dict(
        tenant_id="t-1",
        engagement_id="e-1",
        cidrs=("10.90.0.0/16",),
        dns_suffixes=("lab.argus",),
        k8s_namespace="argus-lab-42",
        vm_network_ids=("labnet-42",),
        capture_full=True,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(hours=4),
        created_by="u-1",
    )
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


def test_evaluate_quick_does_not_return_lab_allow_all() -> None:
    sentinel = object()
    calls: list[object] = []

    def production_evaluator(ctx: object) -> object:
        calls.append(ctx)
        return sentinel

    result = evaluate_with_execution_mode(
        mode=ExecutionMode.QUICK,
        target="https://prod.example/",
        manifest=_manifest(),
        lease=_usable_lease(),
        tenant_id="t-1",
        engagement_id="e-1",
        production_evaluator=production_evaluator,
        production_context={"scan_id": "s-1"},
    )
    assert result is sentinel
    assert result is not LAB_ALLOW_ALL
    assert calls == [{"scan_id": "s-1"}]


def test_evaluate_quick_uses_production_evaluator() -> None:
    def production_evaluator(ctx: dict) -> dict:
        return {"path": "production", **ctx}

    result = evaluate_with_execution_mode(
        mode="quick",
        target="https://prod.example/",
        production_evaluator=production_evaluator,
        production_context={"ok": True},
    )
    assert result == {"path": "production", "ok": True}
    assert result is not LAB_ALLOW_ALL


def test_evaluate_production_shares_evaluator_path_with_quick() -> None:
    def production_evaluator(ctx: str) -> str:
        return f"eval:{ctx}"

    prod = evaluate_with_execution_mode(
        mode=ExecutionMode.PRODUCTION,
        target="https://prod.example/",
        production_evaluator=production_evaluator,
        production_context="p",
    )
    quick = evaluate_with_execution_mode(
        mode=ExecutionMode.QUICK,
        target="https://prod.example/",
        production_evaluator=production_evaluator,
        production_context="p",
    )
    assert prod == quick == "eval:p"


def test_evaluate_quick_requires_production_evaluator() -> None:
    with pytest.raises(ValueError, match="production_evaluator_required"):
        evaluate_with_execution_mode(
            mode=ExecutionMode.QUICK,
            target="https://prod.example/",
            production_context={},
        )


def test_evaluate_quick_requires_production_context() -> None:
    with pytest.raises(ValueError, match="production_context_required"):
        evaluate_with_execution_mode(
            mode=ExecutionMode.QUICK,
            target="https://prod.example/",
            production_evaluator=lambda ctx: ctx,
        )


def test_evaluate_unknown_mode_raises() -> None:
    with pytest.raises(ValueError, match="unsupported_execution_mode"):
        evaluate_with_execution_mode(
            mode="stealth",
            target="https://prod.example/",
            production_evaluator=lambda ctx: ctx,
            production_context={},
        )


def test_evaluate_lab_unrestricted_still_uses_lease_path() -> None:
    m = _manifest()
    decision = evaluate_with_execution_mode(
        mode=ExecutionMode.LAB_UNRESTRICTED,
        target="10.90.9.9",
        manifest=m,
        tenant_id="t-1",
        engagement_id="e-1",
        k8s_namespace="argus-lab-42",
        vm_network_id="labnet-42",
    )
    assert decision is LAB_ALLOW_ALL
    assert decision.allowed is True
    assert decision.requires_approval is False
    assert decision.reason == "verified_lab_unrestricted"


def test_evaluate_lab_usable_lease_returns_allow_all_without_evaluator() -> None:
    lease = _usable_lease()
    decision = evaluate_with_execution_mode(
        mode=ExecutionMode.LAB_UNRESTRICTED,
        target="10.90.2.2",
        lease=lease,
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert decision is LAB_ALLOW_ALL


def test_quick_preflight_lab_lease_active_false() -> None:
    preflight = preflight_phase_execution_mode(
        {"execution_mode": "quick"},
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert preflight.mode == "quick"
    assert preflight.lab_lease_active is False
    assert preflight.lab_lease_id is None
    assert preflight.reason == "quick_production_like"


def test_quick_preflight_ignores_embedded_lab_lease() -> None:
    lease = _usable_lease()
    preflight = preflight_phase_execution_mode(
        {
            "execution_mode": "quick",
            "lab_lease": lease.to_storage_dict(),
        },
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert preflight.lab_lease_active is False
    assert preflight.reason == "quick_production_like"
    assert is_lab_lease_active_from_options(
        {
            "execution_mode": "quick",
            "lab_lease": lease.to_storage_dict(),
        },
        tenant_id="t-1",
        engagement_id="e-1",
    ) is False


def test_extract_execution_mode_scan_depth_quick_stays_production() -> None:
    assert extract_execution_mode({"mode": "quick"}) is ExecutionMode.PRODUCTION
    assert extract_execution_mode({"execution_mode": "quick"}) is ExecutionMode.QUICK


def test_resolve_tool_policy_quick_never_sets_lab_lease_active() -> None:
    lease = _usable_lease()
    decision = resolve_tool_policy(
        "sqlmap",
        mode=ExecutionMode.QUICK,
        lease=lease,
        target="https://prod.example/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert decision.lab_lease_active is False
    assert decision.allowed is False
    assert decision.requires_approval is True


def test_resolve_tool_policy_from_options_quick_not_lab() -> None:
    lease = _usable_lease()
    decision = resolve_tool_policy_from_options(
        "nuclei",
        {
            "execution_mode": "quick",
            "lab_lease": lease.to_storage_dict(),
        },
        target="https://prod.example/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert decision.lab_lease_active is False
    assert decision.reason != "verified_lab_unrestricted"
