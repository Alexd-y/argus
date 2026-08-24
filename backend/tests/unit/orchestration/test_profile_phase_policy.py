"""Profile-driven phase policy + durable checkpoint (R11)."""

from __future__ import annotations

from src.orchestration.phases import PHASE_ORDER, ScanPhase
from src.orchestration.profile_phase_policy import DESTRUCTIVE_PHASES, plan_phases
from src.orchestration.scan_checkpoint import (
    build_checkpoint,
    resume_context,
    ScanCheckpointV1,
)
from src.profiles.resolver import resolve_scan_profile


def test_quick_plan_skips_destructive_and_source_analysis():
    plan = plan_phases(resolve_scan_profile("quick"))
    assert plan.phase_skipping_allowed is True
    assert ScanPhase.EXPLOITATION not in plan.allowed_phases
    assert ScanPhase.POST_EXPLOITATION not in plan.allowed_phases
    assert ScanPhase.SOURCE_ANALYSIS not in plan.allowed_phases
    assert ScanPhase.RECON in plan.allowed_phases
    assert ScanPhase.REPORTING in plan.allowed_phases
    # every non-allowed phase has a skip reason
    for p in PHASE_ORDER:
        if p not in plan.allowed_phases:
            assert p in plan.skipped


def test_quick_does_not_require_lease():
    plan = plan_phases(resolve_scan_profile("quick"))
    assert plan.destructive_phases_require_lease is False
    assert plan.requires_lease_preflight(ScanPhase.EXPLOITATION) is False


def test_light_plan_full_web_no_destructive():
    plan = plan_phases(resolve_scan_profile("light"))
    assert ScanPhase.EXPLOITATION not in plan.allowed_phases
    assert ScanPhase.POST_EXPLOITATION not in plan.allowed_phases
    assert ScanPhase.VULN_ANALYSIS in plan.allowed_phases
    assert plan.skipped[ScanPhase.EXPLOITATION] == "out_of_scope"
    assert plan.destructive_phases_require_lease is False


def test_deep_plan_full_workflow_requires_lease_for_destructive():
    plan = plan_phases(resolve_scan_profile("deep"))
    assert set(plan.allowed_phases) == set(PHASE_ORDER)
    assert plan.destructive_phases_require_lease is True
    assert plan.capture_full is True
    for phase in DESTRUCTIVE_PHASES:
        assert plan.requires_lease_preflight(phase) is True
    assert plan.requires_lease_preflight(ScanPhase.RECON) is False


def test_checkpoint_roundtrip_and_resume_immutable_context():
    resolved = resolve_scan_profile("deep")
    cp = build_checkpoint(
        scan_id="s-1",
        tenant_id="t-1",
        resolved_profile=resolved,
        current_phase="exploitation",
        completed_phases=["recon", "vuln_analysis"],
        remaining_budget={"wall_clock_seconds": 1200},
        scope_hash="abc123",
        lease_state="active",
        tool_registry_version="t-v1",
        payload_registry_version="p-v1",
        prompt_registry_version="pr-v1",
        report_snapshot_status="pending",
    )
    # JSON round-trip
    raw = cp.model_dump(mode="json")
    restored = ScanCheckpointV1.model_validate(raw)
    assert restored.checkpoint_hash() == cp.checkpoint_hash()

    # Resume uses the frozen profile, identical to the original resolution.
    ctx = resume_context(restored)
    assert ctx.external_profile.value == "deep"
    assert ctx.execution_mode.value == "lab_unrestricted"
    assert ctx.requires_lab_lease is True
    assert ctx.to_public_dict() == resolved.to_public_dict()


def test_checkpoint_hash_ignores_updated_at():
    resolved = resolve_scan_profile("light")
    cp = build_checkpoint(
        scan_id="s", tenant_id="t", resolved_profile=resolved, current_phase="recon"
    )
    later = cp.model_copy(update={"updated_at": "2099-01-01T00:00:00Z"})
    assert later.checkpoint_hash() == cp.checkpoint_hash()


def test_checkpoint_hash_changes_with_phase():
    resolved = resolve_scan_profile("light")
    a = build_checkpoint(scan_id="s", tenant_id="t", resolved_profile=resolved, current_phase="recon")
    b = build_checkpoint(scan_id="s", tenant_id="t", resolved_profile=resolved, current_phase="reporting")
    assert a.checkpoint_hash() != b.checkpoint_hash()
