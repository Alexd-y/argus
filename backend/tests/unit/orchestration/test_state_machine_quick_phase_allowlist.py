"""QUICK-004 — ScanStateMachine Quick allowlist: skip exploitation/fuzz/post-ex."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src.orchestration.handlers import run_exploit_attempt
from src.orchestration.phase_resume import (
    ResumeDecision,
    compute_resume_plan,
    format_resume_summary,
)
from src.orchestration.phases import PHASE_ORDER, ScanPhase
from src.orchestration.state_machine import (
    ScanContext,
    _apply_skipped_phase_to_ctx,
    _quick_phase_skip_reason,
)
from src.quick.disallowed import NOT_SCHEDULED_BY_QUICK_PROFILE
from src.quick.workflow import (
    QUICK_PHASE_ALLOWLIST,
    SKIPPED_BY_QUICK_PROFILE,
    skipped_phase_payload,
    skipped_phases_for_options,
)

_SCAN_ID = "ffffffff-0000-4000-8000-000000000004"
_QUICK = {"execution_mode": "quick"}
_PROD = {"execution_mode": "production"}


def test_resume_plan_marks_skipped_by_profile_not_failed() -> None:
    plan = compute_resume_plan(
        completed=set(),
        skipped_by_profile=skipped_phases_for_options(_QUICK),
    )
    for phase in SKIPPED_BY_QUICK_PROFILE:
        assert plan[phase] is ResumeDecision.SKIPPED_BY_PROFILE
    for phase in QUICK_PHASE_ALLOWLIST:
        assert plan[phase] is ResumeDecision.RUN_FRESH
    assert set(plan) == set(PHASE_ORDER)

    summary = format_resume_summary(plan)
    assert "SKIP-PROFILE" in summary
    assert "exploitation" in summary
    assert "quick_fuzz" in summary
    assert "post_exploitation" in summary


def test_resume_plan_profile_skip_wins_over_completed() -> None:
    plan = compute_resume_plan(
        completed={ScanPhase.EXPLOITATION, ScanPhase.RECON},
        skipped_by_profile={ScanPhase.EXPLOITATION},
    )
    assert plan[ScanPhase.EXPLOITATION] is ResumeDecision.SKIPPED_BY_PROFILE
    assert plan[ScanPhase.RECON] is ResumeDecision.SKIP


def test_resume_plan_production_runs_exploitation() -> None:
    plan = compute_resume_plan(
        completed=set(),
        skipped_by_profile=skipped_phases_for_options(_PROD),
    )
    assert plan[ScanPhase.EXPLOITATION] is ResumeDecision.RUN_FRESH
    assert plan[ScanPhase.QUICK_FUZZ] is ResumeDecision.RUN_FRESH
    assert plan[ScanPhase.POST_EXPLOITATION] is ResumeDecision.RUN_FRESH


@pytest.mark.parametrize(
    "phase",
    [
        ScanPhase.SOURCE_ANALYSIS,
        ScanPhase.QUICK_FUZZ,
        ScanPhase.EXPLOITATION,
        ScanPhase.POST_EXPLOITATION,
    ],
)
def test_quick_phase_skip_reason_is_not_scheduled_by_quick_profile(
    phase: ScanPhase,
) -> None:
    reason = _quick_phase_skip_reason(
        phase,
        scan_id=_SCAN_ID,
        options=_QUICK,
        resume_decision=ResumeDecision.SKIPPED_BY_PROFILE,
    )
    assert reason == NOT_SCHEDULED_BY_QUICK_PROFILE
    from_options = _quick_phase_skip_reason(
        phase,
        scan_id=_SCAN_ID,
        options=_QUICK,
        resume_decision=ResumeDecision.RUN_FRESH,
    )
    assert from_options == NOT_SCHEDULED_BY_QUICK_PROFILE


@pytest.mark.parametrize(
    "phase",
    [
        ScanPhase.RECON,
        ScanPhase.THREAT_MODELING,
        ScanPhase.VULN_ANALYSIS,
        ScanPhase.REPORTING,
    ],
)
def test_allowlisted_phases_are_not_skipped_by_profile(phase: ScanPhase) -> None:
    reason = _quick_phase_skip_reason(
        phase,
        scan_id=_SCAN_ID,
        options=_QUICK,
        resume_decision=ResumeDecision.RUN_FRESH,
    )
    assert reason is None


def test_deadline_skips_discovery_keeps_vuln_analysis_and_reporting() -> None:
    options = {
        "execution_mode": "quick",
        "deadline_at": datetime(2020, 1, 1, tzinfo=UTC),
    }
    assert (
        _quick_phase_skip_reason(
            ScanPhase.RECON,
            scan_id=_SCAN_ID,
            options=options,
            resume_decision=ResumeDecision.RUN_FRESH,
        )
        == "deadline_reached"
    )
    assert (
        _quick_phase_skip_reason(
            ScanPhase.THREAT_MODELING,
            scan_id=_SCAN_ID,
            options=options,
            resume_decision=ResumeDecision.RUN_FRESH,
        )
        == "deadline_reached"
    )
    assert (
        _quick_phase_skip_reason(
            ScanPhase.VULN_ANALYSIS,
            scan_id=_SCAN_ID,
            options=options,
            resume_decision=ResumeDecision.RUN_FRESH,
        )
        is None
    )
    assert (
        _quick_phase_skip_reason(
            ScanPhase.REPORTING,
            scan_id=_SCAN_ID,
            options=options,
            resume_decision=ResumeDecision.RUN_FRESH,
        )
        is None
    )


def test_production_mode_does_not_skip_via_quick_reason() -> None:
    assert (
        _quick_phase_skip_reason(
            ScanPhase.EXPLOITATION,
            scan_id=_SCAN_ID,
            options=_PROD,
            resume_decision=ResumeDecision.RUN_FRESH,
        )
        is None
    )


def test_apply_skipped_phase_does_not_mark_failed() -> None:
    ctx = ScanContext()
    payload = skipped_phase_payload(ScanPhase.EXPLOITATION)
    _apply_skipped_phase_to_ctx(ScanPhase.EXPLOITATION, ctx, payload, "https://app.example/")
    assert ctx.exploit_out is not None
    assert ctx.exploit_out.exploits == []
    assert ctx.exploit_out.evidence == []

    _apply_skipped_phase_to_ctx(
        ScanPhase.QUICK_FUZZ,
        ctx,
        skipped_phase_payload(ScanPhase.QUICK_FUZZ),
        "https://app.example/",
    )
    assert ctx.quick_fuzz_out is not None

    _apply_skipped_phase_to_ctx(
        ScanPhase.POST_EXPLOITATION,
        ctx,
        skipped_phase_payload(ScanPhase.POST_EXPLOITATION),
        "https://app.example/",
    )
    assert ctx.post_out is not None


@pytest.mark.asyncio
async def test_run_exploit_attempt_skips_sandbox_for_quick_profile() -> None:
    out = await run_exploit_attempt(
        [{"title": "SQL injection", "severity": "high"}],
        scan_id=_SCAN_ID,
        target="https://app.example/",
        scan_options={"execution_mode": "quick"},
    )
    assert out.exploits == []
    assert out.evidence == []
