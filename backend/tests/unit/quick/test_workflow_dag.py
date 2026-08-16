"""QUICK-004 — QuickWorkflow DAG, stage order, and phase skip payload."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src.orchestration.phases import PHASE_ORDER, ScanPhase
from src.quick.disallowed import NOT_SCHEDULED_BY_QUICK_PROFILE
from src.quick.schemas import (
    QuickBudget,
    QuickProfileName,
    QuickScanPlan,
    QuickTask,
    QuickTaskStage,
)
from src.quick.workflow import (
    PHASE_SKIP_REASONS,
    QUICK_PHASE_ALLOWLIST,
    SKIPPED_BY_QUICK_PROFILE,
    STAGE_ORDER,
    CyclicQuickWorkflowError,
    QuickWorkflow,
    is_quick_execution,
    phase_allowed,
    resolve_quick_plan,
    skip_reason_for_phase,
    skipped_phase_payload,
    skipped_phases_for_options,
)

_SCAN_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_TARGET = "https://app.example/"


def _task(
    task_id: str,
    stage: QuickTaskStage,
    *,
    depends_on: tuple[str, ...] = (),
    priority_score: float = 0.5,
    tool_id: str = "nuclei",
    capability_id: str = "http.fingerprint",
) -> QuickTask:
    return QuickTask(
        task_id=task_id,
        stage=stage,
        target_ref=_TARGET,
        tool_id=tool_id,
        capability_id=capability_id,
        estimated_seconds=10,
        estimated_requests=5,
        priority_score=priority_score,
        depends_on=depends_on,
        idempotency_key=f"{_SCAN_ID}:{tool_id}:{task_id}:none:1",
    )


def _ids(*suffixes: str) -> list[str]:
    return [f"10000000-0000-4000-8000-00000000000{s}" for s in suffixes]


def test_stage_order_is_discovery_through_report() -> None:
    assert STAGE_ORDER == (
        "discovery",
        "fingerprint",
        "test",
        "verify",
        "triage",
        "report",
    )
    assert tuple(item.value for item in QuickTaskStage) == STAGE_ORDER


def test_allowlist_and_skipped_partition_all_phases() -> None:
    all_phases = frozenset(PHASE_ORDER)
    assert QUICK_PHASE_ALLOWLIST.isdisjoint(SKIPPED_BY_QUICK_PROFILE)
    assert QUICK_PHASE_ALLOWLIST | SKIPPED_BY_QUICK_PROFILE == all_phases
    assert SKIPPED_BY_QUICK_PROFILE == frozenset(
        {
            ScanPhase.SOURCE_ANALYSIS,
            ScanPhase.QUICK_FUZZ,
            ScanPhase.EXPLOITATION,
            ScanPhase.POST_EXPLOITATION,
        }
    )


def test_skipped_phases_use_not_scheduled_by_quick_profile_never_failed() -> None:
    for phase in (
        ScanPhase.SOURCE_ANALYSIS,
        ScanPhase.QUICK_FUZZ,
        ScanPhase.EXPLOITATION,
        ScanPhase.POST_EXPLOITATION,
    ):
        assert skip_reason_for_phase(phase) == NOT_SCHEDULED_BY_QUICK_PROFILE
        assert PHASE_SKIP_REASONS[phase] == NOT_SCHEDULED_BY_QUICK_PROFILE
        payload = skipped_phase_payload(phase)
        assert payload["skipped"] is True
        assert payload["skip_reason"] == NOT_SCHEDULED_BY_QUICK_PROFILE
        assert payload["coverage_reason"] == NOT_SCHEDULED_BY_QUICK_PROFILE
        assert payload["coverage_reason_code"] == NOT_SCHEDULED_BY_QUICK_PROFILE
        assert payload["phase"] == phase.value
        assert "failed" not in payload.values()
        assert payload.get("status") != "failed"


def test_skipped_phase_payload_accepts_override_reason() -> None:
    payload = skipped_phase_payload(ScanPhase.RECON, "deadline_reached")
    assert payload["skip_reason"] == "deadline_reached"
    assert payload["coverage_reason_code"] == "deadline_reached"


def test_is_quick_execution_reads_mode_and_context() -> None:
    assert is_quick_execution({"execution_mode": "quick"}) is True
    assert is_quick_execution({"execution_mode_context": {"mode": "quick"}}) is True
    assert is_quick_execution({"execution_mode": "production"}) is False
    assert is_quick_execution({"execution_mode": "lab_unrestricted"}) is False
    assert is_quick_execution(None) is False
    assert is_quick_execution({}) is False
    assert is_quick_execution({"execution_mode": "not-a-mode"}) is False


def test_phase_allowed_and_skipped_phases_for_options() -> None:
    quick = {"execution_mode": "quick"}
    prod = {"execution_mode": "production"}
    assert skipped_phases_for_options(quick) == SKIPPED_BY_QUICK_PROFILE
    assert skipped_phases_for_options(prod) == frozenset()
    assert skipped_phases_for_options(None) == frozenset()
    assert phase_allowed(ScanPhase.RECON, quick) is True
    assert phase_allowed(ScanPhase.REPORTING, quick) is True
    assert phase_allowed(ScanPhase.EXPLOITATION, quick) is False
    assert phase_allowed(ScanPhase.QUICK_FUZZ, quick) is False
    assert phase_allowed(ScanPhase.POST_EXPLOITATION, quick) is False
    assert phase_allowed(ScanPhase.EXPLOITATION, prod) is True


def test_workflow_orders_by_stage_then_priority() -> None:
    disc, fp_low, fp_high, report = _ids("1", "2", "3", "4")
    workflow = QuickWorkflow(
        (
            _task(report, QuickTaskStage.REPORT, priority_score=0.99),
            _task(fp_low, QuickTaskStage.FINGERPRINT, priority_score=0.1, tool_id="httpx"),
            _task(fp_high, QuickTaskStage.FINGERPRINT, priority_score=0.9, tool_id="whatweb"),
            _task(disc, QuickTaskStage.DISCOVERY, priority_score=0.2),
        )
    )
    ordered = [task.task_id for task in workflow.tasks()]
    assert ordered == [disc, fp_high, fp_low, report]


def test_ready_tasks_wait_on_dependencies_and_honor_blocked() -> None:
    disc, fp, report = _ids("1", "2", "3")
    workflow = QuickWorkflow(
        (
            _task(disc, QuickTaskStage.DISCOVERY),
            _task(fp, QuickTaskStage.FINGERPRINT, depends_on=(disc,)),
            _task(report, QuickTaskStage.REPORT, depends_on=(fp,)),
        )
    )
    ready = workflow.ready_tasks(set())
    assert [task.task_id for task in ready] == [disc]

    after_disc = workflow.ready_tasks({disc})
    assert [task.task_id for task in after_disc] == [fp]

    blocked = workflow.ready_tasks({disc}, blocked_ids={fp})
    assert blocked == ()

    done = workflow.ready_tasks({disc, fp, report})
    assert done == ()


def test_unknown_dependency_raises() -> None:
    disc = _ids("1")[0]
    with pytest.raises(ValueError, match="unknown_quick_dependency"):
        QuickWorkflow(
            (
                _task(
                    disc,
                    QuickTaskStage.DISCOVERY,
                    depends_on=("20000000-0000-4000-8000-000000000099",),
                ),
            )
        )


def test_cyclic_dependency_raises_cyclic_quick_workflow_error() -> None:
    a, b = _ids("1", "2")
    with pytest.raises(CyclicQuickWorkflowError, match="cyclic_quick_workflow") as exc_info:
        QuickWorkflow(
            (
                _task(a, QuickTaskStage.DISCOVERY, depends_on=(b,)),
                _task(b, QuickTaskStage.FINGERPRINT, depends_on=(a,)),
            )
        )
    assert exc_info.value.code == "cyclic_quick_workflow"


def test_empty_workflow_is_acyclic() -> None:
    workflow = QuickWorkflow(())
    assert workflow.tasks() == ()
    assert workflow.ready_tasks(set()) == ()


def test_from_plan_and_resolve_stored_plan() -> None:
    disc = _ids("1")[0]
    task = _task(disc, QuickTaskStage.DISCOVERY)
    plan = QuickScanPlan(
        scan_id=_SCAN_ID,
        profile=QuickProfileName.BALANCED,
        deadline_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
        budget=QuickBudget(
            wall_clock_budget_seconds=900,
            discovery_budget_seconds=180,
            fingerprint_budget_seconds=120,
            verification_budget_seconds=240,
            ai_budget_seconds=90,
            report_budget_seconds=60,
            request_budget=500,
            per_host_budget=50,
            concurrency_budget=4,
            reserve_for_validation_percent=20,
        ),
        tasks=(task,),
        plan_version=1,
        prompt_version="quick-planner-v1",
        model_route="wrb",
    )
    workflow = QuickWorkflow.from_plan(plan)
    assert workflow.tasks()[0].task_id == disc

    resolved = resolve_quick_plan(
        scan_id=_SCAN_ID,
        target=_TARGET,
        options={"execution_mode": "quick", "quick_plan": plan},
    )
    assert resolved is plan

    as_dict = resolve_quick_plan(
        scan_id=_SCAN_ID,
        target=_TARGET,
        options={"execution_mode": "quick", "quick_plan": plan.model_dump(mode="python")},
    )
    assert as_dict is not None
    assert as_dict.scan_id == _SCAN_ID
    assert resolve_quick_plan(scan_id=_SCAN_ID, target=_TARGET, options={"execution_mode": "production"}) is None
    assert resolve_quick_plan(scan_id=_SCAN_ID, target="", options={"execution_mode": "quick"}) is None
