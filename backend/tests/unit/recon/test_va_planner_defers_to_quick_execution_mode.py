"""QUICK-003 — VA scan-mode planner defers to QuickPlanner when execution_mode=quick."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from src.execution_mode.mode import ExecutionMode
from src.quick.schemas import (
    QuickBudget,
    QuickProfileName,
    QuickScanConfig,
    QuickScanPlan,
    QuickTask,
    QuickTaskStage,
    QuickTaskStatus,
    SeverityFloor,
)
from src.recon.vulnerability_analysis.active_scan.planner import (
    _QUICK_TOOLS,
    plan_tools_by_scan_mode,
    quick_plan_to_va_steps,
)

_SCAN_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_TASK_ID = "11111111-2222-3333-4444-555555555555"
_TARGET = "https://app.example/"
_DEADLINE = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


def _budget() -> QuickBudget:
    return QuickBudget(
        wall_clock_budget_seconds=900,
        discovery_budget_seconds=180,
        fingerprint_budget_seconds=120,
        verification_budget_seconds=180,
        ai_budget_seconds=90,
        report_budget_seconds=90,
        request_budget=500,
        per_host_budget=50,
        concurrency_budget=4,
        reserve_for_validation_percent=20,
    )


def _config() -> QuickScanConfig:
    return QuickScanConfig(
        profile=QuickProfileName.BALANCED,
        wall_clock_budget_seconds=900,
        ai_budget_seconds=90,
        reserve_for_validation_percent=20,
        max_targets=10,
        max_urls_per_host=50,
        crawl_depth=2,
        severity_floor=SeverityFloor.MEDIUM,
    )


def _quick_plan(*tool_ids: str) -> QuickScanPlan:
    tasks = tuple(
        QuickTask(
            task_id=_TASK_ID if index == 0 else f"11111111-2222-3333-4444-55555555555{index}",
            stage=QuickTaskStage.TEST,
            target_ref=_TARGET,
            tool_id=tool_id,
            capability_id="web.application.cve.known_product",
            estimated_seconds=30,
            estimated_requests=20,
            priority_score=0.7,
            success_signal=("http-cve-nginx",),
            stop_conditions=("deadline_reached",),
            idempotency_key=f"{_SCAN_ID}:{tool_id}:{_TARGET}:digest:1",
            status=QuickTaskStatus.QUEUED,
        )
        for index, tool_id in enumerate(tool_ids)
    )
    return QuickScanPlan(
        scan_id=_SCAN_ID,
        profile=QuickProfileName.BALANCED,
        deadline_at=_DEADLINE,
        budget=_budget(),
        tasks=tasks,
        coverage_intent=(),
        plan_version=1,
        prompt_version="deterministic-v1",
        model_route="deterministic",
    )


def _patch_quick_plan(monkeypatch: pytest.MonkeyPatch, plan: QuickScanPlan) -> MagicMock:
    mock = MagicMock(return_value=plan)
    monkeypatch.setattr(
        "src.recon.vulnerability_analysis.active_scan.planner.plan_for_va_target",
        mock,
    )
    return mock


def test_execution_mode_quick_does_not_use_quick_tools_as_sole_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    historic_ids = {spec.tool_id for spec in _QUICK_TOOLS}
    assert historic_ids == {"nuclei", "nikto"}
    mock = _patch_quick_plan(monkeypatch, _quick_plan("nuclei", "testssl"))
    availability = MagicMock(return_value=True)
    monkeypatch.setattr(
        "src.recon.vulnerability_analysis.active_scan.planner.check_tool_available",
        availability,
    )

    steps = plan_tools_by_scan_mode(
        "quick",
        scan_options={"execution_mode": "quick"},
        target_url=_TARGET,
        execution_mode=ExecutionMode.QUICK,
    )

    mock.assert_called_once()
    assert mock.call_args.kwargs["target_url"] == _TARGET
    availability.assert_not_called()
    tool_ids = [step.tool_id for step in steps]
    assert tool_ids == ["nuclei", "testssl"]
    assert "nikto" not in tool_ids
    assert set(tool_ids) != historic_ids
    assert all(step.job_source == "quick_execution_mode" for step in steps)
    assert all(step.argv_override is None for step in steps)


def test_execution_mode_quick_wins_over_scan_depth_deep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock = _patch_quick_plan(monkeypatch, _quick_plan("nuclei"))
    steps = plan_tools_by_scan_mode(
        "deep",
        scan_options={"vulnerabilities": {"sqli_enabled": True}},
        target_url=_TARGET,
        execution_mode="quick",
    )
    mock.assert_called_once()
    tool_ids = {step.tool_id for step in steps}
    assert tool_ids == {"nuclei"}
    assert "sqlmap" not in tool_ids
    assert "nikto" not in tool_ids
    assert all(step.job_source == "quick_execution_mode" for step in steps)


def test_scan_depth_quick_without_execution_mode_keeps_historic_quick_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock = _patch_quick_plan(monkeypatch, _quick_plan("nuclei"))
    monkeypatch.setattr(
        "src.recon.vulnerability_analysis.active_scan.planner.check_tool_available",
        lambda binary, use_sandbox=False: True,
    )
    monkeypatch.setattr(
        "src.recon.vulnerability_analysis.active_scan.planner._resolve_tool_argv",
        lambda spec, target_url: [spec.binary, "-u", target_url],
    )
    steps = plan_tools_by_scan_mode("quick", target_url=_TARGET)
    mock.assert_not_called()
    tool_ids = {step.tool_id for step in steps}
    assert tool_ids == {spec.tool_id for spec in _QUICK_TOOLS}
    assert "nikto" in tool_ids
    assert all(step.job_source == "scan_mode_quick" for step in steps)
    assert all(step.argv_override is not None for step in steps)


def test_empty_target_in_quick_execution_mode_returns_no_steps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock = _patch_quick_plan(monkeypatch, _quick_plan("nuclei"))
    steps = plan_tools_by_scan_mode(
        "quick",
        target_url="   ",
        execution_mode=ExecutionMode.QUICK,
    )
    assert steps == []
    mock.assert_not_called()


def test_quick_plan_to_va_steps_drops_disallowed_tools() -> None:
    plan = _quick_plan("nuclei", "sqlmap", "hydra")
    steps = quick_plan_to_va_steps(plan)
    assert [step.tool_id for step in steps] == ["nuclei"]
    assert steps[0].job_source == "quick_execution_mode"
    assert steps[0].argv_override is None
    assert steps[0].extra_hints["template_ids"] == ["http-cve-nginx"]
