"""QUICK-009 — Quick metrics emit via helpers, whitelist + cardinality, fail-open."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from src.core import unified_ai_metrics as m
from src.quick import metrics as qmetrics
from src.quick.planner import QuickPlanner, QuickPlannerRequest, QuickPlannerTarget
from src.quick.schemas import (
    AssetFingerprint,
    QuickBudget,
    QuickProfileName,
    QuickScanConfig,
    SeverityFloor,
)

_SCAN_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_ASSET_ID = "99999999-8888-7777-6666-555555555555"


@pytest.fixture(autouse=True)
def _reset_metrics() -> None:
    m.reset_unified_ai_metrics()
    yield
    m.reset_unified_ai_metrics()


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


def test_quick_metric_alias_map_covers_catalogue() -> None:
    expected = {
        "quick_scan_duration_seconds",
        "quick_deadline_overrun_total",
        "quick_budget_used_ratio",
        "quick_tasks_total",
        "quick_assets_discovered_total",
        "quick_templates_selected_total",
        "quick_findings_total",
        "quick_validation_rate",
        "quick_false_positive_rate",
        "quick_coverage_ratio",
        "quick_plan_revisions_total",
        "quick_llm_calls_total",
        "quick_llm_latency_seconds",
        "quick_rag_latency_seconds",
        "quick_tool_failures_total",
    }
    assert expected == set(m.QUICK_METRIC_ALIAS_MAP.keys())
    assert all(name.startswith("argus_quick_") for name in m.QUICK_METRIC_ALIAS_MAP.values())
    assert "argus_quick_scan_duration_seconds" not in m.METRIC_ALIAS_MAP.values()


def test_record_helpers_increment_integer_mirrors() -> None:
    qmetrics.record_deadline_overrun()
    qmetrics.record_task(stage="test", status="succeeded", tool="nuclei")
    qmetrics.record_assets_discovered(amount=3)
    qmetrics.record_templates_selected(amount=5)
    qmetrics.record_finding(severity="high", verdict="confirmed")
    qmetrics.record_plan_revision()
    qmetrics.record_llm_call(model="qwythos", prompt="quick_planner_v1", status="ok", latency_seconds=0.2)
    qmetrics.record_tool_failure(tool="nuclei", reason="timeout")
    qmetrics.record_scan_duration(12.5)
    qmetrics.record_budget_used_ratio(0.4)
    qmetrics.record_validation_rate(0.8)
    qmetrics.record_false_positive_rate(0.1)
    qmetrics.record_coverage_ratio(1.0)
    qmetrics.record_rag_latency(0.05)

    assert m.get_quick_deadline_overrun_total() == 1
    assert m.get_quick_tasks_total() == 1
    assert m.get_quick_assets_discovered_total() == 3
    assert m.get_quick_templates_selected_total() == 5
    assert m.get_quick_findings_total() == 1
    assert m.get_quick_plan_revisions_total() == 1
    assert m.get_quick_llm_calls_total() == 1
    assert m.get_quick_tool_failures_total() == 1
    assert m.get_quick_last_ratio("argus_quick_coverage_ratio") == 1.0


def test_unknown_tool_collapses_to_other() -> None:
    qmetrics.record_task(stage="test", status="succeeded", tool="totally-unknown-scanner")
    assert m.get_quick_tasks_total() == 1
    series = m.get_quick_cardinality_series_count("argus_quick_tasks_total")
    assert series == 1


def test_cardinality_cap_fail_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(m, "_QUICK_CARDINALITY_LIMIT", 8)
    monkeypatch.setattr(m, "_whitelist_quick_label", lambda _label, value: str(value))
    for idx in range(20):
        qmetrics.record_tool_failure(tool=f"tool-{idx}", reason="error")
    assert m.get_quick_tool_failures_total() == 20
    assert m.get_quick_cardinality_series_count("argus_quick_tool_failures_total") <= 8


def test_metrics_fail_open_on_prometheus_error() -> None:
    broken = MagicMock()
    broken.labels.return_value.inc.side_effect = RuntimeError("boom")
    with (
        patch.object(m, "_PROM_COUNTERS", {"argus_quick_deadline_overrun_total": broken}),
        patch.object(m, "_PROM_INITIALIZED", True),
        patch.object(m, "_PROMETHEUS_AVAILABLE", True),
    ):
        assert qmetrics.record_deadline_overrun() == 1


def test_planner_emits_assets_and_tasks() -> None:
    request = QuickPlannerRequest(
        scan_id=_SCAN_ID,
        config=_config(),
        budget=_budget(),
        deadline_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
        fingerprints=(AssetFingerprint(asset_id=_ASSET_ID),),
        targets=(
            QuickPlannerTarget(
                target_ref="https://app.example/",
                asset_id=_ASSET_ID,
                in_scope=True,
            ),
        ),
        scope_allowed=True,
    )
    QuickPlanner().plan(request)
    assert m.get_quick_assets_discovered_total() >= 1
    assert m.get_quick_tasks_total() >= 0


def test_out_of_scope_plan_emits_zero_network_tasks() -> None:
    request = QuickPlannerRequest(
        scan_id=_SCAN_ID,
        config=_config(),
        budget=_budget(),
        deadline_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
        fingerprints=(AssetFingerprint(asset_id=_ASSET_ID),),
        targets=(
            QuickPlannerTarget(
                target_ref="https://evil.example/",
                asset_id=_ASSET_ID,
                in_scope=False,
            ),
        ),
        scope_allowed=False,
    )
    plan = QuickPlanner().plan(request)
    assert plan.tasks == ()
    assert m.get_quick_untracked_tool_executions() == 0


def test_admit_tracked_tool_rejects_untracked() -> None:
    assert qmetrics.admit_tracked_tool("nuclei", catalog_ids={"nuclei"}, planned_ids={"nuclei"}) is True
    assert qmetrics.admit_tracked_tool("sqlmap", catalog_ids={"nuclei"}) is False
    assert qmetrics.admit_tracked_tool("nuclei", catalog_ids={"nuclei"}, planned_ids={"httpx"}) is False
    assert m.get_quick_untracked_tool_executions() >= 2
