"""QUICK-006 — LLM JSON schema validation; invalid output is discarded."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src.quick.llm_schemas import (
    ASSET_FINGERPRINT_SCHEMA_ID,
    FINDING_TRIAGE_SCHEMA_ID,
    QUICK_SCAN_PLAN_SCHEMA_ID,
    LlmQuickScanPlan,
    LlmQuickTask,
    LlmSchemaError,
    apply_llm_tasks_to_plan,
    extract_json_object,
    parse_llm_critique,
    parse_llm_fingerprint,
    parse_llm_plan,
    parse_llm_report,
    parse_llm_triage,
    tool_id_is_catalog_safe,
)
from src.quick.schemas import (
    FindingTriageVerdict,
    QuickBudget,
    QuickCoverageRecord,
    QuickCoverageState,
    QuickProfileName,
    QuickScanPlan,
    QuickTask,
    QuickTaskStage,
    QuickTaskStatus,
    SeverityFloor,
)

_SCAN_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_TASK_ID = "11111111-2222-3333-4444-555555555555"
_ASSET_ID = "99999999-8888-7777-6666-555555555555"
_FINDING_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
_DEADLINE = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
_TARGET = "https://app.example/"
_CAPABILITY = "http.fingerprint"
_CATALOG = frozenset({"nuclei", "httpx", "whatweb"})


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


def _baseline_task(**overrides: object) -> QuickTask:
    base: dict[str, object] = dict(
        task_id=_TASK_ID,
        stage=QuickTaskStage.TEST,
        target_ref=_TARGET,
        tool_id="nuclei",
        capability_id=_CAPABILITY,
        estimated_seconds=30,
        estimated_requests=20,
        priority_score=0.5,
        idempotency_key="scan:task:nuclei:test",
        status=QuickTaskStatus.QUEUED,
    )
    base.update(overrides)
    return QuickTask(**base)  # type: ignore[arg-type]


def _baseline_plan(**overrides: object) -> QuickScanPlan:
    base: dict[str, object] = dict(
        scan_id=_SCAN_ID,
        profile=QuickProfileName.BALANCED,
        deadline_at=_DEADLINE,
        budget=_budget(),
        tasks=(_baseline_task(),),
        coverage_intent=(
            QuickCoverageRecord(
                asset_id=_ASSET_ID,
                capability_id=_CAPABILITY,
                state=QuickCoverageState.NOT_SCHEDULED,
                reason_code="not_scheduled_by_quick_profile",
            ),
        ),
        plan_version=1,
        prompt_version="deterministic-v1",
        model_route="deterministic",
    )
    base.update(overrides)
    return QuickScanPlan(**base)  # type: ignore[arg-type]


def _valid_plan_json(*, tool_id: str = "nuclei") -> str:
    return (
        '{"tasks":[{"stage":"test","target_ref":"'
        + _TARGET
        + '","tool_id":"'
        + tool_id
        + '","capability_id":"'
        + _CAPABILITY
        + '","estimated_seconds":12,"estimated_requests":3,'
        + '"priority_score":0.9}]}'
    )


def test_extract_json_object_strips_markdown_fence() -> None:
    payload = extract_json_object("```json\n" + _valid_plan_json() + "\n```")
    assert payload["tasks"][0]["tool_id"] == "nuclei"


def test_extract_json_object_rejects_empty_and_non_object() -> None:
    with pytest.raises(LlmSchemaError, match="empty_llm_output"):
        extract_json_object("   ")
    with pytest.raises(LlmSchemaError, match="llm_output_not_json_object"):
        extract_json_object("not-json")
    with pytest.raises(LlmSchemaError, match="llm_output_json_decode"):
        extract_json_object("{not json}")
    with pytest.raises(LlmSchemaError, match="llm_output_not_json_object"):
        extract_json_object("[1, 2]")


def test_parse_llm_plan_happy_path_catalog_tool() -> None:
    plan = parse_llm_plan(_valid_plan_json(), catalog_tool_ids=_CATALOG)
    assert plan.tasks[0].tool_id == "nuclei"
    assert plan.tasks[0].priority_score == 0.9


def test_parse_llm_plan_ignores_unknown_extra_keys() -> None:
    raw = (
        '{"tasks":[{"stage":"test","target_ref":"'
        + _TARGET
        + '","tool_id":"nuclei","capability_id":"'
        + _CAPABILITY
        + '","invented_field":true}],"mystery":1}'
    )
    plan = parse_llm_plan(raw, catalog_tool_ids=_CATALOG)
    assert isinstance(plan, LlmQuickScanPlan)
    assert not hasattr(plan.tasks[0], "invented_field")


def test_parse_llm_plan_rejects_tool_id_outside_catalog() -> None:
    with pytest.raises(LlmSchemaError, match="planner_unknown_tool_id:nikto") as exc:
        parse_llm_plan(_valid_plan_json(tool_id="nikto"), catalog_tool_ids=_CATALOG)
    assert exc.value.schema_id == QUICK_SCAN_PLAN_SCHEMA_ID


def test_parse_llm_plan_rejects_disallowed_tool_even_if_listed() -> None:
    catalog = frozenset({"nuclei", "sqlmap"})
    with pytest.raises(LlmSchemaError, match="planner_unknown_tool_id:sqlmap"):
        parse_llm_plan(_valid_plan_json(tool_id="sqlmap"), catalog_tool_ids=catalog)


def test_parse_llm_plan_rejects_invalid_schema_types() -> None:
    with pytest.raises(LlmSchemaError, match="planner_schema_invalid") as exc:
        parse_llm_plan(
            '{"tasks":[{"stage":"test","target_ref":"'
            + _TARGET
            + '","tool_id":"nuclei","capability_id":"'
            + _CAPABILITY
            + '","estimated_seconds":10.5}]}',
            catalog_tool_ids=_CATALOG,
        )
    assert exc.value.schema_id == QUICK_SCAN_PLAN_SCHEMA_ID


def test_tool_id_is_catalog_safe_rejects_paths_and_spaces() -> None:
    assert tool_id_is_catalog_safe("nuclei", _CATALOG) is True
    assert tool_id_is_catalog_safe("NUCLEI", _CATALOG) is True
    assert tool_id_is_catalog_safe("nuclei -t cves", _CATALOG) is False
    assert tool_id_is_catalog_safe("../nuclei", _CATALOG) is False
    assert tool_id_is_catalog_safe("", _CATALOG) is False


def test_parse_llm_fingerprint_happy_and_invalid() -> None:
    parsed = parse_llm_fingerprint(
        '{"asset_id":"'
        + _ASSET_ID
        + '","product":{"value":"nginx","confidence":0.8,"evidence_ids":["ev-1"]}}'
    )
    assert parsed.asset_id == _ASSET_ID
    assert parsed.product is not None
    assert parsed.product.value == "nginx"
    with pytest.raises(LlmSchemaError, match="fingerprint_schema_invalid") as exc:
        parse_llm_fingerprint("{}")
    assert exc.value.schema_id == ASSET_FINGERPRINT_SCHEMA_ID


def test_parse_llm_triage_citations_missing_becomes_hypothesis() -> None:
    triage = parse_llm_triage(
        '{"finding_id":"'
        + _FINDING_ID
        + '","verdict":"confirmed","severity":"high","confidence":0.95,'
        + '"fact_summary":"SQLi in login","citations":[]}'
    )
    assert triage.verdict is FindingTriageVerdict.HYPOTHESIS
    assert triage.confidence == 0.4
    assert triage.hypothesis_summary == "SQLi in login"


def test_parse_llm_triage_keeps_confirmed_when_cited() -> None:
    triage = parse_llm_triage(
        '{"finding_id":"'
        + _FINDING_ID
        + '","verdict":"confirmed","severity":"high","confidence":0.95,'
        + '"fact_summary":"SQLi in login","citations":["cite-abc1"]}'
    )
    assert triage.verdict is FindingTriageVerdict.CONFIRMED
    assert triage.confidence == 0.95
    assert triage.citations == ("cite-abc1",)


def test_parse_llm_triage_rejects_unknown_verdict() -> None:
    with pytest.raises(LlmSchemaError, match="triage_schema_invalid") as exc:
        parse_llm_triage(
            '{"finding_id":"'
            + _FINDING_ID
            + '","verdict":"exploited","severity":"high","confidence":0.9,'
            + '"fact_summary":"nope"}'
        )
    assert exc.value.schema_id == FINDING_TRIAGE_SCHEMA_ID


def test_parse_llm_critique_missing_citations_invalidates_evidence_link() -> None:
    critique = parse_llm_critique(
        '{"triage_id":"'
        + _FINDING_ID
        + '","evidence_to_weakness_valid":true,"citations":[]}'
    )
    assert critique.evidence_to_weakness_valid is False
    assert "missing_citations" in critique.false_positive_indicators


def test_parse_llm_critique_keeps_valid_when_cited() -> None:
    critique = parse_llm_critique(
        '{"triage_id":"'
        + _FINDING_ID
        + '","evidence_to_weakness_valid":true,"citations":["ev-9"]}'
    )
    assert critique.evidence_to_weakness_valid is True
    assert critique.citations == ("ev-9",)


def test_parse_llm_report_happy_path_and_invalid_profile() -> None:
    report = parse_llm_report(
        '{"scan_id":"'
        + _SCAN_ID
        + '","profile":"balanced","executive_summary":["finding-abc1 verified"],'
        + '"verified_finding_ids":["finding-abc1"],"recommended_next_mode":"lab_unrestricted"}'
    )
    assert report.profile is QuickProfileName.BALANCED
    assert report.recommended_next_mode == "lab_unrestricted"
    assert report.incompleteness_warning
    with pytest.raises(LlmSchemaError, match="report_schema_invalid"):
        parse_llm_report(
            '{"scan_id":"'
            + _SCAN_ID
            + '","profile":"stealth","executive_summary":["x"]}'
        )


def test_apply_llm_tasks_to_plan_reranks_without_inventing_tools() -> None:
    llm_plan = LlmQuickScanPlan(
        tasks=[
            LlmQuickTask(
                stage="test",
                target_ref=_TARGET,
                tool_id="nuclei",
                capability_id=_CAPABILITY,
                priority_score=0.99,
                estimated_seconds=8,
            ),
            LlmQuickTask(
                stage="test",
                target_ref=_TARGET,
                tool_id="httpx",
                capability_id=_CAPABILITY,
                priority_score=1.0,
            ),
        ]
    )
    merged = apply_llm_tasks_to_plan(
        _baseline_plan(), llm_plan, catalog_tool_ids=_CATALOG
    )
    assert [task.tool_id for task in merged.tasks] == ["nuclei"]
    assert merged.tasks[0].task_id == _TASK_ID
    assert merged.tasks[0].priority_score == 0.99
    assert merged.prompt_version == "quick_planner_v1"


def test_apply_llm_tasks_to_plan_raises_when_no_catalog_overlap() -> None:
    llm_plan = LlmQuickScanPlan(
        tasks=[
            LlmQuickTask(
                stage="test",
                target_ref="https://other.example/",
                tool_id="nuclei",
                capability_id=_CAPABILITY,
            )
        ]
    )
    with pytest.raises(LlmSchemaError, match="planner_no_catalog_overlap"):
        apply_llm_tasks_to_plan(_baseline_plan(), llm_plan, catalog_tool_ids=_CATALOG)
