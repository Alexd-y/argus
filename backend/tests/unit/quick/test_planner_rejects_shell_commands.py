"""QUICK-006 — planner must reject shell/CLI strings; fallback is deterministic."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from src.quick import llm_routes as quick_llm_routes
from src.quick.llm_routes import plan_with_ai
from src.quick.llm_schemas import (
    QUICK_SCAN_PLAN_SCHEMA_ID,
    LlmSchemaError,
    contains_shell_command,
    parse_llm_plan,
)
from src.quick.planner import QuickPlannerRequest, QuickPlannerTarget
from src.quick.schemas import (
    AssetFingerprint,
    FingerprintFact,
    QuickBudget,
    QuickCoverageRecord,
    QuickCoverageState,
    QuickProfileName,
    QuickScanConfig,
    QuickScanPlan,
    QuickTask,
    QuickTaskStage,
    QuickTaskStatus,
    SeverityFloor,
)

_SCAN_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_TASK_ID = "11111111-2222-3333-4444-555555555555"
_ASSET_ID = "99999999-8888-7777-6666-555555555555"
_DEADLINE = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
_TARGET = "https://app.example/"
_CAPABILITY = "http.fingerprint"
_CATALOG = frozenset({"nuclei", "httpx"})


@pytest.fixture(autouse=True)
def _clear_llm_caches() -> None:
    quick_llm_routes._RESPONSE_CACHE.clear()
    yield
    quick_llm_routes._RESPONSE_CACHE.clear()


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


def _config(*, enable_ai: bool = True) -> QuickScanConfig:
    return QuickScanConfig(
        profile=QuickProfileName.BALANCED,
        wall_clock_budget_seconds=900,
        ai_budget_seconds=90,
        reserve_for_validation_percent=20,
        max_targets=10,
        max_urls_per_host=50,
        crawl_depth=2,
        severity_floor=SeverityFloor.MEDIUM,
        enable_ai=enable_ai,
    )


def _baseline_plan() -> QuickScanPlan:
    return QuickScanPlan(
        scan_id=_SCAN_ID,
        profile=QuickProfileName.BALANCED,
        deadline_at=_DEADLINE,
        budget=_budget(),
        tasks=(
            QuickTask(
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
            ),
        ),
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


class _FixedPlanner:
    def plan(self, request: QuickPlannerRequest) -> QuickScanPlan:
        return _baseline_plan()


def _request(*, enable_ai: bool = True) -> QuickPlannerRequest:
    return QuickPlannerRequest(
        scan_id=_SCAN_ID,
        config=_config(enable_ai=enable_ai),
        budget=_budget(),
        deadline_at=_DEADLINE,
        fingerprints=(
            AssetFingerprint(
                asset_id=_ASSET_ID,
                protocol=FingerprintFact(value="https", confidence=1.0),
            ),
        ),
        targets=(
            QuickPlannerTarget(
                target_ref=_TARGET, asset_id=_ASSET_ID, in_scope=True
            ),
        ),
    )


@pytest.mark.parametrize(
    "payload",
    [
        "bash -c id",
        "powershell Get-Process",
        "docker exec sandbox nmap",
        "curl http://evil.example/",
        "rm -rf /tmp",
        "/bin/sh -c whoami",
        {"command": "nmap -sV 10.0.0.1"},
        {"argv": ["nuclei", "-t", "cves"]},
        {"shell": "pwsh"},
        {"tasks": [{"tool_id": "nuclei; wget http://x"}]},
    ],
)
def test_contains_shell_command_detects_cli(payload: object) -> None:
    assert contains_shell_command(payload) is True


def test_contains_shell_command_allows_plain_tool_id() -> None:
    assert contains_shell_command("nuclei") is False
    assert contains_shell_command({"tool_id": "httpx", "stage": "fingerprint"}) is False


def test_parse_llm_plan_rejects_command_field() -> None:
    raw = '{"tasks":[],"command":"nmap -sV target"}'
    with pytest.raises(LlmSchemaError, match="planner_shell_command_rejected") as exc:
        parse_llm_plan(raw, catalog_tool_ids=_CATALOG)
    assert exc.value.schema_id == QUICK_SCAN_PLAN_SCHEMA_ID


def test_parse_llm_plan_rejects_tool_id_with_flags() -> None:
    raw = (
        '{"tasks":[{"stage":"test","target_ref":"'
        + _TARGET
        + '","tool_id":"nuclei -t cves -u http://x","capability_id":"'
        + _CAPABILITY
        + '"}]}'
    )
    with pytest.raises(LlmSchemaError, match="planner_unknown_tool_id|planner_shell"):
        parse_llm_plan(raw, catalog_tool_ids=_CATALOG)


def test_parse_llm_plan_rejects_nested_curl_in_success_signal() -> None:
    raw = (
        '{"tasks":[{"stage":"test","target_ref":"'
        + _TARGET
        + '","tool_id":"nuclei","capability_id":"'
        + _CAPABILITY
        + '","success_signal":["curl http://oast.example/cb"]}]}'
    )
    with pytest.raises(LlmSchemaError, match="planner_shell_command_rejected"):
        parse_llm_plan(raw, catalog_tool_ids=_CATALOG)


@pytest.mark.asyncio
async def test_plan_with_ai_discards_shell_output_for_deterministic() -> None:
    baseline = _baseline_plan()
    with patch(
        "src.quick.llm_routes.call_llm_unified",
        new_callable=AsyncMock,
        return_value='{"command":"bash -c nmap -sV","tasks":[]}',
    ) as mock_llm:
        result = await plan_with_ai(
            _request(),
            planner=_FixedPlanner(),
            allowed_tool_ids=_CATALOG,
        )
    mock_llm.assert_awaited_once()
    assert result.used_ai is False
    assert result.fallback_reason == "schema_invalid"
    assert result.model_route == "deterministic"
    assert result.value.tasks == baseline.tasks
    assert "schema_invalid" in result.degraded
