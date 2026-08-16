"""QUICK-006 — enable_ai=false, schema fail, and Qwythos/WRB/small fallbacks."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.config import settings
from src.llm import facade, phase_routing
from src.llm.facade import (
    _CLOUD_FALLBACK_TASKS,
    _QUICK_QWYTHOS_TASKS,
    _QUICK_SMALL_TASKS,
    _QUICK_TASKS,
    _SCHEMA_BOUND_PROMPT_IDS,
    _execute_quick_route,
    _should_use_unified_gateway,
    _task_to_preferred_alias,
)
from src.llm.task_router import LLMTask
from src.quick import llm_routes as quick_llm_routes
from src.quick.llm_routes import (
    classify_fingerprint,
    critique_finding,
    generate_report,
    plan_with_ai,
    triage_finding,
)
from src.quick.planner import QuickPlannerRequest, QuickPlannerTarget
from src.quick.schemas import (
    AssetFingerprint,
    FindingTriage,
    FindingTriageVerdict,
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
_FINDING_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
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


def _config(*, enable_ai: bool = True, cloud_llm_allowed: bool = False) -> QuickScanConfig:
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
        cloud_llm_allowed=cloud_llm_allowed,
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
            QuickPlannerTarget(target_ref=_TARGET, asset_id=_ASSET_ID, in_scope=True),
        ),
    )


def _triage() -> FindingTriage:
    return FindingTriage(
        finding_id=_FINDING_ID,
        verdict=FindingTriageVerdict.NEEDS_VERIFICATION,
        severity=SeverityFloor.HIGH,
        confidence=0.6,
        fact_summary="possible SQLi",
        citations=("cite-ev01",),
    )


def _valid_plan_json() -> str:
    return (
        '{"tasks":[{"stage":"test","target_ref":"'
        + _TARGET
        + '","tool_id":"nuclei","capability_id":"'
        + _CAPABILITY
        + '","priority_score":0.91,"estimated_seconds":9}]}'
    )


class TestEnableAiFalseSkipsLlm:
    @pytest.mark.asyncio
    async def test_plan_with_ai_does_not_call_facade(self) -> None:
        with patch(
            "src.quick.llm_routes.call_llm_unified", new_callable=AsyncMock
        ) as mock_llm:
            result = await plan_with_ai(
                _request(enable_ai=False),
                planner=_FixedPlanner(),
                allowed_tool_ids=_CATALOG,
            )
        mock_llm.assert_not_called()
        assert result.used_ai is False
        assert result.fallback_reason == "enable_ai_false"
        assert result.model_route == "deterministic"
        assert result.value.tasks == _baseline_plan().tasks

    @pytest.mark.asyncio
    async def test_fingerprint_triage_critic_report_skip_llm(self) -> None:
        with patch(
            "src.quick.llm_routes.call_llm_unified", new_callable=AsyncMock
        ) as mock_llm:
            fp = await classify_fingerprint(
                {"product": "nginx"}, asset_id=_ASSET_ID, enable_ai=False
            )
            triage = await triage_finding(
                {"finding_id": _FINDING_ID, "title": "xss"}, enable_ai=False
            )
            critique = await critique_finding(_triage(), enable_ai=False)
            report = await generate_report(
                scan_id=_SCAN_ID, config=_config(enable_ai=False)
            )
        mock_llm.assert_not_called()
        assert fp.used_ai is False and fp.model_route == "rules"
        assert triage.used_ai is False and triage.model_route == "rules"
        assert critique.used_ai is False and critique.model_route == "needs_verification"
        assert report.used_ai is False and report.model_route == "template_renderer"


class TestSchemaFailDiscardsAi:
    @pytest.mark.asyncio
    async def test_invalid_planner_json_uses_deterministic_plan(self) -> None:
        with patch(
            "src.quick.llm_routes.call_llm_unified",
            new_callable=AsyncMock,
            return_value="I cannot produce JSON today.",
        ) as mock_llm:
            result = await plan_with_ai(
                _request(),
                planner=_FixedPlanner(),
                allowed_tool_ids=_CATALOG,
            )
        mock_llm.assert_awaited_once()
        assert result.used_ai is False
        assert result.fallback_reason == "schema_invalid"
        assert result.value.prompt_version == "deterministic-v1"
        assert result.value.tasks[0].tool_id == "nuclei"

    @pytest.mark.asyncio
    async def test_unknown_tool_id_discards_ai_plan(self) -> None:
        raw = (
            '{"tasks":[{"stage":"test","target_ref":"'
            + _TARGET
            + '","tool_id":"sqlmap","capability_id":"'
            + _CAPABILITY
            + '"}]}'
        )
        with patch(
            "src.quick.llm_routes.call_llm_unified",
            new_callable=AsyncMock,
            return_value=raw,
        ):
            result = await plan_with_ai(
                _request(),
                planner=_FixedPlanner(),
                allowed_tool_ids=_CATALOG,
            )
        assert result.used_ai is False
        assert result.fallback_reason == "schema_invalid"
        assert all(task.tool_id != "sqlmap" for task in result.value.tasks)

    @pytest.mark.asyncio
    async def test_valid_plan_is_applied_when_schema_ok(self) -> None:
        with patch(
            "src.quick.llm_routes.call_llm_unified",
            new_callable=AsyncMock,
            return_value=_valid_plan_json(),
        ):
            result = await plan_with_ai(
                _request(),
                planner=_FixedPlanner(),
                allowed_tool_ids=_CATALOG,
            )
        assert result.used_ai is True
        assert result.model_route == "qwythos-primary"
        assert result.value.tasks[0].priority_score == 0.91


class TestQwythosWrbSmallFallbacks:
    @pytest.mark.asyncio
    async def test_qwythos_unavailable_planner_falls_back_deterministic(self) -> None:
        with patch(
            "src.quick.llm_routes.call_llm_unified",
            new_callable=AsyncMock,
            side_effect=RuntimeError("qwythos_unavailable:quick_planner"),
        ):
            result = await plan_with_ai(
                _request(),
                planner=_FixedPlanner(),
                allowed_tool_ids=_CATALOG,
            )
        assert result.used_ai is False
        assert result.fallback_reason == "qwythos_unavailable"
        assert result.model_route == "deterministic"

    @pytest.mark.asyncio
    async def test_qwythos_unavailable_reporter_uses_template(self) -> None:
        with patch(
            "src.quick.llm_routes.call_llm_unified",
            new_callable=AsyncMock,
            side_effect=RuntimeError("qwythos_unavailable:quick_reporter"),
        ):
            result = await generate_report(
                scan_id=_SCAN_ID, config=_config(enable_ai=True)
            )
        assert result.used_ai is False
        assert result.fallback_reason == "qwythos_unavailable"
        assert result.model_route == "template_renderer"
        assert result.value.executive_summary

    @pytest.mark.asyncio
    async def test_wrb_unavailable_critic_needs_verification(self) -> None:
        with patch(
            "src.quick.llm_routes.call_llm_unified",
            new_callable=AsyncMock,
            side_effect=RuntimeError("wrb_unavailable:quick_critic"),
        ):
            result = await critique_finding(_triage(), enable_ai=True)
        assert result.used_ai is False
        assert result.fallback_reason == "wrb_unavailable"
        assert result.model_route == "needs_verification"
        assert result.value.evidence_to_weakness_valid is False
        assert "wrb_unavailable" in result.value.alternative_explanations

    @pytest.mark.asyncio
    async def test_small_model_unavailable_fingerprint_uses_rules(self) -> None:
        observations = {"product": "nginx", "evidence_ids": ["ev-1"]}
        with patch(
            "src.quick.llm_routes.call_llm_unified",
            new_callable=AsyncMock,
            side_effect=RuntimeError("small_model_unavailable:quick_fingerprint"),
        ):
            result = await classify_fingerprint(
                observations, asset_id=_ASSET_ID, enable_ai=True
            )
        assert result.used_ai is False
        assert result.fallback_reason == "small_model_unavailable"
        assert result.model_route == "rules"
        assert result.value.product is not None
        assert result.value.product.value == "nginx"

    @pytest.mark.asyncio
    async def test_small_model_unavailable_triage_uses_rules(self) -> None:
        with patch(
            "src.quick.llm_routes.call_llm_unified",
            new_callable=AsyncMock,
            side_effect=RuntimeError("small_model_unavailable:quick_triage"),
        ):
            result = await triage_finding(
                {
                    "finding_id": _FINDING_ID,
                    "title": "reflected xss",
                    "citations": ["cite-1"],
                },
                enable_ai=True,
            )
        assert result.used_ai is False
        assert result.fallback_reason == "small_model_unavailable"
        assert result.value.verdict is FindingTriageVerdict.NEEDS_VERIFICATION

    @pytest.mark.asyncio
    async def test_planner_timeout_does_not_block(self) -> None:
        with patch(
            "src.quick.llm_routes.call_llm_unified",
            new_callable=AsyncMock,
            side_effect=TimeoutError,
        ):
            result = await plan_with_ai(
                _request(),
                planner=_FixedPlanner(),
                allowed_tool_ids=_CATALOG,
            )
        assert result.used_ai is False
        assert result.fallback_reason == "ai_timeout"
        assert "ai_timeout" in result.degraded


class TestFacadeQuickRoutingNoLiveModels:
    def test_quick_tasks_are_not_cloud_fallback(self) -> None:
        for task in _QUICK_TASKS:
            assert task not in _CLOUD_FALLBACK_TASKS

    def test_quick_alias_and_prompt_bindings(self) -> None:
        assert _task_to_preferred_alias(LLMTask.QUICK_PLANNER) == "quick_planner"
        assert _task_to_preferred_alias(LLMTask.QUICK_FINGERPRINT) == "quick_triage"
        assert _task_to_preferred_alias(LLMTask.QUICK_TRIAGE) == "quick_triage"
        assert _task_to_preferred_alias(LLMTask.QUICK_CRITIC) == "quick_critic"
        assert _task_to_preferred_alias(LLMTask.QUICK_REPORTER) == "quick_reporter"
        assert _SCHEMA_BOUND_PROMPT_IDS[LLMTask.QUICK_PLANNER] == "quick_planner_v1"
        assert LLMTask.QUICK_PLANNER in _QUICK_QWYTHOS_TASKS
        assert LLMTask.QUICK_REPORTER in _QUICK_QWYTHOS_TASKS
        assert LLMTask.QUICK_FINGERPRINT in _QUICK_SMALL_TASKS
        assert LLMTask.QUICK_TRIAGE in _QUICK_SMALL_TASKS
        assert LLMTask.QUICK_CRITIC not in _QUICK_SMALL_TASKS

    def test_quick_tasks_skip_unified_gateway(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "argus_unified_llm_gateway", True)
        for task in _QUICK_TASKS:
            assert _should_use_unified_gateway(task, "quick_scan_plan_v1", True) is False

    @pytest.mark.asyncio
    async def test_qwythos_down_raises_for_planner(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("QWYTHOS_URL", raising=False)
        with pytest.raises(RuntimeError, match="qwythos_unavailable:quick_planner"):
            await _execute_quick_route(
                "sys",
                "user",
                LLMTask.QUICK_PLANNER,
                scan_id=_SCAN_ID,
                phase="quick_planner",
                scan_options={},
            )

    @pytest.mark.asyncio
    async def test_wrb_down_raises_for_critic(self, monkeypatch: pytest.MonkeyPatch) -> None:
        wrb = MagicMock()
        wrb.is_configured = False
        monkeypatch.setattr("src.llm.facade._get_wrb_adapter", lambda: wrb)
        with pytest.raises(RuntimeError, match="wrb_unavailable:quick_critic"):
            await _execute_quick_route(
                "sys",
                "user",
                LLMTask.QUICK_CRITIC,
                scan_id=_SCAN_ID,
                phase="quick_critic",
                scan_options={},
            )

    @pytest.mark.asyncio
    async def test_small_model_down_raises_for_fingerprint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GEMMA_LOCAL_URL", raising=False)
        monkeypatch.delenv("QWEN_LOCAL_URL", raising=False)
        with pytest.raises(RuntimeError, match="small_model_unavailable:quick_fingerprint"):
            await _execute_quick_route(
                "sys",
                "user",
                LLMTask.QUICK_FINGERPRINT,
                scan_id=_SCAN_ID,
                phase="quick_fingerprint",
                scan_options={},
            )

    @pytest.mark.asyncio
    async def test_qwythos_call_failure_planner_does_not_use_cloud(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("QWYTHOS_URL", "http://qwythos.invalid/v1")
        monkeypatch.setattr(facade, "_any_cloud_key_configured", lambda: True)
        with patch.object(
            facade, "_call_via_local_openai", new_callable=AsyncMock, side_effect=OSError
        ), patch.object(
            facade, "_call_via_task_router", new_callable=AsyncMock
        ) as cloud:
            with pytest.raises(RuntimeError, match="qwythos_unavailable"):
                await _execute_quick_route(
                    "sys",
                    "user",
                    LLMTask.QUICK_PLANNER,
                    scan_id=_SCAN_ID,
                    phase="quick_planner",
                    scan_options={"cloud_llm_allowed": True},
                )
        cloud.assert_not_called()

    @pytest.mark.asyncio
    async def test_quick_tasks_bypass_phase_routing_even_when_enabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ARGUS_PHASE_ROUTING_ENABLED", "true")
        phase_routing.reset_cache()
        monkeypatch.delenv("QWYTHOS_URL", raising=False)
        with pytest.raises(RuntimeError, match="qwythos_unavailable"):
            await facade.call_llm_unified(
                "sys",
                "user",
                task=LLMTask.QUICK_PLANNER,
                phase="quick_planner",
            )
