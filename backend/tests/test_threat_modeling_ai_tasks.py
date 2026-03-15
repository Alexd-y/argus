"""Tests for threat modeling AI task schemas and registry."""

from __future__ import annotations

import pytest
from app.prompts.threat_modeling_prompts import (
    PROMPT_VERSION,
    get_threat_modeling_prompt,
)
from app.schemas.ai.common import (
    StatementType,
    ThreatModelingAiTask,
    build_tm_task_metadata,
)
from app.schemas.threat_modeling.ai_tasks import (
    CriticalAssetOutput,
    CriticalAssetsInput,
    ReportSummaryOutput,
    ScenarioScoreOutput,
    ThreatScenariosInput,
    TrustBoundariesOutput,
    TrustBoundaryOutput,
)
from app.schemas.threat_modeling.schemas import (
    CriticalAsset,
    ThreatModelInputBundle,
    TrustBoundary,
)
from src.recon.threat_modeling.ai_task_registry import (
    THREAT_MODELING_AI_TASKS,
    get_threat_modeling_ai_task_definitions,
    validate_threat_modeling_ai_payload,
)


class TestThreatModelingAiTaskRegistry:
    """Registry structure and validation."""

    def test_tasks_ordered(self) -> None:
        assert len(THREAT_MODELING_AI_TASKS) == 9
        assert THREAT_MODELING_AI_TASKS[0] == "critical_assets"
        assert THREAT_MODELING_AI_TASKS[-1] == "report_summary"

    def test_definitions_has_all_tasks(self) -> None:
        defs = get_threat_modeling_ai_task_definitions()
        assert set(defs.keys()) == set(THREAT_MODELING_AI_TASKS)
        for _task_name, d in defs.items():
            assert "input_schema" in d
            assert "expected_output_schema" in d
            assert "prompt_template" in d
            assert "persistence_mapping" in d

    def test_validate_critical_assets_payload(self) -> None:
        meta = {
            "task": "critical_assets",
            "run_id": "r1",
            "job_id": "j1",
            "trace_id": "t1",
        }
        bundle = {"engagement_id": "e1"}
        inp = {"meta": meta, "bundle": bundle}
        out = {
            "assets": [
                {
                    "id": "ca1",
                    "name": "API",
                    "asset_type": "service",
                    "description": "Main API",
                    "statement_type": "observation",
                    "evidence_refs": ["api_surface:path_/api"],
                },
            ],
        }
        r = validate_threat_modeling_ai_payload("critical_assets", inp, out)
        assert r["input"]["is_valid"]
        assert r["output"]["is_valid"]

    def test_validate_report_summary_payload(self) -> None:
        meta = {
            "task": "report_summary",
            "run_id": "r1",
            "job_id": "j1",
            "trace_id": "t1",
        }
        inp = {"meta": meta, "full_model": {"scenarios": [], "assets": []}}
        out = {"executive_summary": "The threat model identifies 3 critical assets."}
        r = validate_threat_modeling_ai_payload("report_summary", inp, out)
        assert r["input"]["is_valid"]
        assert r["output"]["is_valid"]

    def test_validate_rejects_unknown_task(self) -> None:
        with pytest.raises(ValueError, match="Unknown threat modeling AI task"):
            validate_threat_modeling_ai_payload("unknown", {}, {})


class TestCriticalAssetsSchemas:
    """Critical assets input/output validation."""

    def test_input_validates(self) -> None:
        meta = build_tm_task_metadata(
            ThreatModelingAiTask.CRITICAL_ASSETS, "r1", "j1",
        )
        bundle = ThreatModelInputBundle(engagement_id="e1")
        inp = CriticalAssetsInput(meta=meta, bundle=bundle)
        assert inp.meta.task == ThreatModelingAiTask.CRITICAL_ASSETS

    def test_output_observation_requires_evidence_refs(self) -> None:
        with pytest.raises(ValueError, match="evidence_refs required"):
            CriticalAssetOutput(
                id="ca1",
                name="DB",
                asset_type="database",
                description="Main DB",
                statement_type=StatementType.OBSERVATION,
                evidence_refs=[],
            )

    def test_output_hypothesis_allows_empty_evidence_refs(self) -> None:
        item = CriticalAssetOutput(
            id="ca1",
            name="DB",
            asset_type="database",
            description="Assumed critical",
            statement_type=StatementType.HYPOTHESIS,
            evidence_refs=[],
        )
        assert item.statement_type == StatementType.HYPOTHESIS
        assert item.evidence_refs == []

    def test_output_valid_with_evidence(self) -> None:
        item = CriticalAssetOutput(
            id="ca1",
            name="API",
            asset_type="service",
            description="Main API",
            statement_type=StatementType.EVIDENCE,
            evidence_refs=["endpoint_inventory:row_3"],
        )
        assert item.evidence_refs == ["endpoint_inventory:row_3"]


class TestTrustBoundariesSchemas:
    """Trust boundaries input/output validation."""

    def test_output_valid(self) -> None:
        out = TrustBoundariesOutput(
            boundaries=[
                TrustBoundaryOutput(
                    id="tb1",
                    name="DMZ",
                    description="Demilitarized zone",
                    components=["web", "api"],
                    statement_type=StatementType.INFERENCE,
                    evidence_refs=["live_hosts:host_1"],
                ),
            ],
        )
        assert len(out.boundaries) == 1
        assert out.boundaries[0].name == "DMZ"


class TestThreatScenariosInput:
    """Threat scenarios input with assets/boundaries/profiles."""

    def test_input_with_context(self) -> None:
        meta = build_tm_task_metadata(
            ThreatModelingAiTask.THREAT_SCENARIOS, "r1", "j1",
        )
        bundle = ThreatModelInputBundle(engagement_id="e1")
        assets = [CriticalAsset(id="ca1", name="DB", asset_type="database")]
        boundaries = [TrustBoundary(id="tb1", name="DMZ", components=[])]
        inp = ThreatScenariosInput(
            meta=meta,
            bundle=bundle,
            assets=assets,
            boundaries=boundaries,
            profiles=[],
        )
        assert len(inp.assets) == 1
        assert len(inp.boundaries) == 1


class TestScenarioScoringOutput:
    """Scenario scoring output validation."""

    def test_score_with_evidence(self) -> None:
        item = ScenarioScoreOutput(
            scenario_id="ts1",
            likelihood=0.7,
            impact=0.8,
            risk_score=0.56,
            statement_type=StatementType.INFERENCE,
            evidence_refs=["threat_scenario:ts1"],
        )
        assert item.scenario_id == "ts1"
        assert item.risk_score == 0.56


class TestReportSummaryOutput:
    """Report summary output validation."""

    def test_executive_summary_required(self) -> None:
        with pytest.raises(ValueError):
            ReportSummaryOutput(executive_summary="")

    def test_executive_summary_valid(self) -> None:
        out = ReportSummaryOutput(
            executive_summary="The threat model identifies critical assets and high-risk scenarios.",
        )
        assert len(out.executive_summary) > 0


class TestThreatModelingPrompts:
    """Prompt templates."""

    def test_prompt_version(self) -> None:
        assert PROMPT_VERSION == "1.0.0"

    def test_all_tasks_have_prompts(self) -> None:
        for task in THREAT_MODELING_AI_TASKS:
            prompt = get_threat_modeling_prompt(task)
            assert isinstance(prompt, str)
            assert len(prompt) > 50
            assert "evidence" in prompt.lower() or "Recon" in prompt
            assert "statement_type" in prompt or "hypothesis" in prompt

    def test_unknown_task_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown threat modeling task"):
            get_threat_modeling_prompt("unknown_task")
