"""Tests for threat modeling artifact generators."""

from __future__ import annotations

from app.schemas.ai.common import PriorityLevel
from app.schemas.threat_modeling.schemas import (
    AIReasoningTrace,
    ApplicationFlow,
    AttackerProfile,
    CriticalAsset,
    EntryPoint,
    MCPInvocationTrace,
    TestingRoadmapItem,
    ThreatModelArtifact,
    ThreatModelInputBundle,
    ThreatScenario,
    TrustBoundary,
)
from src.recon.threat_modeling.artifacts import (
    generate_ai_reasoning_trace_json,
    generate_all_artifacts,
    generate_critical_assets_csv,
    generate_mcp_trace_json,
    generate_threat_scenarios_csv,
)


def _minimal_bundle() -> ThreatModelInputBundle:
    return ThreatModelInputBundle(
        engagement_id="e1",
        target_id="t1",
        critical_assets=[
            CriticalAsset(id="ca1", name="User DB", asset_type="database", description="PII"),
        ],
        trust_boundaries=[
            TrustBoundary(id="tb1", name="DMZ", description="External", components=["web", "api"]),
        ],
        attacker_profiles=[
            AttackerProfile(id="ap1", name="Script kiddie", capability_level="low"),
        ],
        entry_points=[
            EntryPoint(id="ep1", name="Login API", entry_type="api", host_or_component="api.example.com"),
        ],
        application_flows=[
            ApplicationFlow(id="af1", source="Client", sink="API", data_type="JSON"),
        ],
        artifact_refs=["stage2_structured.json"],
    )


def _minimal_artifact() -> ThreatModelArtifact:
    return ThreatModelArtifact(
        run_id="r1",
        job_id="j1",
        scenarios=[
            ThreatScenario(
                id="ts1",
                title="SQLi via login",
                description="Attacker injects SQL",
                likelihood=0.7,
                impact=0.8,
                priority=PriorityLevel.HIGH,
                assumptions=["No WAF"],
                recommended_next_manual_checks=["Run sqlmap"],
            ),
        ],
        testing_roadmap=[
            TestingRoadmapItem(
                scenario_id="ts1",
                title="Test SQLi",
                priority=PriorityLevel.HIGH,
                recommended_actions=["Run sqlmap"],
            ),
        ],
    )


class TestGenerateAllArtifacts:
    """Test generate_all_artifacts returns all 12 artifact types."""

    def test_returns_twelve_artifacts(self) -> None:
        bundle = _minimal_bundle()
        artifact = _minimal_artifact()
        result = generate_all_artifacts(bundle, artifact)
        assert len(result) == 12
        assert "threat_model.md" in result
        assert "critical_assets.csv" in result
        assert "entry_points.csv" in result
        assert "attacker_profiles.csv" in result
        assert "trust_boundaries.csv" in result
        assert "trust_boundaries.md" in result
        assert "application_flows.md" in result
        assert "threat_scenarios.csv" in result
        assert "testing_priorities.md" in result
        assert "evidence_gaps.md" in result
        assert "ai_reasoning_trace.json" in result
        assert "mcp_trace.json" in result

    def test_threat_model_md_has_sections(self) -> None:
        bundle = _minimal_bundle()
        artifact = _minimal_artifact()
        result = generate_all_artifacts(bundle, artifact)
        md = result["threat_model.md"]
        assert "## Executive Summary" in md
        assert "## Recon Inputs Used" in md
        assert "## Critical Assets" in md
        assert "## Trust Boundaries" in md
        assert "## Threat Scenarios" in md
        assert "## Unknowns/Evidence Gaps" in md

    def test_critical_assets_csv_has_headers(self) -> None:
        bundle = _minimal_bundle()
        result = generate_critical_assets_csv(bundle)
        lines = result.strip().split("\n")
        assert lines[0] == "id,name,asset_type,description"
        assert "ca1" in lines[1]

    def test_threat_scenarios_csv_has_all_columns(self) -> None:
        artifact = _minimal_artifact()
        result = generate_threat_scenarios_csv(artifact)
        lines = result.strip().split("\n")
        assert "id" in lines[0]
        assert "recommended_next_manual_checks" in lines[0]
        assert "ts1" in lines[1]

    def test_ai_reasoning_trace_json_valid(self) -> None:
        artifact = ThreatModelArtifact(
            run_id="r1",
            job_id="j1",
            ai_reasoning_traces=[
                AIReasoningTrace(
                    step_id="s1",
                    step_type="inference",
                    description="Inferred asset",
                    input_refs=["bundle"],
                    output_refs=["out"],
                ),
            ],
        )
        result = generate_ai_reasoning_trace_json(artifact)
        assert "run_id" in result
        assert "traces" in result
        assert "s1" in result

    def test_mcp_trace_json_valid(self) -> None:
        artifact = ThreatModelArtifact(
            run_id="r1",
            job_id="j1",
            mcp_invocation_traces=[
                MCPInvocationTrace(
                    invocation_id="inv1",
                    tool_name="fetch",
                    input_summary={"url": "https://example.com"},
                    output_summary={"status": 200},
                ),
            ],
        )
        result = generate_mcp_trace_json(artifact)
        assert "run_id" in result
        assert "invocations" in result
        assert "fetch" in result

    def test_with_ai_results_report_summary(self) -> None:
        bundle = _minimal_bundle()
        artifact = _minimal_artifact()
        ai_results = {
            "report_summary": type("ReportSummaryOutput", (), {"executive_summary": "Summary for exec"})(),
        }
        result = generate_all_artifacts(bundle, artifact, ai_results=ai_results)
        md = result["threat_model.md"]
        assert "Summary for exec" in md
