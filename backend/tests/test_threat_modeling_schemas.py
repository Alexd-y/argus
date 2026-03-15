"""Tests for threat modeling Pydantic schemas — CriticalAsset, TrustBoundary, AttackerProfile,
EntryPoint, ApplicationFlow, ThreatScenario, ThreatModelInputBundle, AIReasoningTrace,
MCPInvocationTrace, EvidenceRef validation.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from app.schemas.ai.common import PriorityLevel
from app.schemas.threat_modeling.schemas import (
    AIReasoningTrace,
    ApplicationFlow,
    AttackerProfile,
    CriticalAsset,
    EntryPoint,
    EvidenceLink,
    MCPInvocationTrace,
    ScenarioScore,
    ThreatModelArtifact,
    ThreatModelInputBundle,
    ThreatModelRun,
    ThreatScenario,
    TrustBoundary,
)
from app.schemas.threat_modeling.schemas import (
    TestingRoadmapItem as TestingRoadmapItemSchema,
)
from pydantic import ValidationError

# --- CriticalAsset ---


class TestCriticalAsset:
    """CriticalAsset schema validation."""

    def test_valid_minimal(self) -> None:
        asset = CriticalAsset(id="a1", name="User DB", asset_type="database")
        assert asset.id == "a1"
        assert asset.name == "User DB"
        assert asset.asset_type == "database"
        assert asset.description is None

    def test_valid_with_description(self) -> None:
        asset = CriticalAsset(
            id="a1",
            name="User DB",
            asset_type="database",
            description="Stores PII",
        )
        assert asset.description == "Stores PII"

    def test_empty_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            CriticalAsset(id="", name="x", asset_type="db")

    def test_empty_name_raises(self) -> None:
        with pytest.raises(ValidationError):
            CriticalAsset(id="a1", name="", asset_type="db")

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            CriticalAsset(id="a1", name="x", asset_type="db", extra="forbidden")


# --- TrustBoundary ---


class TestTrustBoundary:
    """TrustBoundary schema validation."""

    def test_valid_minimal(self) -> None:
        boundary = TrustBoundary(id="tb1", name="DMZ")
        assert boundary.id == "tb1"
        assert boundary.components == []

    def test_valid_with_components(self) -> None:
        boundary = TrustBoundary(
            id="tb1",
            name="DMZ",
            components=["web", "api", "db"],
        )
        assert boundary.components == ["web", "api", "db"]

    def test_empty_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            TrustBoundary(id="", name="x")

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            TrustBoundary(id="tb1", name="x", unknown=1)


# --- AttackerProfile ---


class TestAttackerProfile:
    """AttackerProfile schema validation."""

    def test_valid_minimal(self) -> None:
        profile = AttackerProfile(
            id="ap1",
            name="Script kiddie",
            capability_level="low",
        )
        assert profile.capability_level == "low"

    def test_valid_with_description(self) -> None:
        profile = AttackerProfile(
            id="ap1",
            name="APT",
            capability_level="nation_state",
            description="Advanced persistent threat",
        )
        assert profile.description == "Advanced persistent threat"

    def test_empty_capability_level_raises(self) -> None:
        with pytest.raises(ValidationError):
            AttackerProfile(id="ap1", name="x", capability_level="")


# --- EntryPoint ---


class TestEntryPoint:
    """EntryPoint schema validation."""

    def test_valid_minimal(self) -> None:
        ep = EntryPoint(id="ep1", name="Login API", entry_type="api")
        assert ep.entry_type == "api"
        assert ep.host_or_component is None

    def test_valid_full(self) -> None:
        ep = EntryPoint(
            id="ep1",
            name="Login API",
            entry_type="api",
            host_or_component="api.example.com",
            description="REST login endpoint",
        )
        assert ep.host_or_component == "api.example.com"

    def test_empty_entry_type_raises(self) -> None:
        with pytest.raises(ValidationError):
            EntryPoint(id="ep1", name="x", entry_type="")


# --- ApplicationFlow ---


class TestApplicationFlow:
    """ApplicationFlow schema validation."""

    def test_valid_minimal(self) -> None:
        flow = ApplicationFlow(id="f1", source="web", sink="api")
        assert flow.source == "web"
        assert flow.sink == "api"

    def test_valid_with_data_type(self) -> None:
        flow = ApplicationFlow(
            id="f1",
            source="web",
            sink="api",
            data_type="json",
        )
        assert flow.data_type == "json"

    def test_empty_source_raises(self) -> None:
        with pytest.raises(ValidationError):
            ApplicationFlow(id="f1", source="", sink="api")


# --- ScenarioScore ---


class TestScenarioScore:
    """ScenarioScore schema validation."""

    def test_valid(self) -> None:
        score = ScenarioScore(likelihood=0.5, impact=0.8, risk_score=0.4)
        assert score.likelihood == 0.5
        assert score.risk_score == 0.4

    def test_likelihood_out_of_range_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScenarioScore(likelihood=1.5, impact=0.5)
        with pytest.raises(ValidationError):
            ScenarioScore(likelihood=-0.1, impact=0.5)

    def test_impact_out_of_range_raises(self) -> None:
        with pytest.raises(ValidationError):
            ScenarioScore(likelihood=0.5, impact=2.0)


# --- EvidenceLink (EvidenceRef validation) ---


class TestEvidenceLink:
    """EvidenceLink schema — EvidenceRef validation."""

    def test_valid_evidence_ref(self) -> None:
        link = EvidenceLink(ref="artifact.csv:row1", label="Source")
        assert link.ref == "artifact.csv:row1"
        assert link.label == "Source"

    def test_valid_without_label(self) -> None:
        link = EvidenceLink(ref="js:app.js:/api/v1")
        assert link.label is None

    def test_evidence_ref_empty_raises(self) -> None:
        with pytest.raises(ValidationError):
            EvidenceLink(ref="")

    def test_evidence_ref_whitespace_only_raises(self) -> None:
        with pytest.raises(ValidationError):
            EvidenceLink(ref="   ")

    def test_evidence_ref_invalid_pattern_raises(self) -> None:
        with pytest.raises(ValidationError):
            EvidenceLink(ref="!invalid")  # must start with alphanumeric

    def test_evidence_ref_valid_patterns(self) -> None:
        valid_refs = [
            "a",
            "artifact.csv:row1",
            "js:app.js:/api/v1",
            "recon://artifacts/abc-123",
        ]
        for ref in valid_refs:
            link = EvidenceLink(ref=ref)
            assert link.ref == ref


# --- ThreatScenario (all required fields) ---


class TestThreatScenario:
    """ThreatScenario schema — all required fields and EvidenceRef validation."""

    def test_valid_minimal_required_fields(self) -> None:
        scenario = ThreatScenario(
            id="ts1",
            title="SQLi via login",
            description="Attacker injects SQL in login form",
            likelihood=0.7,
            impact=0.9,
            priority=PriorityLevel.HIGH,
        )
        assert scenario.id == "ts1"
        assert scenario.title == "SQLi via login"
        assert scenario.description == "Attacker injects SQL in login form"
        assert scenario.likelihood == 0.7
        assert scenario.impact == 0.9
        assert scenario.priority == PriorityLevel.HIGH
        assert scenario.related_assets == []
        assert scenario.recon_evidence_refs == []
        assert scenario.assumptions == []
        assert scenario.recommended_next_manual_checks == []

    def test_valid_full(self) -> None:
        scenario = ThreatScenario(
            id="ts1",
            title="SQLi via login",
            host_component="auth-service",
            entry_point="POST /login",
            attacker_profile="script_kiddie",
            trust_boundary="dmz-to-internal",
            description="Attacker injects SQL in login form",
            likelihood=0.7,
            impact=0.9,
            priority=PriorityLevel.HIGH,
            related_assets=["user_db"],
            recon_evidence_refs=["route_inventory.csv:/login"],
            assumptions=["Form uses raw SQL"],
            recommended_next_manual_checks=["Test with sqlmap"],
        )
        assert scenario.related_assets == ["user_db"]
        assert scenario.recon_evidence_refs == ["route_inventory.csv:/login"]
        assert scenario.assumptions == ["Form uses raw SQL"]
        assert scenario.recommended_next_manual_checks == ["Test with sqlmap"]

    def test_missing_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            ThreatScenario(
                title="x",
                description="x",
                likelihood=0.5,
                impact=0.5,
                priority=PriorityLevel.MEDIUM,
            )

    def test_missing_description_raises(self) -> None:
        with pytest.raises(ValidationError):
            ThreatScenario(
                id="ts1",
                title="x",
                description="",
                likelihood=0.5,
                impact=0.5,
                priority=PriorityLevel.MEDIUM,
            )

    def test_invalid_priority_raises(self) -> None:
        with pytest.raises(ValidationError):
            ThreatScenario(
                id="ts1",
                title="x",
                description="x",
                likelihood=0.5,
                impact=0.5,
                priority="invalid",
            )

    def test_likelihood_out_of_range_raises(self) -> None:
        with pytest.raises(ValidationError):
            ThreatScenario(
                id="ts1",
                title="x",
                description="x",
                likelihood=1.1,
                impact=0.5,
                priority=PriorityLevel.MEDIUM,
            )

    def test_recon_evidence_refs_invalid_raises(self) -> None:
        with pytest.raises(ValidationError):
            ThreatScenario(
                id="ts1",
                title="x",
                description="x",
                likelihood=0.5,
                impact=0.5,
                priority=PriorityLevel.MEDIUM,
                recon_evidence_refs=[""],
            )

    def test_recon_evidence_refs_valid(self) -> None:
        scenario = ThreatScenario(
            id="ts1",
            title="x",
            description="x",
            likelihood=0.5,
            impact=0.5,
            priority=PriorityLevel.MEDIUM,
            recon_evidence_refs=["artifact.csv:row1", "js:app.js"],
        )
        assert len(scenario.recon_evidence_refs) == 2

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            ThreatScenario(
                id="ts1",
                title="x",
                description="x",
                likelihood=0.5,
                impact=0.5,
                priority=PriorityLevel.MEDIUM,
                unknown_field=1,
            )


# --- ThreatModelInputBundle ---


class TestThreatModelInputBundle:
    """ThreatModelInputBundle schema validation."""

    def test_valid_minimal(self) -> None:
        bundle = ThreatModelInputBundle(engagement_id="e1")
        assert bundle.engagement_id == "e1"
        assert bundle.target_id is None
        assert bundle.critical_assets == []
        assert bundle.trust_boundaries == []
        assert bundle.attacker_profiles == []
        assert bundle.entry_points == []
        assert bundle.application_flows == []
        assert bundle.artifact_refs == []

    def test_valid_full(self) -> None:
        bundle = ThreatModelInputBundle(
            engagement_id="e1",
            target_id="t1",
            critical_assets=[CriticalAsset(id="a1", name="DB", asset_type="database")],
            trust_boundaries=[TrustBoundary(id="tb1", name="DMZ")],
            attacker_profiles=[
                AttackerProfile(id="ap1", name="APT", capability_level="high")
            ],
            entry_points=[EntryPoint(id="ep1", name="API", entry_type="api")],
            application_flows=[
                ApplicationFlow(id="f1", source="web", sink="api")
            ],
            artifact_refs=["artifact1.json"],
        )
        assert len(bundle.critical_assets) == 1
        assert len(bundle.trust_boundaries) == 1
        assert len(bundle.artifact_refs) == 1

    def test_empty_engagement_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            ThreatModelInputBundle(engagement_id="")

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            ThreatModelInputBundle(engagement_id="e1", unknown=1)


# --- AIReasoningTrace ---


class TestAIReasoningTrace:
    """AIReasoningTrace schema validation."""

    def test_valid_minimal(self) -> None:
        trace = AIReasoningTrace(
            step_id="s1",
            step_type="analyze",
            description="Analyzed entry points",
        )
        assert trace.step_id == "s1"
        assert trace.input_refs == []
        assert trace.output_refs == []
        assert trace.timestamp is None

    def test_valid_full(self) -> None:
        ts = datetime(2026, 3, 12, 10, 0, 0)
        trace = AIReasoningTrace(
            step_id="s1",
            step_type="analyze",
            description="Analyzed entry points",
            input_refs=["input1"],
            output_refs=["output1"],
            timestamp=ts,
        )
        assert trace.timestamp == ts

    def test_empty_step_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            AIReasoningTrace(step_id="", step_type="x", description="x")

    def test_empty_description_raises(self) -> None:
        with pytest.raises(ValidationError):
            AIReasoningTrace(step_id="s1", step_type="x", description="")


# --- MCPInvocationTrace ---


class TestMCPInvocationTrace:
    """MCPInvocationTrace schema validation."""

    def test_valid_minimal(self) -> None:
        trace = MCPInvocationTrace(
            invocation_id="inv1",
            tool_name="read_file",
        )
        assert trace.input_summary == {}
        assert trace.output_summary == {}
        assert trace.timestamp is None

    def test_valid_full(self) -> None:
        ts = datetime(2026, 3, 12, 10, 0, 0)
        trace = MCPInvocationTrace(
            invocation_id="inv1",
            tool_name="read_file",
            input_summary={"path": "/tmp/x"},
            output_summary={"lines": 10},
            timestamp=ts,
        )
        assert trace.input_summary == {"path": "/tmp/x"}
        assert trace.output_summary == {"lines": 10}
        assert trace.timestamp == ts

    def test_empty_invocation_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            MCPInvocationTrace(invocation_id="", tool_name="x")

    def test_empty_tool_name_raises(self) -> None:
        with pytest.raises(ValidationError):
            MCPInvocationTrace(invocation_id="inv1", tool_name="")


# --- TestingRoadmapItem ---


class TestTestingRoadmapItem:
    """TestingRoadmapItem schema validation."""

    def test_valid(self) -> None:
        item = TestingRoadmapItemSchema(
            scenario_id="ts1",
            title="Test SQLi",
            priority=PriorityLevel.HIGH,
        )
        assert item.evidence_refs == []
        assert item.recommended_actions == []

    def test_valid_with_evidence_refs(self) -> None:
        item = TestingRoadmapItemSchema(
            scenario_id="ts1",
            title="Test SQLi",
            priority=PriorityLevel.HIGH,
            evidence_refs=["artifact.csv:row1"],
            recommended_actions=["Run sqlmap"],
        )
        assert len(item.evidence_refs) == 1
        assert len(item.recommended_actions) == 1

    def test_invalid_evidence_ref_raises(self) -> None:
        with pytest.raises(ValidationError):
            TestingRoadmapItemSchema(
                scenario_id="ts1",
                title="x",
                priority=PriorityLevel.MEDIUM,
                evidence_refs=[""],
            )


# --- ThreatModelArtifact ---


class TestThreatModelArtifact:
    """ThreatModelArtifact schema validation."""

    def test_valid_minimal(self) -> None:
        artifact = ThreatModelArtifact(run_id="r1", job_id="j1")
        assert artifact.scenarios == []
        assert artifact.testing_roadmap == []
        assert artifact.ai_reasoning_traces == []
        assert artifact.mcp_invocation_traces == []
        assert artifact.evidence_links == []

    def test_valid_with_scenarios(self) -> None:
        scenario = ThreatScenario(
            id="ts1",
            title="x",
            description="x",
            likelihood=0.5,
            impact=0.5,
            priority=PriorityLevel.MEDIUM,
        )
        artifact = ThreatModelArtifact(
            run_id="r1",
            job_id="j1",
            scenarios=[scenario],
        )
        assert len(artifact.scenarios) == 1


# --- ThreatModelRun (Pydantic schema) ---


class TestThreatModelRun:
    """ThreatModelRun Pydantic schema validation."""

    def test_valid_minimal(self) -> None:
        run = ThreatModelRun(
            engagement_id="e1",
            status="pending",
            input_bundle_ref="s3://bucket/bundle.json",
            job_id="j1",
            run_id="r1",
        )
        assert run.target_id is None
        assert run.started_at is None
        assert run.completed_at is None
        assert run.artifact_refs == []

    def test_valid_full(self) -> None:
        ts = datetime(2026, 3, 12, 10, 0, 0)
        run = ThreatModelRun(
            engagement_id="e1",
            target_id="t1",
            status="completed",
            started_at=ts,
            completed_at=ts,
            input_bundle_ref="s3://bucket/bundle.json",
            artifact_refs=["artifact1.json"],
            job_id="j1",
            run_id="r1",
        )
        assert run.target_id == "t1"
        assert run.status == "completed"
        assert run.artifact_refs == ["artifact1.json"]

    def test_empty_engagement_id_raises(self) -> None:
        with pytest.raises(ValidationError):
            ThreatModelRun(
                engagement_id="",
                status="pending",
                input_bundle_ref="x",
                job_id="j1",
                run_id="r1",
            )

    def test_empty_input_bundle_ref_raises(self) -> None:
        with pytest.raises(ValidationError):
            ThreatModelRun(
                engagement_id="e1",
                status="pending",
                input_bundle_ref="",
                job_id="j1",
                run_id="r1",
            )
