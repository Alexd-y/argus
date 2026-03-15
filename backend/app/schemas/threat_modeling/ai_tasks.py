"""AI task input/output schemas for threat modeling — 9 tasks with evidence-backed outputs."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictFloat, model_validator

from app.schemas.ai.common import (
    EvidenceRef,
    PriorityLevel,
    StatementType,
    ThreatModelingAiTask,
    ThreatModelRunMetadata,
    validate_tm_meta_task,
)
from app.schemas.threat_modeling.schemas import (
    ApplicationFlow,
    AttackerProfile,
    CriticalAsset,
    EntryPoint,
    ThreatModelInputBundle,
    TrustBoundary,
)

# --- Shared evidence-backed mixin ---


class EvidenceBackedItem(BaseModel):
    """Mixin for threat modeling output items with evidence linkage."""

    model_config = ConfigDict(extra="forbid")

    statement_type: StatementType
    evidence_refs: list[EvidenceRef] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def _validate_evidence_requirements(self) -> EvidenceBackedItem:
        if (
            self.statement_type != StatementType.HYPOTHESIS
            and not self.evidence_refs
        ):
            raise ValueError(
                "evidence_refs required for non-hypothesis statements; "
                "use statement_type=hypothesis for assumptions",
            )
        return self


# --- Task 1: critical_assets ---


class CriticalAssetsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: ThreatModelRunMetadata
    bundle: ThreatModelInputBundle

    @model_validator(mode="after")
    def _validate_meta_task(self) -> CriticalAssetsInput:
        validate_tm_meta_task(self.meta, ThreatModelingAiTask.CRITICAL_ASSETS)
        return self


class CriticalAssetOutput(EvidenceBackedItem):
    """Critical asset with evidence linkage."""

    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=500)
    asset_type: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=2000)


class CriticalAssetsOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assets: list[CriticalAssetOutput] = Field(default_factory=list, max_length=200)


# --- Task 2: trust_boundaries ---


class TrustBoundariesInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: ThreatModelRunMetadata
    bundle: ThreatModelInputBundle

    @model_validator(mode="after")
    def _validate_meta_task(self) -> TrustBoundariesInput:
        validate_tm_meta_task(self.meta, ThreatModelingAiTask.TRUST_BOUNDARIES)
        return self


class TrustBoundaryOutput(EvidenceBackedItem):
    """Trust boundary with evidence linkage."""

    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=500)
    description: str | None = Field(default=None, max_length=2000)
    components: list[str] = Field(default_factory=list, max_length=100)


class TrustBoundariesOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    boundaries: list[TrustBoundaryOutput] = Field(default_factory=list, max_length=100)


# --- Task 3: attacker_profiles ---


class AttackerProfilesInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: ThreatModelRunMetadata
    bundle: ThreatModelInputBundle

    @model_validator(mode="after")
    def _validate_meta_task(self) -> AttackerProfilesInput:
        validate_tm_meta_task(self.meta, ThreatModelingAiTask.ATTACKER_PROFILES)
        return self


class AttackerProfileOutput(EvidenceBackedItem):
    """Attacker profile with evidence linkage."""

    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    capability_level: str = Field(min_length=1, max_length=50)
    description: str | None = Field(default=None, max_length=2000)


class AttackerProfilesOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profiles: list[AttackerProfileOutput] = Field(default_factory=list, max_length=50)


# --- Task 4: entry_points ---


class EntryPointsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: ThreatModelRunMetadata
    bundle: ThreatModelInputBundle

    @model_validator(mode="after")
    def _validate_meta_task(self) -> EntryPointsInput:
        validate_tm_meta_task(self.meta, ThreatModelingAiTask.ENTRY_POINTS)
        return self


class EntryPointOutput(EvidenceBackedItem):
    """Entry point with evidence linkage."""

    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=500)
    entry_type: str = Field(min_length=1, max_length=100)
    host_or_component: str | None = Field(default=None, max_length=500)
    description: str | None = Field(default=None, max_length=2000)


class EntryPointsOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entry_points: list[EntryPointOutput] = Field(default_factory=list, max_length=200)


# --- Task 5: application_flows ---


class ApplicationFlowsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: ThreatModelRunMetadata
    bundle: ThreatModelInputBundle

    @model_validator(mode="after")
    def _validate_meta_task(self) -> ApplicationFlowsInput:
        validate_tm_meta_task(self.meta, ThreatModelingAiTask.APPLICATION_FLOWS)
        return self


class ApplicationFlowOutput(EvidenceBackedItem):
    """Application flow with evidence linkage."""

    id: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=500)
    sink: str = Field(min_length=1, max_length=500)
    data_type: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=2000)


class ApplicationFlowsOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    flows: list[ApplicationFlowOutput] = Field(default_factory=list, max_length=200)


# --- Task 6: threat_scenarios (input includes assets, boundaries, profiles) ---


class ThreatScenariosInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: ThreatModelRunMetadata
    bundle: ThreatModelInputBundle
    assets: list[CriticalAsset] = Field(default_factory=list, max_length=200)
    boundaries: list[TrustBoundary] = Field(default_factory=list, max_length=100)
    profiles: list[AttackerProfile] = Field(default_factory=list, max_length=50)
    entry_points: list[EntryPoint] = Field(default_factory=list, max_length=200)
    flows: list[ApplicationFlow] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def _validate_meta_task(self) -> ThreatScenariosInput:
        validate_tm_meta_task(self.meta, ThreatModelingAiTask.THREAT_SCENARIOS)
        return self


class ThreatScenarioOutput(EvidenceBackedItem):
    """Threat scenario with evidence linkage."""

    id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    related_assets: list[str] = Field(default_factory=list, max_length=50)
    host_component: str | None = Field(default=None, max_length=500)
    entry_point: str | None = Field(default=None, max_length=200)
    attacker_profile: str | None = Field(default=None, max_length=200)
    trust_boundary: str | None = Field(default=None, max_length=200)
    description: str = Field(min_length=1, max_length=5000)
    likelihood: StrictFloat = Field(ge=0.0, le=1.0)
    impact: StrictFloat = Field(ge=0.0, le=1.0)
    priority: PriorityLevel
    assumptions: list[str] = Field(default_factory=list, max_length=50)
    recommended_next_manual_checks: list[str] = Field(default_factory=list, max_length=50)


class ThreatScenariosOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenarios: list[ThreatScenarioOutput] = Field(default_factory=list, max_length=500)


# --- Task 7: scenario_scoring ---


class ScenarioScoringInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: ThreatModelRunMetadata
    scenarios: list[ThreatScenarioOutput] = Field(default_factory=list, max_length=500)

    @model_validator(mode="after")
    def _validate_meta_task(self) -> ScenarioScoringInput:
        validate_tm_meta_task(self.meta, ThreatModelingAiTask.SCENARIO_SCORING)
        return self


class ScenarioScoreOutput(EvidenceBackedItem):
    """Scenario score with evidence linkage."""

    scenario_id: str = Field(min_length=1, max_length=100)
    likelihood: StrictFloat = Field(ge=0.0, le=1.0)
    impact: StrictFloat = Field(ge=0.0, le=1.0)
    risk_score: StrictFloat | None = Field(default=None, ge=0.0, le=1.0)


class ScenarioScoringOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scores: list[ScenarioScoreOutput] = Field(default_factory=list, max_length=500)


# --- Task 8: testing_roadmap ---


class TestingRoadmapInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: ThreatModelRunMetadata
    scenarios: list[ThreatScenarioOutput] = Field(default_factory=list, max_length=500)
    scores: list[ScenarioScoreOutput] = Field(default_factory=list, max_length=500)

    @model_validator(mode="after")
    def _validate_meta_task(self) -> TestingRoadmapInput:
        validate_tm_meta_task(self.meta, ThreatModelingAiTask.TESTING_ROADMAP)
        return self


class TestingRoadmapItemOutput(EvidenceBackedItem):
    """Testing roadmap item with evidence linkage."""

    scenario_id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    priority: PriorityLevel
    recommended_actions: list[str] = Field(default_factory=list, max_length=20)


class TestingRoadmapOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[TestingRoadmapItemOutput] = Field(default_factory=list, max_length=500)


# --- Task 9: report_summary ---


class ReportSummaryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: ThreatModelRunMetadata
    full_model: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_meta_task(self) -> ReportSummaryInput:
        validate_tm_meta_task(self.meta, ThreatModelingAiTask.REPORT_SUMMARY)
        return self


class ReportSummaryOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executive_summary: str = Field(min_length=1, max_length=10000)


# --- Input/Output model mapping for registry ---

TM_TASK_INPUT_MODELS: dict[ThreatModelingAiTask, type[BaseModel]] = {
    ThreatModelingAiTask.CRITICAL_ASSETS: CriticalAssetsInput,
    ThreatModelingAiTask.TRUST_BOUNDARIES: TrustBoundariesInput,
    ThreatModelingAiTask.ATTACKER_PROFILES: AttackerProfilesInput,
    ThreatModelingAiTask.ENTRY_POINTS: EntryPointsInput,
    ThreatModelingAiTask.APPLICATION_FLOWS: ApplicationFlowsInput,
    ThreatModelingAiTask.THREAT_SCENARIOS: ThreatScenariosInput,
    ThreatModelingAiTask.SCENARIO_SCORING: ScenarioScoringInput,
    ThreatModelingAiTask.TESTING_ROADMAP: TestingRoadmapInput,
    ThreatModelingAiTask.REPORT_SUMMARY: ReportSummaryInput,
}

TM_TASK_OUTPUT_MODELS: dict[ThreatModelingAiTask, type[BaseModel]] = {
    ThreatModelingAiTask.CRITICAL_ASSETS: CriticalAssetsOutput,
    ThreatModelingAiTask.TRUST_BOUNDARIES: TrustBoundariesOutput,
    ThreatModelingAiTask.ATTACKER_PROFILES: AttackerProfilesOutput,
    ThreatModelingAiTask.ENTRY_POINTS: EntryPointsOutput,
    ThreatModelingAiTask.APPLICATION_FLOWS: ApplicationFlowsOutput,
    ThreatModelingAiTask.THREAT_SCENARIOS: ThreatScenariosOutput,
    ThreatModelingAiTask.SCENARIO_SCORING: ScenarioScoringOutput,
    ThreatModelingAiTask.TESTING_ROADMAP: TestingRoadmapOutput,
    ThreatModelingAiTask.REPORT_SUMMARY: ReportSummaryOutput,
}
