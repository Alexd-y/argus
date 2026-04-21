from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from src.schemas.ai.common import ThreatModelingAiTask


class GenericTaskInput(BaseModel):
    meta: dict[str, Any] = {}
    bundle: dict[str, Any] = {}


class GenericTaskOutput(BaseModel):
    pass


class CriticalAssetsOutput(BaseModel):
    assets: list[dict[str, Any]] = []


class TrustBoundariesOutput(BaseModel):
    boundaries: list[dict[str, Any]] = []


class AttackerProfilesOutput(BaseModel):
    profiles: list[dict[str, Any]] = []


class EntryPointsOutput(BaseModel):
    entry_points: list[dict[str, Any]] = []


class ApplicationFlowsOutput(BaseModel):
    flows: list[dict[str, Any]] = []


class ThreatScenariosOutput(BaseModel):
    scenarios: list[dict[str, Any]] = []


class ScenarioScoringOutput(BaseModel):
    scores: list[dict[str, Any]] = []


class TestingRoadmapOutput(BaseModel):
    items: list[dict[str, Any]] = []


class ReportSummaryOutput(BaseModel):
    executive_summary: str = ""


TM_TASK_INPUT_MODELS: dict[ThreatModelingAiTask, type[BaseModel]] = {
    ThreatModelingAiTask.CRITICAL_ASSETS: GenericTaskInput,
    ThreatModelingAiTask.TRUST_BOUNDARIES: GenericTaskInput,
    ThreatModelingAiTask.ATTACKER_PROFILES: GenericTaskInput,
    ThreatModelingAiTask.ENTRY_POINTS: GenericTaskInput,
    ThreatModelingAiTask.APPLICATION_FLOWS: GenericTaskInput,
    ThreatModelingAiTask.THREAT_SCENARIOS: GenericTaskInput,
    ThreatModelingAiTask.SCENARIO_SCORING: GenericTaskInput,
    ThreatModelingAiTask.TESTING_ROADMAP: GenericTaskInput,
    ThreatModelingAiTask.REPORT_SUMMARY: GenericTaskInput,
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
