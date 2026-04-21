from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class Stage3CriticalAsset(BaseModel):
    id: str
    name: str
    type: str = "observation"
    source: str = ""


class Stage3TrustBoundary(BaseModel):
    id: str
    name: str
    components: list[str] = []
    source: str = ""


class Stage3EntryPoint(BaseModel):
    id: str
    name: str
    component_id: str
    type: str = "hypothesis"
    source: str = ""


class Stage3ThreatScenario(BaseModel):
    id: str
    priority: str = "medium"
    entry_point_id: str
    attacker_profile_id: str
    description: str


class Stage3ApplicationFlow(BaseModel):
    id: str
    source: str
    sink: str
    data_type: str | None = None
    description: str | None = None


class PriorityHypothesis(BaseModel):
    id: str
    hypothesis_text: str
    priority: Any = "medium"
    confidence: float = 0.5
    related_asset_id: str | None = None
    source_artifact: str = ""


class AiTmPriorityHypotheses(BaseModel):
    hypotheses: list[PriorityHypothesis] = []


class ThreatModelUnified(BaseModel):
    critical_assets: list[Stage3CriticalAsset] = []
    trust_boundaries: list[Stage3TrustBoundary] = []
    entry_points: list[Stage3EntryPoint] = []
    attacker_profiles: list[Any] = []
    threat_scenarios: list[Stage3ThreatScenario] = []
