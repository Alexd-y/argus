"""Pydantic models for Stage 2 threat modeling artifacts."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictFloat

from app.schemas.ai.common import PriorityLevel
from app.schemas.threat_modeling.schemas import (
    ApplicationFlow,
    AttackerProfile,
    CriticalAsset,
    EntryPoint,
    ThreatModelInputBundle,
    TrustBoundary,
)


class Stage3CriticalAsset(BaseModel):
    """Critical asset from Stage 3 with provenance (observation vs hypothesis)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=500)
    type: Literal["observation", "hypothesis"] = Field(
        description="Provenance: observation (evidence-backed) or hypothesis (assumption)",
    )
    source: str = Field(min_length=1, max_length=500)


class Stage3TrustBoundary(BaseModel):
    """Trust boundary from Stage 3 with provenance."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=500)
    components: list[str] = Field(default_factory=list, max_length=100)
    source: str = Field(min_length=1, max_length=500)


class Stage3EntryPoint(BaseModel):
    """Entry point from Stage 3 with component linkage and provenance."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=500)
    component_id: str = Field(min_length=1, max_length=100)
    type: Literal["hypothesis"] = Field(
        description="Provenance: hypothesis-based entry point",
    )
    source: str = Field(min_length=1, max_length=500)


class Stage3ThreatScenario(BaseModel):
    """Threat scenario from Stage 3 with entry point and attacker linkage."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    priority: str = Field(min_length=1, max_length=50)
    entry_point_id: str = Field(min_length=1, max_length=100)
    attacker_profile_id: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=5000)


class ThreatModelUnified(BaseModel):
    """Unified threat model aggregating all Stage 3 artifacts."""

    model_config = ConfigDict(extra="forbid")

    critical_assets: list[Stage3CriticalAsset] = Field(default_factory=list, max_length=200)
    trust_boundaries: list[Stage3TrustBoundary] = Field(default_factory=list, max_length=100)
    entry_points: list[Stage3EntryPoint] = Field(default_factory=list, max_length=200)
    attacker_profiles: list[AttackerProfile] = Field(default_factory=list, max_length=50)
    threat_scenarios: list[Stage3ThreatScenario] = Field(default_factory=list, max_length=500)


class PriorityHypothesis(BaseModel):
    """Prioritized hypothesis with confidence and asset linkage."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    hypothesis_text: str = Field(min_length=1, max_length=5000)
    priority: PriorityLevel
    confidence: StrictFloat = Field(ge=0.0, le=1.0)
    related_asset_id: str | None = Field(default=None, max_length=100)
    source_artifact: str = Field(min_length=1, max_length=500)


class AiTmPriorityHypotheses(BaseModel):
    """Container for AI-generated prioritized hypotheses."""

    model_config = ConfigDict(extra="forbid")

    hypotheses: list[PriorityHypothesis] = Field(default_factory=list, max_length=500)


class Stage3ApplicationFlow(ApplicationFlow):
    """Stage 3 application flow — extends ApplicationFlow (id, source, sink, data_type, description)."""

    pass


class Stage2InputsArtifact(BaseModel):
    """Stage 2 inputs artifact: metadata + ThreatModelInputBundle-like structure for traceability."""

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(min_length=1, max_length=200)
    job_id: str = Field(min_length=1, max_length=200)
    engagement_id: str = Field(min_length=1, max_length=36)
    target_id: str | None = Field(default=None, max_length=36)
    bundle: ThreatModelInputBundle = Field(
        description="Threat model input bundle with recon artifacts",
    )
