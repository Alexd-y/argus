"""Schema definitions for Stage 3 readiness assessment."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.ai.common import EvidenceRef

Stage3ReadinessStatus = Literal[
    "ready_for_stage3",
    "partially_ready_for_stage3",
    "not_ready_for_stage3",
]

Stage3BlockingReason = Literal[
    "blocked_missing_stage1",
    "blocked_missing_stage2",
    "blocked_unlinked_stage_artifacts",
    "blocked_stage3_not_ready",
]

# Next-phase gate statuses (VA3UP-007) — used by next_phase_gate.json
NextPhaseGateBlockingStatus = Literal[
    "blocked_missing_stage1",
    "blocked_missing_stage2",
    "blocked_missing_stage3",
    "blocked_no_confirmed_findings",
    "blocked_insufficient_evidence",
    "blocked_unlinked_findings",
    "blocked_unresolved_contradictions",
    "ready_for_next_phase",
]


class Stage3ExecutionReadinessResult(BaseModel):
    """Result of Stage 3 dependency/readiness check (VA-001 execution gate)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ready: bool
    blocking_reason: Stage3BlockingReason | None = None
    status: Stage3ReadinessStatus
    missing_artifacts: list[str] = Field(default_factory=list, max_length=200)
    missing_evidence: list[str] = Field(default_factory=list, max_length=500)
    degraded_analysis_areas: list[str] = Field(default_factory=list, max_length=200)
    recommended_follow_up: list[str] = Field(default_factory=list, max_length=200)
    recon_dir: str | None = None


class CoverageScores(BaseModel):
    """Coverage scores for Stage 3 readiness dimensions."""

    model_config = ConfigDict(extra="forbid")

    route: float = Field(default=0.0, ge=0.0, le=1.0, description="Route discovery coverage")
    input_surface: float = Field(default=0.0, ge=0.0, le=1.0, description="Input surface mapping coverage")
    api_surface: float = Field(default=0.0, ge=0.0, le=1.0, description="API surface mapping coverage")
    content_anomaly: float = Field(default=0.0, ge=0.0, le=1.0, description="Content/anomaly analysis coverage")
    boundary_mapping: float = Field(default=0.0, ge=0.0, le=1.0, description="Boundary mapping coverage")


class Stage3ReadinessResult(BaseModel):
    """Result of Stage 3 readiness assessment."""

    model_config = ConfigDict(extra="forbid")

    status: Stage3ReadinessStatus
    missing_evidence: list[str] = Field(default_factory=list, max_length=500)
    unknowns: list[str] = Field(default_factory=list, max_length=500)
    recommended_follow_up: list[str] = Field(default_factory=list, max_length=200)
    coverage_scores: CoverageScores = Field(default_factory=CoverageScores)


ROUTE_CLASSIFICATION_CSV_COLUMNS: tuple[str, ...] = (
    "route",
    "host",
    "classification",
    "discovery_source",
    "evidence_ref",
)


class RouteClassificationRow(BaseModel):
    """Schema for a single row in route_classification.csv."""

    model_config = ConfigDict(extra="forbid")

    route: str = Field(min_length=1, max_length=2048)
    host: str = Field(min_length=1, max_length=512)
    classification: str = Field(min_length=1, max_length=128)
    discovery_source: str = Field(min_length=1, max_length=128)
    evidence_ref: EvidenceRef | None = Field(default=None)

    @model_validator(mode="before")
    @classmethod
    def _empty_evidence_ref_to_none(cls, data: object) -> object:
        if isinstance(data, dict) and data.get("evidence_ref") == "":
            return {**data, "evidence_ref": None}
        return data
