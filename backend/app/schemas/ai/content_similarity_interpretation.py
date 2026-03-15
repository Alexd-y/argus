"""Schema definitions for `content_similarity_interpretation` task."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from app.schemas.ai.common import (
    EvidenceBacked,
    EvidenceRef,
    ReconAiTask,
    StatementType,
    TaskRunMetadata,
    validate_meta_task,
)


class SimilarityInterpretation(StrEnum):
    SHARED_404_OR_PLATFORM_TEMPLATE = "shared_404_or_platform_template"
    UNIQUE_OR_SMALL_CLUSTER = "unique_or_small_cluster"
    SHARED_REDIRECT_BEHAVIOR = "shared_redirect_behavior"


class ContentClusterInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cluster_id: str = Field(min_length=1, max_length=200)
    host: str = Field(min_length=1, max_length=500)
    cluster_size: StrictInt = Field(ge=1, le=100000)
    template_hint: str = Field(min_length=1, max_length=100)
    evidence_ref: EvidenceRef


class RedirectClusterInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    redirect_cluster_id: str = Field(min_length=1, max_length=200)
    host: str = Field(min_length=1, max_length=500)
    redirect_target: str = Field(min_length=1, max_length=2000)
    evidence_ref: EvidenceRef


class ContentSimilarityInterpretationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: TaskRunMetadata
    content_clusters: list[ContentClusterInput] = Field(default_factory=list, max_length=400)
    redirect_clusters: list[RedirectClusterInput] = Field(default_factory=list, max_length=400)

    @model_validator(mode="after")
    def _validate_meta_task(self) -> ContentSimilarityInterpretationInput:
        validate_meta_task(self.meta, ReconAiTask.CONTENT_SIMILARITY_INTERPRETATION)
        return self


class ClusterInterpretation(EvidenceBacked):
    statement_type: Literal[StatementType.INFERENCE] = StatementType.INFERENCE
    cluster_id: str = Field(min_length=1, max_length=200)
    interpretation: SimilarityInterpretation


class ContentSimilarityInterpretationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=5000)
    clusters: list[ClusterInterpretation] = Field(default_factory=list)


def build_cluster_interpretation(
    cluster_id: str,
    interpretation: SimilarityInterpretation,
    confidence: float,
    evidence_refs: list[str],
) -> ClusterInterpretation:
    return ClusterInterpretation(
        statement_type=StatementType.INFERENCE,
        cluster_id=cluster_id,
        interpretation=interpretation,
        confidence=confidence,
        evidence_refs=evidence_refs,
    )
