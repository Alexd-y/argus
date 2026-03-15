"""Schema definitions for `anomaly_interpretation` task."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from app.schemas.ai.common import (
    EvidenceBacked,
    EvidenceRef,
    ReconAiTask,
    StatementType,
    TaskRunMetadata,
    validate_meta_task,
)


class AnomalyClassification(StrEnum):
    FORGOTTEN_INFRA = "forgotten_infra"
    INTENTIONAL_PLACEHOLDER = "intentional_placeholder"
    CATCH_ALL = "catch_all"
    LEGACY_NAMING = "legacy_naming"
    PLATFORM_ALIAS = "platform_alias"


class AnomalyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=500)
    status: str = Field(min_length=1, max_length=20)
    suspicious_host: StrictBool
    catch_all_hint: StrictBool
    shared_with_root: StrictBool
    evidence_refs: list[EvidenceRef] = Field(min_length=1)


class AnomalyInterpretationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: TaskRunMetadata
    anomalies: list[AnomalyInput] = Field(default_factory=list, max_length=400)

    @model_validator(mode="after")
    def _validate_meta_task(self) -> AnomalyInterpretationInput:
        validate_meta_task(self.meta, ReconAiTask.ANOMALY_INTERPRETATION)
        return self


class AnomalyAssessment(EvidenceBacked):
    statement_type: Literal[StatementType.HYPOTHESIS] = StatementType.HYPOTHESIS
    host: str = Field(min_length=1, max_length=500)
    classification: AnomalyClassification
    recommendation: str = Field(min_length=1, max_length=2000)
    evidence_refs: list[EvidenceRef] = Field(min_length=1)


class AnomalyInterpretationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    anomalies: list[AnomalyAssessment] = Field(default_factory=list)


def build_anomaly_assessment(
    host: str,
    classification: AnomalyClassification,
    confidence: float,
    recommendation: str,
    evidence_refs: list[str],
) -> AnomalyAssessment:
    return AnomalyAssessment(
        statement_type=StatementType.HYPOTHESIS,
        host=host,
        classification=classification,
        confidence=confidence,
        recommendation=recommendation,
        evidence_refs=evidence_refs,
    )
