"""Schema definitions for `stage3_preparation_summary` task."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.ai.common import (
    EvidenceBacked,
    EvidenceRef,
    PriorityLevel,
    ReconAiTask,
    StatementType,
    TaskRunMetadata,
    validate_meta_task,
)
from app.schemas.recon.stage3_readiness import Stage3ReadinessResult


class Stage3PreparationSummaryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: TaskRunMetadata
    focus_hosts: list[str] = Field(default_factory=list, max_length=200)
    risk_hypotheses: list[str] = Field(default_factory=list, max_length=300)
    stage3_readiness: Stage3ReadinessResult

    @model_validator(mode="after")
    def _validate_meta_task(self) -> Stage3PreparationSummaryInput:
        validate_meta_task(self.meta, ReconAiTask.STAGE3_PREPARATION_SUMMARY)
        return self


class Stage3NextStep(EvidenceBacked):
    statement_type: Literal[StatementType.HYPOTHESIS] = StatementType.HYPOTHESIS
    step: str = Field(min_length=1, max_length=2000)
    priority: PriorityLevel
    evidence_refs: list[EvidenceRef] = Field(min_length=1)


class Stage3PreparationSummaryOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=5000)
    next_steps: list[Stage3NextStep] = Field(default_factory=list)


def build_stage3_next_step(
    step: str,
    priority: PriorityLevel,
    evidence_refs: list[str],
    confidence: float = 0.7,
) -> Stage3NextStep:
    return Stage3NextStep(
        statement_type=StatementType.HYPOTHESIS,
        step=step,
        priority=priority,
        confidence=confidence,
        evidence_refs=evidence_refs,
    )
