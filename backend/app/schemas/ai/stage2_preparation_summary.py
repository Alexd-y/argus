"""Schema definitions for `stage2_preparation_summary` task."""

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


class Stage2PreparationSummaryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: TaskRunMetadata
    focus_hosts: list[str] = Field(default_factory=list, max_length=200)
    risk_hypotheses: list[str] = Field(default_factory=list, max_length=300)

    @model_validator(mode="after")
    def _validate_meta_task(self) -> Stage2PreparationSummaryInput:
        validate_meta_task(self.meta, ReconAiTask.STAGE2_PREPARATION_SUMMARY)
        return self


class Stage2NextStep(EvidenceBacked):
    statement_type: Literal[StatementType.HYPOTHESIS] = StatementType.HYPOTHESIS
    step: str = Field(min_length=1, max_length=2000)
    priority: PriorityLevel
    evidence_refs: list[EvidenceRef] = Field(min_length=1)


class Stage2PreparationSummaryOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=5000)
    next_steps: list[Stage2NextStep] = Field(default_factory=list)


def build_stage2_next_step(
    step: str,
    priority: PriorityLevel,
    evidence_refs: list[str],
    confidence: float = 0.7,
) -> Stage2NextStep:
    return Stage2NextStep(
        statement_type=StatementType.HYPOTHESIS,
        step=step,
        priority=priority,
        confidence=confidence,
        evidence_refs=evidence_refs,
    )
