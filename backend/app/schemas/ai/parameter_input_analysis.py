"""Schema definitions for `parameter_input_analysis` task."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.ai.common import (
    EvidenceBacked,
    EvidenceRef,
    ReconAiTask,
    StatementType,
    TaskRunMetadata,
    validate_meta_task,
)


class ParameterSource(StrEnum):
    QUERY = "query"
    FORM_INPUT = "form_input"
    PATH = "path"


class ParameterCategory(StrEnum):
    SEARCH = "search"
    FILTER = "filter"
    FILE = "file"
    CALLBACK = "callback"
    REDIRECT = "redirect"
    ID_STATE = "id_state"
    GENERAL = "general"


class ParameterInputRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    source: ParameterSource
    context_url: str = Field(min_length=1, max_length=2000)
    evidence_refs: list[EvidenceRef] = Field(min_length=1)


class ParameterInputAnalysisInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: TaskRunMetadata
    params: list[ParameterInputRecord] = Field(default_factory=list, max_length=400)

    @model_validator(mode="after")
    def _validate_meta_task(self) -> ParameterInputAnalysisInput:
        validate_meta_task(self.meta, ReconAiTask.PARAMETER_INPUT_ANALYSIS)
        return self


class ParameterOutput(EvidenceBacked):
    statement_type: Literal[StatementType.OBSERVATION] = StatementType.OBSERVATION
    name: str = Field(min_length=1, max_length=200)
    category: ParameterCategory
    context_url: str = Field(min_length=1, max_length=2000)


class ParameterInputAnalysisOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    params: list[ParameterOutput] = Field(default_factory=list)


def build_parameter_output(
    name: str,
    category: ParameterCategory,
    context_url: str,
    evidence_refs: list[str],
) -> ParameterOutput:
    return ParameterOutput(
        statement_type=StatementType.OBSERVATION,
        confidence=0.7,
        name=name,
        category=category,
        context_url=context_url,
        evidence_refs=evidence_refs,
    )
