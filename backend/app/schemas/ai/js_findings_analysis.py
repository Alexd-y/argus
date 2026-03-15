"""Schema definitions for `js_findings_analysis` task."""

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


class JsFindingCategory(StrEnum):
    CLIENT_ROUTE = "client_route"
    API_REF = "api_ref"
    HIDDEN_HINT = "hidden_hint"
    THIRD_PARTY = "third_party"
    FEATURE_FLAG = "feature_flag"
    AUTH_HINT = "auth_hint"
    CONFIG_HINT = "config_hint"
    FRONTEND_MARKER = "frontend_marker"


class JsScriptFindingInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: JsFindingCategory
    value: str = Field(min_length=1, max_length=2000)
    evidence_refs: list[EvidenceRef] = Field(min_length=1)


class JsFindingsAnalysisInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: TaskRunMetadata
    script_findings: list[JsScriptFindingInput] = Field(default_factory=list, max_length=400)

    @model_validator(mode="after")
    def _validate_meta_task(self) -> JsFindingsAnalysisInput:
        validate_meta_task(self.meta, ReconAiTask.JS_FINDINGS_ANALYSIS)
        return self


class JsFindingOutput(EvidenceBacked):
    statement_type: Literal[StatementType.OBSERVATION] = StatementType.OBSERVATION
    category: JsFindingCategory
    value: str = Field(min_length=1, max_length=2000)


class JsFindingsAnalysisOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=5000)
    findings: list[JsFindingOutput] = Field(default_factory=list)


def build_finding(
    category: JsFindingCategory,
    value: str,
    evidence_refs: list[str],
) -> JsFindingOutput:
    return JsFindingOutput(
        statement_type=StatementType.OBSERVATION,
        confidence=0.7,
        category=category,
        value=value,
        evidence_refs=evidence_refs,
    )
