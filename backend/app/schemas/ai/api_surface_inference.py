"""Schema definitions for `api_surface_inference` task."""

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


class ApiType(StrEnum):
    REST_LIKE = "rest_like"
    GRAPHQL = "graphql"
    JSON_ENDPOINT = "json_endpoint"


class AuthBoundaryHint(StrEnum):
    AUTH_RELATED = "auth_related"
    FRONTEND_TO_BACKEND = "frontend_to_backend"
    UNKNOWN = "unknown"


class ApiCandidateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=2000)
    source: str = Field(min_length=1, max_length=200)
    method_hint: str = Field(min_length=1, max_length=32)
    evidence_refs: list[EvidenceRef] = Field(min_length=1)


class ApiSurfaceInferenceInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: TaskRunMetadata
    api_candidates: list[ApiCandidateInput] = Field(default_factory=list, max_length=400)

    @model_validator(mode="after")
    def _validate_meta_task(self) -> ApiSurfaceInferenceInput:
        validate_meta_task(self.meta, ReconAiTask.API_SURFACE_INFERENCE)
        return self


class ApiSurfaceRecord(EvidenceBacked):
    statement_type: Literal[StatementType.INFERENCE] = StatementType.INFERENCE
    path: str = Field(min_length=1, max_length=2000)
    api_type: ApiType
    auth_boundary_hint: AuthBoundaryHint


class ApiSurfaceInferenceOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_surface: list[ApiSurfaceRecord] = Field(default_factory=list)


def build_api_surface_record(
    path: str,
    api_type: ApiType,
    auth_boundary_hint: AuthBoundaryHint,
    evidence_refs: list[str],
) -> ApiSurfaceRecord:
    return ApiSurfaceRecord(
        statement_type=StatementType.INFERENCE,
        confidence=0.72,
        path=path,
        api_type=api_type,
        auth_boundary_hint=auth_boundary_hint,
        evidence_refs=evidence_refs,
    )
