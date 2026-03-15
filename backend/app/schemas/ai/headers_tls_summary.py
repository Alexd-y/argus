"""Schema definitions for `headers_tls_summary` task."""

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


class SecurityPosture(StrEnum):
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"


class HostHeaderTlsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=2000)
    header_score: str = Field(min_length=1, max_length=20)
    cookie_count: str = Field(min_length=1, max_length=20)
    cookie_secure: str = Field(min_length=1, max_length=20)
    evidence_refs: list[EvidenceRef] = Field(min_length=1)


class HeadersTlsSummaryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: TaskRunMetadata
    hosts: list[HostHeaderTlsInput] = Field(default_factory=list, max_length=400)

    @model_validator(mode="after")
    def _validate_meta_task(self) -> HeadersTlsSummaryInput:
        validate_meta_task(self.meta, ReconAiTask.HEADERS_TLS_SUMMARY)
        return self


class HostSecurityControl(EvidenceBacked):
    statement_type: Literal[StatementType.OBSERVATION] = StatementType.OBSERVATION
    host: str = Field(min_length=1, max_length=2000)
    posture: SecurityPosture


class HeadersTlsSummaryOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=5000)
    controls: list[HostSecurityControl] = Field(default_factory=list)


def build_host_security_control(
    host: str,
    posture: SecurityPosture,
    confidence: float,
    evidence_refs: list[str],
) -> HostSecurityControl:
    return HostSecurityControl(
        statement_type=StatementType.OBSERVATION,
        host=host,
        posture=posture,
        confidence=confidence,
        evidence_refs=evidence_refs,
    )
