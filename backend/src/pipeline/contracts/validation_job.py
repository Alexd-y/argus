"""ValidationJob — typed unit dispatched into the verifier loop.

A ValidationJob is created by the AI Orchestrator's planner after the LLM emits a
:class:`ValidationPlanV1` (see ``src.orchestrator.schemas``). It carries the full
plan, the canary token used to correlate OAST callbacks, and the explicit list of
evidence kinds the verifier MUST collect to confirm the finding.

The plan is validated against the JSON Schema BEFORE construction (the loader
returns a :class:`ValidationPlanV1` Pydantic model); this contract therefore only
needs to enforce structural invariants, not the schema itself.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    model_validator,
)

from src.orchestrator.schemas.loader import ValidationPlanV1
from src.pipeline.contracts.finding_dto import EvidenceKind
from src.pipeline.contracts.phase_io import ScanPhase

_CANARY_RE = re.compile(r"^[0-9a-f]{16,128}$")


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class ValidationJob(BaseModel):
    """Typed unit for the verifier loop (Backlog/dev1_md §6 / §16.1).

    Invariants
    ----------
    * ``canary_token`` must be lowercase hex, 16-128 chars (matches
      ``src.oast.token.generate_canary_token`` output format).
    * ``evidence_required`` must contain at least one EvidenceKind so the verifier
      always has a deterministic completion criterion.
    * ``phase`` is fixed to one of the three phases that may legitimately request
      validation: vuln_analysis (low-risk validators), exploitation (gated),
      post_exploitation (impact proof).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    tenant_id: UUID
    scan_id: UUID
    finding_id: UUID
    phase: ScanPhase
    canary_token: StrictStr = Field(min_length=16, max_length=128)
    validation_plan: ValidationPlanV1
    evidence_required: list[EvidenceKind] = Field(min_length=1, max_length=16)
    correlation_id: StrictStr = Field(min_length=1, max_length=128)
    created_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if not _CANARY_RE.fullmatch(self.canary_token):
            raise ValueError(
                "canary_token must be lowercase hex, length 16-128 (got "
                f"{len(self.canary_token)} chars)"
            )
        if self.phase not in {
            ScanPhase.VULN_ANALYSIS,
            ScanPhase.EXPLOITATION,
            ScanPhase.POST_EXPLOITATION,
        }:
            raise ValueError(
                f"ValidationJob.phase={self.phase.value} is not a validation-eligible phase"
            )
        if len(set(self.evidence_required)) != len(self.evidence_required):
            raise ValueError("evidence_required must not contain duplicates")
        return self
