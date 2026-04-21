"""Phase I/O contracts for the 6-phase ARGUS pipeline.

Defines:
  - :class:`ScanPhase`  — canonical enum of the six phases (recon → reporting).
  - :class:`PhaseInput` — typed envelope handed to a phase handler.
  - :class:`PhaseOutput` — typed envelope produced by a phase handler.
  - :class:`PhaseTransition` — value object that enforces legal phase transitions.

The legacy module ``src.orchestration.phases`` ships an equivalent ``ScanPhase`` enum
with identical string values; this duplicate exists in the new ``pipeline.contracts``
namespace as the source of truth for the v1 control-plane (Backlog/dev1_md §2/§16.1).
The string values must stay in lock-step so the two enums interoperate transparently.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    model_validator,
)


class ScanPhase(StrEnum):
    """Six phases of the ARGUS pentest pipeline (Backlog/dev1_md §2)."""

    RECON = "recon"
    THREAT_MODELING = "threat_modeling"
    VULN_ANALYSIS = "vuln_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


PHASE_ORDER: tuple[ScanPhase, ...] = (
    ScanPhase.RECON,
    ScanPhase.THREAT_MODELING,
    ScanPhase.VULN_ANALYSIS,
    ScanPhase.EXPLOITATION,
    ScanPhase.POST_EXPLOITATION,
    ScanPhase.REPORTING,
)

_PHASE_INDEX: dict[ScanPhase, int] = {phase: idx for idx, phase in enumerate(PHASE_ORDER)}


def _utcnow() -> datetime:
    """Return current UTC time with timezone info (Pydantic-friendly default factory)."""
    return datetime.now(tz=timezone.utc)


class PhaseInput(BaseModel):
    """Typed input envelope passed into a phase handler.

    ``payload`` is intentionally a generic ``dict[str, Any]`` because each phase has
    its own per-phase schema (see ``src.orchestration.phases``); strict per-phase
    typing happens inside the handler. The envelope itself enforces tenant/scan/phase
    identity and a correlation id for OTel tracing.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    scan_id: UUID
    phase: ScanPhase
    correlation_id: StrictStr = Field(min_length=1, max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)


class PhaseOutput(BaseModel):
    """Typed output envelope produced by a phase handler.

    ``next_phase`` is optional because the reporting phase has no successor. When set,
    it must satisfy :meth:`PhaseTransition.is_allowed` against ``phase``; the envelope
    enforces this in ``model_validator``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    scan_id: UUID
    phase: ScanPhase
    success: StrictBool
    payload: dict[str, Any] = Field(default_factory=dict)
    next_phase: ScanPhase | None = None
    error_code: StrictStr | None = Field(default=None, max_length=64)
    error_message: StrictStr | None = Field(default=None, max_length=2000)
    correlation_id: StrictStr = Field(min_length=1, max_length=128)
    created_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _validate_transition_and_error(self) -> Self:
        if self.next_phase is not None:
            transition = PhaseTransition(source=self.phase, destination=self.next_phase)
            if not transition.is_allowed():
                raise ValueError(
                    f"illegal phase transition {self.phase.value} -> {self.next_phase.value}"
                )
        if not self.success and self.error_code is None:
            raise ValueError("error_code is required when success is False")
        if self.success and (self.error_code is not None or self.error_message is not None):
            raise ValueError("error_code/error_message must be empty when success is True")
        return self


class PhaseTransition(BaseModel):
    """Value object representing a phase transition.

    Rules (Backlog/dev1_md §2; ARG-001 acceptance criteria):
      1. Forward transitions to the immediate next phase are always allowed.
      2. Skipping forward by more than one phase is allowed *only* when the destination
         is :attr:`ScanPhase.REPORTING` (terminal short-circuit on failure / cancellation).
      3. Self-transitions (idempotent re-entry) are allowed for retries.
      4. Backward transitions are always rejected — the pipeline is monotonic.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: ScanPhase
    destination: ScanPhase

    def is_allowed(self) -> bool:
        """Return True if this transition obeys the 6-phase ordering rules."""
        if self.source == self.destination:
            return True
        src_idx = _PHASE_INDEX[self.source]
        dst_idx = _PHASE_INDEX[self.destination]
        if dst_idx < src_idx:
            return False
        if dst_idx - src_idx == 1:
            return True
        return self.destination is ScanPhase.REPORTING
