"""Scenario lifecycle state machine for executable playbooks (P2-PLAYBOOKS-002).

A *scenario* is one concrete instantiation of a playbook against a target.
Its status moves through a small, explicit state machine. Transitions are
validated centrally so no caller can drive a scenario into an inconsistent
state (e.g. CONFIRMED before RUNNING).

The full :class:`ScenarioPlanner`/executor arrives in P4; this module owns the
canonical status enum, the transition table, and the immutable
:class:`ScenarioState` value object that every layer records.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, Self

from pydantic import BaseModel, ConfigDict, Field, StrictStr, model_validator


class ScenarioStatus(StrEnum):
    """Lifecycle status of a planned / running scenario."""

    DISCOVERED = "discovered"
    PLANNED = "planned"
    SKIPPED_NOT_APPLICABLE = "skipped_not_applicable"
    WAITING_APPROVAL = "waiting_approval"
    RUNNING = "running"
    PARTIAL = "partial"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    CLEANUP_COMPLETE = "cleanup_complete"
    CLEANUP_FAILED = "cleanup_failed"


# Statuses whose ``reason`` field is mandatory (they encode a decision that an
# operator or auditor must be able to understand without extra context).
REASON_REQUIRED_STATUSES: Final[frozenset[ScenarioStatus]] = frozenset(
    {
        ScenarioStatus.SKIPPED_NOT_APPLICABLE,
        ScenarioStatus.REJECTED,
        ScenarioStatus.CLEANUP_FAILED,
    }
)

# Terminal statuses have no outgoing transitions.
TERMINAL_STATUSES: Final[frozenset[ScenarioStatus]] = frozenset(
    {
        ScenarioStatus.SKIPPED_NOT_APPLICABLE,
        ScenarioStatus.CLEANUP_COMPLETE,
        ScenarioStatus.CLEANUP_FAILED,
    }
)


# Allowed transitions. Absence of a key ⇒ terminal (no outgoing edges).
_ALLOWED_TRANSITIONS: Final[dict[ScenarioStatus, frozenset[ScenarioStatus]]] = {
    ScenarioStatus.DISCOVERED: frozenset(
        {ScenarioStatus.PLANNED, ScenarioStatus.SKIPPED_NOT_APPLICABLE}
    ),
    ScenarioStatus.PLANNED: frozenset(
        {
            ScenarioStatus.WAITING_APPROVAL,
            ScenarioStatus.RUNNING,
            ScenarioStatus.SKIPPED_NOT_APPLICABLE,
        }
    ),
    ScenarioStatus.WAITING_APPROVAL: frozenset(
        {
            ScenarioStatus.RUNNING,
            ScenarioStatus.REJECTED,
            ScenarioStatus.SKIPPED_NOT_APPLICABLE,
        }
    ),
    ScenarioStatus.RUNNING: frozenset(
        {
            ScenarioStatus.PARTIAL,
            ScenarioStatus.CONFIRMED,
            ScenarioStatus.REJECTED,
            ScenarioStatus.CLEANUP_COMPLETE,
            ScenarioStatus.CLEANUP_FAILED,
        }
    ),
    ScenarioStatus.PARTIAL: frozenset(
        {
            ScenarioStatus.RUNNING,
            ScenarioStatus.CONFIRMED,
            ScenarioStatus.REJECTED,
            ScenarioStatus.CLEANUP_COMPLETE,
            ScenarioStatus.CLEANUP_FAILED,
        }
    ),
    ScenarioStatus.CONFIRMED: frozenset(
        {ScenarioStatus.CLEANUP_COMPLETE, ScenarioStatus.CLEANUP_FAILED}
    ),
    ScenarioStatus.REJECTED: frozenset(
        {ScenarioStatus.CLEANUP_COMPLETE, ScenarioStatus.CLEANUP_FAILED}
    ),
}


class InvalidTransitionError(ValueError):
    """Raised when a scenario status transition is not permitted."""

    def __init__(self, current: ScenarioStatus, target: ScenarioStatus) -> None:
        super().__init__(f"illegal scenario transition {current.value!r} -> {target.value!r}")
        self.current = current
        self.target = target


def allowed_transitions(current: ScenarioStatus) -> frozenset[ScenarioStatus]:
    """Return the set of statuses reachable in one step from ``current``."""
    return _ALLOWED_TRANSITIONS.get(current, frozenset())


def can_transition(current: ScenarioStatus, target: ScenarioStatus) -> bool:
    """Return ``True`` if ``current`` may transition directly to ``target``."""
    return target in allowed_transitions(current)


def validate_transition(current: ScenarioStatus, target: ScenarioStatus) -> None:
    """Raise :class:`InvalidTransitionError` if the transition is not allowed."""
    if not can_transition(current, target):
        raise InvalidTransitionError(current, target)


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class ScenarioState(BaseModel):
    """Immutable snapshot of a scenario's lifecycle state.

    ``reason`` is mandatory for :data:`REASON_REQUIRED_STATUSES` so a skip /
    rejection / cleanup failure always carries an explanation for auditors.
    Transition to a new state via :meth:`transition`, which validates the edge.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: ScenarioStatus
    reason: StrictStr | None = Field(default=None, max_length=2000)
    updated_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.status in REASON_REQUIRED_STATUSES:
            if self.reason is None or not self.reason.strip():
                raise ValueError(f"status {self.status.value!r} requires a non-empty reason")
        return self

    @classmethod
    def initial(cls, reason: str | None = None) -> ScenarioState:
        """Return the canonical starting state (``DISCOVERED``)."""
        return cls(status=ScenarioStatus.DISCOVERED, reason=reason)

    def transition(self, target: ScenarioStatus, *, reason: str | None = None) -> ScenarioState:
        """Return a new :class:`ScenarioState` after a validated transition."""
        validate_transition(self.status, target)
        return ScenarioState(status=target, reason=reason, updated_at=_utcnow())


__all__ = [
    "InvalidTransitionError",
    "REASON_REQUIRED_STATUSES",
    "TERMINAL_STATUSES",
    "ScenarioState",
    "ScenarioStatus",
    "allowed_transitions",
    "can_transition",
    "validate_transition",
]
