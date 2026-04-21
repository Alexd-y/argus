"""Pydantic schemas shared by every webhook adapter (ARG-035).

The runtime contract:

* :class:`NotificationEvent` is the *only* shape ever passed to an adapter's
  :meth:`send` method. Free-form ``payload`` dicts are explicitly rejected
  upstream so a caller cannot smuggle un-validated JSON into the wire.
* :class:`AdapterResult` is the *only* shape returned. Adapters never raise
  past the dispatcher — every transport / 4xx / 5xx surface lands here.
* :class:`CircuitState` captures the per-(adapter × tenant) failure
  counter. The dispatcher persists it in-process; restarts clear it (which
  is the desired behaviour — the upstream system may have come back).

All models are ``frozen=True`` + ``extra="forbid"`` so a stray attribute
fails loudly during typing instead of silently leaking into a webhook body.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

NOTIFICATION_EVENT_TYPES: Final[frozenset[str]] = frozenset(
    {
        "approval.pending",
        "scan.completed",
        "critical.finding.detected",
    }
)
"""Closed taxonomy of event types the dispatcher accepts.

Adding a new event type requires updating both this set AND the matching
unit test, so the wire-contract surface stays explicit.
"""


class NotificationSeverity(StrEnum):
    """Closed-taxonomy severity used by Linear / Jira priority mapping."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class NotificationEvent(BaseModel):
    """One business event ready for fan-out to webhook adapters.

    The dispatcher constructs this from internal pipeline events (approval
    queue, scan-completion, critical-finding hit) before any HTTP call. The
    adapter receives an immutable, sanitised payload — never a raw service
    object.

    Notes
    -----
    * ``event_id`` MUST be globally unique and stable: it doubles as the
      idempotency key for Linear / Jira ``external_id`` lookups so a retry
      never creates a duplicate ticket.
    * ``title`` and ``summary`` are operator-safe text that the adapters can
      forward verbatim. Anything that may contain raw secrets / PII MUST be
      sanitised by the caller (typically via
      :func:`src.reports.replay_command_sanitizer.sanitize_replay_command`).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: StrictStr = Field(
        min_length=8,
        max_length=128,
        description=(
            "Stable, globally-unique identifier for this event. Used as the "
            "idempotency key for Linear / Jira issue creation."
        ),
    )
    event_type: StrictStr = Field(
        min_length=1,
        max_length=64,
        description=(
            "One of NOTIFICATION_EVENT_TYPES (approval.pending / "
            "scan.completed / critical.finding.detected)."
        ),
    )
    severity: NotificationSeverity = NotificationSeverity.MEDIUM
    title: StrictStr = Field(min_length=1, max_length=300)
    summary: StrictStr = Field(min_length=1, max_length=2_000)
    tenant_id: StrictStr = Field(min_length=1, max_length=128)
    scan_id: StrictStr | None = Field(default=None, max_length=128)
    finding_id: StrictStr | None = Field(default=None, max_length=128)
    approval_id: StrictStr | None = Field(default=None, max_length=128)
    root_cause_hash: StrictStr | None = Field(
        default=None,
        max_length=128,
        description=(
            "Stable fingerprint of the root cause; used as Linear / Jira "
            "external_id so the same finding never spawns duplicate tickets."
        ),
    )
    evidence_url: StrictStr | None = Field(
        default=None,
        max_length=2_048,
        description="Optional pre-signed URL to the evidence artefact.",
    )
    occurred_at: datetime | None = Field(
        default=None,
        description="UTC timestamp; if absent the adapter substitutes server time.",
    )
    extra_tags: tuple[StrictStr, ...] = Field(
        default_factory=tuple,
        max_length=20,
        description="Additional labels (cwe, owasp, etc.) — adapter-specific.",
    )

    def is_known_event_type(self) -> bool:
        """Return ``True`` iff ``event_type`` is in the closed taxonomy."""
        return self.event_type in NOTIFICATION_EVENT_TYPES


class AdapterResult(BaseModel):
    """Outcome of one :meth:`NotifierProtocol.send` call.

    Adapters MUST return this even on transport failure — the dispatcher
    walks the chain and records audit events; raising past it would fail
    open and lose the event.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    adapter_name: StrictStr = Field(min_length=1, max_length=32)
    event_id: StrictStr = Field(min_length=8, max_length=128)
    delivered: StrictBool
    status_code: StrictInt | None = Field(default=None, ge=100, le=599)
    attempts: StrictInt = Field(
        default=1,
        ge=0,
        le=10,
        description=(
            "Number of HTTP attempts performed; 0 when the adapter "
            "short-circuited (disabled / skipped / circuit-open / dedup)."
        ),
    )
    target_redacted: StrictStr = Field(
        min_length=1,
        max_length=64,
        description=(
            "First 12 hex chars of sha256(target_url) — used for audit "
            "rows so the raw webhook URL never lands in the audit chain."
        ),
    )
    error_code: StrictStr | None = Field(
        default=None,
        max_length=64,
        description=(
            "Closed-taxonomy short identifier; populated only on failure. "
            "Examples: http_4xx, http_5xx, network_error, timeout, "
            "circuit_open, disabled, invalid_config."
        ),
    )
    skipped_reason: StrictStr | None = Field(
        default=None,
        max_length=64,
        description=(
            "Populated when ``delivered=False`` AND no error occurred. "
            "Examples: disabled_globally, disabled_for_tenant, missing_secret, "
            "circuit_open, idempotent_duplicate."
        ),
    )
    duplicate_of: StrictStr | None = Field(
        default=None,
        max_length=128,
        description=(
            "When delivered=False due to idempotent dedup — references the "
            "event_id that already shipped."
        ),
    )


class CircuitState(BaseModel):
    """Per-(adapter, tenant) circuit breaker state.

    The implementation is deliberately small: we track only the consecutive
    failure count + the timestamp the breaker tripped. On success the count
    resets to zero; on the threshold-th failure the breaker opens for
    ``cooldown_seconds`` and short-circuits subsequent calls until the
    cooldown elapses.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    failure_count: StrictInt = Field(default=0, ge=0, le=10_000)
    opened_at: datetime | None = None
    cooldown_seconds: StrictInt = Field(default=60, ge=1, le=86_400)


__all__ = [
    "NOTIFICATION_EVENT_TYPES",
    "AdapterResult",
    "CircuitState",
    "NotificationEvent",
    "NotificationSeverity",
]
