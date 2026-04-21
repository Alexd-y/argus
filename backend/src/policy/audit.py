"""Tamper-evident audit log for the ARGUS policy plane (Backlog/dev1_md §8).

Every preflight decision (scope check, ownership proof, policy verdict,
approval lookup) emits an :class:`AuditEvent`. Events are linked into a
SHA-256 hash chain so any post-hoc tampering — deletion, reorder, or
content edit — is detected by simply replaying the chain.

Design constraints:

* No PII / secrets in payloads. The :class:`AuditEvent` model rejects any
  ``payload`` value that looks like raw user input; callers must
  pre-filter to short, non-sensitive identifiers (UUIDs, enum names, IP
  prefixes).
* No I/O in the model layer. Persisted backends live behind the
  :class:`AuditSink` protocol — :class:`InMemoryAuditSink` is included for
  unit tests and dev environments; production deploys swap in a Postgres /
  Loki / WORM-S3 sink behind the same interface.
* Idempotent append: emitting the same logical event twice (same
  ``event_id``) is a no-op when the sink supports it. The default
  in-memory sink raises :class:`AuditChainError` on duplicate IDs to keep
  unit tests honest.

The hash chain uses the construction:

    event_hash = sha256(
        canonical_json(event_without_event_hash) + b"|" + prev_event_hash
    )

with ``prev_event_hash = "0" * 64`` for the first event in a chain. This
matches RFC 6962-style tamper-evident logs but avoids pulling Merkle tree
machinery — the volume of policy events is low enough (≪10^4 / scan) that
linear chain verification is fine.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    model_validator,
)


_logger = logging.getLogger(__name__)


GENESIS_HASH: Final[str] = "0" * 64
"""Sentinel hash used as ``prev_event_hash`` for the first event in a chain."""


# ---------------------------------------------------------------------------
# Event taxonomy
# ---------------------------------------------------------------------------


class AuditEventType(StrEnum):
    """Closed taxonomy of policy-plane audit event kinds."""

    SCOPE_CHECK = "scope.check"
    OWNERSHIP_VERIFY = "ownership.verify"
    POLICY_DECISION = "policy.decision"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_DENIED = "approval.denied"
    APPROVAL_REVOKED = "approval.revoked"
    PREFLIGHT_PASS = "preflight.pass"
    PREFLIGHT_DENY = "preflight.deny"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AuditChainError(Exception):
    """Raised when the hash chain is broken or an event is malformed."""


class AuditPayloadError(ValueError):
    """Raised when an audit payload value violates the safe-shape contract.

    Inherits from :class:`ValueError` so Pydantic surfaces it as a normal
    :class:`pydantic.ValidationError` when raised inside a model validator.
    """


# ---------------------------------------------------------------------------
# Payload shape guard
# ---------------------------------------------------------------------------


_MAX_PAYLOAD_KEYS: Final[int] = 32
_MAX_KEY_LEN: Final[int] = 64
_MAX_STR_VALUE_LEN: Final[int] = 256
_MAX_LIST_LEN: Final[int] = 32

_AUDIT_KEY_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _coerce_payload(value: object) -> object:
    """Recursively validate / coerce an audit payload value.

    Allowed leaves: ``None``, ``bool``, ``int``, ``float``, ``str``,
    ``UUID``, ``StrEnum`` (lowered to its ``value``).

    Lists / tuples are accepted (recursively) up to :data:`_MAX_LIST_LEN`
    items. Dicts are accepted (recursively) up to :data:`_MAX_PAYLOAD_KEYS`
    keys, each matching ``^[a-z][a-z0-9_]{0,63}$``.

    Strings longer than :data:`_MAX_STR_VALUE_LEN` are truncated with a
    ``…`` marker so a stray HTTP body cannot blow up the audit row.
    """
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, str):
        if len(value) > _MAX_STR_VALUE_LEN:
            return value[: _MAX_STR_VALUE_LEN - 1] + "\u2026"
        return value
    if isinstance(value, list | tuple):
        items = list(value)
        if len(items) > _MAX_LIST_LEN:
            raise AuditPayloadError(
                f"audit payload list/tuple has {len(items)} items (max {_MAX_LIST_LEN})"
            )
        return [_coerce_payload(v) for v in items]
    if isinstance(value, Mapping):
        if len(value) > _MAX_PAYLOAD_KEYS:
            raise AuditPayloadError(
                f"audit payload dict has {len(value)} keys (max {_MAX_PAYLOAD_KEYS})"
            )
        out: dict[str, object] = {}
        for key, raw in value.items():
            if not isinstance(key, str) or not _AUDIT_KEY_RE.fullmatch(key):
                raise AuditPayloadError(
                    f"audit payload key {key!r} must match ^[a-z][a-z0-9_]{{0,63}}$"
                )
            if len(key) > _MAX_KEY_LEN:
                raise AuditPayloadError(
                    f"audit payload key {key!r} exceeds {_MAX_KEY_LEN} chars"
                )
            out[key] = _coerce_payload(raw)
        return out
    raise AuditPayloadError(
        f"audit payload contains unsupported type {type(value).__name__!r}"
    )


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# AuditEvent
# ---------------------------------------------------------------------------


class AuditEvent(BaseModel):
    """One immutable row of the policy-plane audit log.

    Notes
    -----
    * ``event_hash`` is computed once at construction time over the canonical
      JSON of every other field plus ``prev_event_hash``. Any subsequent
      mutation (impossible — model is frozen) would flip the hash.
    * ``payload`` MUST contain only short, non-sensitive identifiers; the
      validator rejects free-form text or nested user input. Use the
      ``failure_summary`` enum strings exposed by sibling modules.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID = Field(default_factory=uuid4)
    event_type: AuditEventType
    occurred_at: datetime = Field(default_factory=_utcnow)
    tenant_id: UUID
    scan_id: UUID | None = None
    actor_id: UUID | None = None
    decision_allowed: StrictBool
    failure_summary: StrictStr | None = Field(default=None, max_length=64)
    prev_event_hash: StrictStr = Field(
        default=GENESIS_HASH, min_length=64, max_length=64
    )
    event_hash: StrictStr = Field(default="", max_length=64)
    payload: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _coerce_payload_before(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        payload = data.get("payload")
        if payload is None:
            return data
        coerced = _coerce_payload(payload)
        if not isinstance(coerced, dict):
            raise AuditPayloadError("audit payload must be a mapping at the top level")
        return {**data, "payload": coerced}

    @model_validator(mode="after")
    def _bind_hash(self) -> "AuditEvent":
        expected = _compute_event_hash(self)
        if not self.event_hash:
            object.__setattr__(self, "event_hash", expected)
        elif self.event_hash != expected:
            raise AuditChainError(
                f"event_hash mismatch for event_id={self.event_id}: "
                f"expected={expected} actual={self.event_hash}"
            )
        return self


def _compute_event_hash(event: AuditEvent) -> str:
    """Return the SHA-256 hex digest of the canonical event payload."""
    canonical = json.dumps(
        {
            "event_id": str(event.event_id),
            "event_type": event.event_type.value,
            "occurred_at": event.occurred_at.isoformat(),
            "tenant_id": str(event.tenant_id),
            "scan_id": str(event.scan_id) if event.scan_id is not None else None,
            "actor_id": str(event.actor_id) if event.actor_id is not None else None,
            "decision_allowed": event.decision_allowed,
            "failure_summary": event.failure_summary,
            "payload": event.payload,
            "prev_event_hash": event.prev_event_hash,
        },
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------


@runtime_checkable
class AuditSink(Protocol):
    """Append-only persistence backend for :class:`AuditEvent` rows."""

    def append(self, event: AuditEvent) -> None:
        """Persist ``event``. Must be idempotent on duplicate ``event_id``."""

    def latest_hash(self, *, tenant_id: UUID) -> str:
        """Return the most recent ``event_hash`` for ``tenant_id``.

        Must return :data:`GENESIS_HASH` when the tenant has no events.
        """

    def iter_events(self, *, tenant_id: UUID) -> Iterable[AuditEvent]:
        """Yield events for ``tenant_id`` in append order (oldest first)."""


class InMemoryAuditSink:
    """Process-local in-memory sink intended for unit tests and dev mode.

    Thread-safe (a single :class:`threading.Lock` guards every mutation).
    Production deployments MUST swap in a durable sink (Postgres WORM table,
    append-only S3 object, or the project's audit_log Alembic migration).
    """

    def __init__(self) -> None:
        self._events: dict[UUID, list[AuditEvent]] = {}
        self._seen_ids: set[UUID] = set()
        self._lock = threading.Lock()

    def append(self, event: AuditEvent) -> None:
        with self._lock:
            if event.event_id in self._seen_ids:
                raise AuditChainError(
                    f"duplicate audit event_id={event.event_id} rejected by sink"
                )
            self._seen_ids.add(event.event_id)
            self._events.setdefault(event.tenant_id, []).append(event)

    def latest_hash(self, *, tenant_id: UUID) -> str:
        with self._lock:
            tenant_events = self._events.get(tenant_id, [])
            if not tenant_events:
                return GENESIS_HASH
            return tenant_events[-1].event_hash

    def iter_events(self, *, tenant_id: UUID) -> Iterable[AuditEvent]:
        with self._lock:
            return list(self._events.get(tenant_id, []))


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------


class AuditLogger:
    """Front door for emitting policy-plane audit events.

    Wraps a :class:`AuditSink` and a per-tenant lock so concurrent emitters
    can never produce two events with the same ``prev_event_hash`` (which
    would silently fork the chain).
    """

    def __init__(self, sink: AuditSink) -> None:
        self._sink = sink
        self._tenant_locks: dict[UUID, threading.Lock] = {}
        self._index_lock = threading.Lock()

    @property
    def sink(self) -> AuditSink:
        return self._sink

    def emit(
        self,
        *,
        event_type: AuditEventType,
        tenant_id: UUID,
        decision_allowed: bool,
        scan_id: UUID | None = None,
        actor_id: UUID | None = None,
        failure_summary: str | None = None,
        payload: Mapping[str, object] | None = None,
    ) -> AuditEvent:
        """Persist a new :class:`AuditEvent` and return the materialised row."""
        with self._tenant_lock(tenant_id):
            prev_hash = self._sink.latest_hash(tenant_id=tenant_id)
            event = AuditEvent(
                event_type=event_type,
                tenant_id=tenant_id,
                scan_id=scan_id,
                actor_id=actor_id,
                decision_allowed=decision_allowed,
                failure_summary=failure_summary,
                prev_event_hash=prev_hash,
                payload=dict(payload or {}),
            )
            self._sink.append(event)
            _logger.info(
                "policy.audit.emit",
                extra={
                    "event_type": event.event_type.value,
                    "tenant_id": str(event.tenant_id),
                    "decision_allowed": event.decision_allowed,
                    "failure_summary": event.failure_summary,
                    "event_hash_prefix": event.event_hash[:12],
                },
            )
            return event

    def verify_chain(self, *, tenant_id: UUID) -> int:
        """Replay the tenant's chain, raising :class:`AuditChainError` on tamper.

        Returns the number of events verified. Linear-time in the number of
        events (low enough to be fine — see module docstring).
        """
        events = list(self._sink.iter_events(tenant_id=tenant_id))
        prev_hash = GENESIS_HASH
        for event in events:
            if event.prev_event_hash != prev_hash:
                raise AuditChainError(
                    f"chain break at event_id={event.event_id}: "
                    f"prev={event.prev_event_hash} expected={prev_hash}"
                )
            expected = _compute_event_hash(event)
            if event.event_hash != expected:
                raise AuditChainError(f"event_hash drift at event_id={event.event_id}")
            prev_hash = event.event_hash
        return len(events)

    def _tenant_lock(self, tenant_id: UUID) -> threading.Lock:
        with self._index_lock:
            lock = self._tenant_locks.get(tenant_id)
            if lock is None:
                lock = threading.Lock()
                self._tenant_locks[tenant_id] = lock
            return lock


__all__ = [
    "GENESIS_HASH",
    "AuditChainError",
    "AuditEvent",
    "AuditEventType",
    "AuditLogger",
    "AuditPayloadError",
    "AuditSink",
    "InMemoryAuditSink",
]
