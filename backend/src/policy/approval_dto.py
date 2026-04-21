"""Pure-data layer for the approval workflow (Backlog/dev1_md §8, §16).

This module contains the *immutable, side-effect-free* contract that every
caller of :mod:`src.policy.approval_service` agrees on: status enums,
pydantic request / signature models, the closed-taxonomy failure summaries,
and the :class:`ApprovalError` raised on any verification failure.

Why a separate module?
----------------------
``ApprovalService`` (in :mod:`src.policy.approval_service`) needs to import
:mod:`src.sandbox.signing` and :mod:`src.policy.audit` to do its job. Through
the rest of the codebase, ``signing`` transitively pulls in
``src.payloads.builder`` which in turn imports :mod:`src.policy.preflight`,
and ``preflight`` historically imported the DTOs from a single, monolithic
``src.policy.approval`` module. The result was a *latent* cycle:

    src.policy.__init__
      -> src.policy.approval (start)
        -> src.sandbox.signing
          -> ... -> src.payloads.builder
            -> src.policy.preflight
              -> src.policy.approval (PARTIAL — kaboom)

By keeping every type the rest of the policy plane needs in this *pure*
DTO module — which imports nothing beyond stdlib + pydantic — the cycle
is broken structurally: :mod:`src.policy.preflight` only ever imports
from :mod:`src.policy.approval_dto`, which is fully importable from a
cold interpreter without dragging in ``signing`` / ``audit`` /
``payloads`` first.

The legacy public surface (``ApprovalRequest``, ``ApprovalSignature``,
etc.) is preserved verbatim by :mod:`src.policy.approval`, which now acts
as a thin re-export shim for backward compatibility.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from enum import StrEnum
from typing import Final, Self
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    model_validator,
)


# ---------------------------------------------------------------------------
# Closed taxonomy of failure summaries
# ---------------------------------------------------------------------------


_REASON_NO_APPROVAL: Final[str] = "approval_missing"
_REASON_EXPIRED: Final[str] = "approval_expired"
_REASON_INVALID_SIG: Final[str] = "approval_signature_invalid"
_REASON_TARGET_MISMATCH: Final[str] = "approval_target_mismatch"
_REASON_ACTION_MISMATCH: Final[str] = "approval_action_mismatch"
_REASON_DUAL_CONTROL: Final[str] = "approval_dual_control_required"
_REASON_UNKNOWN_KEY: Final[str] = "approval_unknown_key"
_REASON_REVOKED: Final[str] = "approval_revoked"

APPROVAL_FAILURE_REASONS: Final[frozenset[str]] = frozenset(
    {
        _REASON_NO_APPROVAL,
        _REASON_EXPIRED,
        _REASON_INVALID_SIG,
        _REASON_TARGET_MISMATCH,
        _REASON_ACTION_MISMATCH,
        _REASON_DUAL_CONTROL,
        _REASON_UNKNOWN_KEY,
        _REASON_REVOKED,
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ApprovalError(Exception):
    """Base class for every approval workflow failure.

    The ``summary`` is always one of :data:`APPROVAL_FAILURE_REASONS` so
    the policy plane can surface it to the customer / audit log without
    leaking implementation details (stack traces, signer IDs, etc.).
    """

    def __init__(self, summary: str) -> None:
        super().__init__(summary)
        self.summary = summary


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ApprovalAction(StrEnum):
    """Risk class of the action being approved.

    Mirrors :class:`src.pipeline.contracts.tool_job.RiskLevel` but is
    intentionally smaller — the policy plane only cares whether dual
    control kicks in.
    """

    HIGH = "high"
    DESTRUCTIVE = "destructive"


class ApprovalStatus(StrEnum):
    """Lifecycle state of an :class:`ApprovalRequest`."""

    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"
    REVOKED = "revoked"
    EXPIRED = "expired"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ApprovalRequest(BaseModel):
    """Immutable description of "what is being approved".

    The same payload bytes that are SHA-256'd into the signature payload
    are the bytes the operator UI displays — there is no hidden field that
    the operator did not explicitly endorse.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    scan_id: UUID | None = None
    action: ApprovalAction
    tool_id: StrictStr = Field(min_length=2, max_length=64)
    target: StrictStr = Field(min_length=1, max_length=2_048)
    justification: StrictStr = Field(min_length=10, max_length=512)
    expires_at: datetime
    created_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be strictly later than created_at")
        return self

    def canonical_bytes(self) -> bytes:
        """Return the canonical JSON serialisation that signers must endorse."""
        return _canonical_approval_payload(self)


class ApprovalSignature(BaseModel):
    """One Ed25519 signature over an :class:`ApprovalRequest`.

    The signing operator is identified by ``signer_key_id`` (matching the
    short hex id used by :class:`~src.sandbox.signing.KeyManager`). The
    optional ``signer_actor_id`` ties the signature back to the platform's
    own user identity for audit / non-repudiation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: UUID
    signer_key_id: StrictStr = Field(min_length=16, max_length=16)
    signer_actor_id: UUID | None = None
    signature_b64: StrictStr = Field(min_length=86, max_length=128)
    signed_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.signed_at.tzinfo is None:
            raise ValueError("signed_at must be timezone-aware")
        return self


# ---------------------------------------------------------------------------
# Canonicalisation
# ---------------------------------------------------------------------------


def _canonical_approval_payload(request: ApprovalRequest) -> bytes:
    """Stable JSON encoding of the fields signers endorse.

    Excludes ``created_at`` and any platform-side identifiers; only the
    operator-meaningful fields are bound to the signature so a chained
    re-issue (re-signing under a new ``request_id``) does not silently
    re-use signatures.
    """
    payload: Mapping[str, object] = {
        "request_id": str(request.request_id),
        "tenant_id": str(request.tenant_id),
        "scan_id": str(request.scan_id) if request.scan_id is not None else None,
        "action": request.action.value,
        "tool_id": request.tool_id,
        "target": request.target,
        "justification": request.justification,
        "expires_at": request.expires_at.astimezone(timezone.utc).isoformat(),
    }
    return json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


__all__ = [
    "APPROVAL_FAILURE_REASONS",
    "ApprovalAction",
    "ApprovalError",
    "ApprovalRequest",
    "ApprovalSignature",
    "ApprovalStatus",
]
