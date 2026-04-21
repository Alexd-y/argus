"""Approval verification service (Backlog/dev1_md §8, §16).

The :class:`ApprovalService` is the single source of truth for "did a
privileged operator authorise this exact action?". It enforces:

* Cryptographic provenance — every approval is signed with an Ed25519 key
  registered in :class:`~src.sandbox.signing.KeyManager`. Signatures bind
  the *canonical* approval payload (action, target, justification, expiry)
  so an operator cannot accidentally approve a slightly different request.
* Time-bounded validity — every approval carries an explicit ``expires_at``
  in UTC; expired tokens fail closed, never silently extend.
* Dual control for destructive actions — :class:`ApprovalAction.DESTRUCTIVE`
  requires *two distinct* signers from the registered key set. A single
  operator can never destroy data on their own.
* Idempotent persistence + immutable audit — every signed approval is
  written to an :class:`~src.policy.audit.AuditLogger` so the customer can
  prove (or refute) that a given action was sanctioned.

The service is deliberately I/O-light: it does NOT talk to a database or an
HTTP queue. The caller persists the :class:`ApprovalRequest` somewhere of
their choice (the project's ``approvals`` Postgres table is the canonical
location) and pulls back the matching :class:`ApprovalSignature` records;
the service then verifies the bundle against the in-memory key set.

The data contracts (``ApprovalRequest``, ``ApprovalSignature``,
``ApprovalAction``, ``ApprovalStatus``, ``ApprovalError``,
``APPROVAL_FAILURE_REASONS``) live in :mod:`src.policy.approval_dto` so
that downstream modules (notably :mod:`src.policy.preflight`) can depend
on the *pure* DTO layer without dragging in :mod:`src.sandbox.signing` /
:mod:`src.policy.audit`. See ``approval_dto`` module docstring for the
cyclic-import history that motivated the split.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.policy.approval_dto import (
    _REASON_ACTION_MISMATCH,
    _REASON_DUAL_CONTROL,
    _REASON_EXPIRED,
    _REASON_INVALID_SIG,
    _REASON_NO_APPROVAL,
    _REASON_REVOKED,
    _REASON_TARGET_MISMATCH,
    _REASON_UNKNOWN_KEY,
    ApprovalAction,
    ApprovalError,
    ApprovalRequest,
    ApprovalSignature,
    ApprovalStatus,
    _utcnow,
)
from src.policy.audit import AuditEventType, AuditLogger
from src.sandbox.signing import (
    KeyManager,
    KeyNotFoundError,
    public_key_id,
    sign_blob,
    verify_blob,
)


_logger = logging.getLogger(__name__)


class ApprovalService:
    """Verify cryptographic approvals and emit audit trails.

    The service is stateless apart from references to the key manager and
    the audit logger. Approval / signature persistence lives in the caller
    so the service stays test-friendly (no DB harness required).
    """

    def __init__(
        self,
        *,
        key_manager: KeyManager,
        audit_logger: AuditLogger,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._key_manager = key_manager
        self._audit_logger = audit_logger
        self._clock: Callable[[], datetime] = clock or _utcnow

    # -- Issuance helpers ----------------------------------------------------

    def sign_request(
        self,
        request: ApprovalRequest,
        *,
        private_key: Ed25519PrivateKey,
        signer_actor_id: UUID | None = None,
    ) -> ApprovalSignature:
        """Produce a signature for ``request`` using ``private_key``.

        Convenience for tests / dev tooling. Production operators sign via
        the dedicated approval UI; the service only verifies.
        """
        public_key: Ed25519PublicKey = private_key.public_key()
        kid = public_key_id(public_key)
        signature_b64 = sign_blob(private_key, request.canonical_bytes())
        return ApprovalSignature(
            request_id=request.request_id,
            signer_key_id=kid,
            signer_actor_id=signer_actor_id,
            signature_b64=signature_b64,
        )

    # -- Verification --------------------------------------------------------

    def verify(
        self,
        *,
        request: ApprovalRequest,
        signatures: Sequence[ApprovalSignature],
        revoked_signature_ids: Iterable[str] | None = None,
        expected_target: str,
        expected_action: ApprovalAction,
    ) -> ApprovalStatus:
        """Validate ``signatures`` against ``request`` and policy rules.

        Returns :class:`ApprovalStatus.GRANTED` on success and emits an
        :class:`AuditEventType.APPROVAL_GRANTED` event. On failure raises
        :class:`ApprovalError` with a closed-taxonomy ``summary`` and emits
        :class:`AuditEventType.APPROVAL_DENIED`.

        Failure cases (in evaluation order):

        1. Empty signature list — ``approval_missing``.
        2. Action mismatch — ``approval_action_mismatch``.
        3. Target mismatch — ``approval_target_mismatch``.
        4. Expiry passed — ``approval_expired``.
        5. Unknown signer key — ``approval_unknown_key``.
        6. Bad signature — ``approval_signature_invalid``.
        7. Signature ID revoked — ``approval_revoked``.
        8. Destructive action with fewer than 2 *distinct* signers —
           ``approval_dual_control_required``.
        """
        revoked = frozenset(revoked_signature_ids or ())

        try:
            self._verify_locked(
                request=request,
                signatures=signatures,
                revoked=revoked,
                expected_target=expected_target,
                expected_action=expected_action,
            )
        except ApprovalError as exc:
            self._emit(
                event_type=AuditEventType.APPROVAL_DENIED,
                request=request,
                allowed=False,
                summary=exc.summary,
            )
            raise

        self._emit(
            event_type=AuditEventType.APPROVAL_GRANTED,
            request=request,
            allowed=True,
            summary=None,
        )
        return ApprovalStatus.GRANTED

    # -- Internals -----------------------------------------------------------

    def _verify_locked(
        self,
        *,
        request: ApprovalRequest,
        signatures: Sequence[ApprovalSignature],
        revoked: frozenset[str],
        expected_target: str,
        expected_action: ApprovalAction,
    ) -> None:
        if not signatures:
            raise ApprovalError(_REASON_NO_APPROVAL)
        if request.action is not expected_action:
            raise ApprovalError(_REASON_ACTION_MISMATCH)
        if request.target != expected_target:
            raise ApprovalError(_REASON_TARGET_MISMATCH)
        now = self._clock()
        if now >= request.expires_at:
            raise ApprovalError(_REASON_EXPIRED)

        canonical = request.canonical_bytes()
        unique_signers: set[str] = set()
        for signature in signatures:
            if signature.request_id != request.request_id:
                raise ApprovalError(_REASON_INVALID_SIG)
            if signature.signature_b64 in revoked:
                raise ApprovalError(_REASON_REVOKED)
            try:
                public_key = self._key_manager.get(signature.signer_key_id)
            except KeyNotFoundError as exc:
                _logger.warning(
                    "policy.approval.unknown_key",
                    extra={
                        "request_id": str(request.request_id),
                        "signer_key_id": signature.signer_key_id,
                        "error_class": type(exc).__name__,
                    },
                )
                raise ApprovalError(_REASON_UNKNOWN_KEY) from exc
            if not verify_blob(public_key, canonical, signature.signature_b64):
                raise ApprovalError(_REASON_INVALID_SIG)
            unique_signers.add(signature.signer_key_id)

        required = 2 if request.action is ApprovalAction.DESTRUCTIVE else 1
        if len(unique_signers) < required:
            raise ApprovalError(_REASON_DUAL_CONTROL)

    def _emit(
        self,
        *,
        event_type: AuditEventType,
        request: ApprovalRequest,
        allowed: bool,
        summary: str | None,
    ) -> None:
        self._audit_logger.emit(
            event_type=event_type,
            tenant_id=request.tenant_id,
            scan_id=request.scan_id,
            decision_allowed=allowed,
            failure_summary=summary,
            payload={
                "request_id": request.request_id,
                "action": request.action,
                "tool_id": request.tool_id,
            },
        )


__all__ = [
    "ApprovalService",
]
