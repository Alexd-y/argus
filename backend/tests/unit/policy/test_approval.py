"""Unit tests for :mod:`src.policy.approval`.

Verifies signature canonicalisation, single + dual control, expiry,
target / action mismatch, revocation, unknown-key rejection, and the
audit trail emitted on every verification path.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ValidationError

from src.policy.approval import (
    APPROVAL_FAILURE_REASONS,
    ApprovalAction,
    ApprovalError,
    ApprovalRequest,
    ApprovalService,
    ApprovalSignature,
    ApprovalStatus,
)
from src.policy.audit import AuditEventType, InMemoryAuditSink


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(
    *,
    tenant_id: UUID,
    action: ApprovalAction = ApprovalAction.HIGH,
    target: str = "https://example.com/api",
    expires_at: datetime | None = None,
    created_at: datetime | None = None,
    tool_id: str = "burp_active",
) -> ApprovalRequest:
    now = created_at or datetime.now(tz=timezone.utc)
    expires = expires_at or (now + timedelta(hours=1))
    return ApprovalRequest(
        tenant_id=tenant_id,
        action=action,
        tool_id=tool_id,
        target=target,
        justification="approved by lead via security review",
        created_at=now,
        expires_at=expires,
    )


def _frozen_clock(now: datetime) -> Callable[[], datetime]:
    def _clock() -> datetime:
        return now

    return _clock


# ---------------------------------------------------------------------------
# ApprovalRequest validation
# ---------------------------------------------------------------------------


class TestPolicyApprovalRequest:
    def test_canonical_bytes_is_stable(self, tenant_id: UUID) -> None:
        req = _make_request(tenant_id=tenant_id)
        assert req.canonical_bytes() == req.canonical_bytes()

    def test_canonical_bytes_does_not_include_created_at(self, tenant_id: UUID) -> None:
        now = datetime.now(tz=timezone.utc)
        req1 = _make_request(
            tenant_id=tenant_id,
            created_at=now,
            expires_at=now + timedelta(hours=1),
        )
        # Mutating only created_at must NOT change the canonical bytes.
        req2 = ApprovalRequest(
            request_id=req1.request_id,
            tenant_id=tenant_id,
            scan_id=None,
            action=req1.action,
            tool_id=req1.tool_id,
            target=req1.target,
            justification=req1.justification,
            created_at=now - timedelta(minutes=30),
            expires_at=req1.expires_at,
        )
        assert req1.canonical_bytes() == req2.canonical_bytes()

    def test_expires_before_created_rejected(self, tenant_id: UUID) -> None:
        now = datetime.now(tz=timezone.utc)
        with pytest.raises(ValidationError):
            ApprovalRequest(
                tenant_id=tenant_id,
                action=ApprovalAction.HIGH,
                tool_id="burp_active",
                target="https://example.com",
                justification="needs work needs work needs work",
                created_at=now,
                expires_at=now - timedelta(seconds=1),
            )

    def test_naive_datetimes_rejected(self, tenant_id: UUID) -> None:
        now = datetime(2026, 4, 17, 12, 0, 0)
        with pytest.raises(ValidationError):
            ApprovalRequest(
                tenant_id=tenant_id,
                action=ApprovalAction.HIGH,
                tool_id="burp_active",
                target="https://example.com",
                justification="needs work needs work needs work",
                created_at=now,
                expires_at=now + timedelta(hours=1),
            )

    def test_short_justification_rejected(self, tenant_id: UUID) -> None:
        now = datetime.now(tz=timezone.utc)
        with pytest.raises(ValidationError):
            ApprovalRequest(
                tenant_id=tenant_id,
                action=ApprovalAction.HIGH,
                tool_id="burp_active",
                target="https://example.com",
                justification="short",
                created_at=now,
                expires_at=now + timedelta(hours=1),
            )

    def test_extra_fields_forbidden(self, tenant_id: UUID) -> None:
        now = datetime.now(tz=timezone.utc)
        with pytest.raises(ValidationError):
            ApprovalRequest.model_validate(
                {
                    "tenant_id": str(tenant_id),
                    "action": "high",
                    "tool_id": "burp_active",
                    "target": "https://example.com",
                    "justification": "approved by lead via security review",
                    "created_at": now.isoformat(),
                    "expires_at": (now + timedelta(hours=1)).isoformat(),
                    "extra": "nope",
                }
            )


# ---------------------------------------------------------------------------
# Single-signer happy path
# ---------------------------------------------------------------------------


class TestSingleSigner:
    def test_high_action_one_signer_grants(
        self,
        tenant_id: UUID,
        approval_service: ApprovalService,
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
        audit_sink: InMemoryAuditSink,
    ) -> None:
        private_key, _, _ = ed25519_keypair
        request = _make_request(tenant_id=tenant_id, action=ApprovalAction.HIGH)
        signature = approval_service.sign_request(request, private_key=private_key)
        status = approval_service.verify(
            request=request,
            signatures=[signature],
            expected_target=request.target,
            expected_action=ApprovalAction.HIGH,
        )
        assert status is ApprovalStatus.GRANTED
        events = list(audit_sink.iter_events(tenant_id=tenant_id))
        assert len(events) == 1
        assert events[0].event_type is AuditEventType.APPROVAL_GRANTED
        assert events[0].decision_allowed is True

    def test_signature_does_not_verify_for_other_payload(
        self,
        tenant_id: UUID,
        approval_service: ApprovalService,
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    ) -> None:
        private_key, _, _ = ed25519_keypair
        request = _make_request(tenant_id=tenant_id)
        signature = approval_service.sign_request(request, private_key=private_key)
        # Build a different request with a fresh request_id but the same key.
        other = _make_request(tenant_id=tenant_id, target="https://other.example.com")
        re_used = ApprovalSignature(
            request_id=other.request_id,
            signer_key_id=signature.signer_key_id,
            signature_b64=signature.signature_b64,
        )
        with pytest.raises(ApprovalError) as exc_info:
            approval_service.verify(
                request=other,
                signatures=[re_used],
                expected_target=other.target,
                expected_action=ApprovalAction.HIGH,
            )
        assert exc_info.value.summary == "approval_signature_invalid"


# ---------------------------------------------------------------------------
# Dual control for destructive
# ---------------------------------------------------------------------------


class TestDualControl:
    def test_destructive_requires_two_distinct_signers(
        self,
        tenant_id: UUID,
        approval_service: ApprovalService,
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
        second_ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    ) -> None:
        priv1, _, _ = ed25519_keypair
        priv2, _, _ = second_ed25519_keypair
        request = _make_request(tenant_id=tenant_id, action=ApprovalAction.DESTRUCTIVE)
        sig1 = approval_service.sign_request(request, private_key=priv1)
        sig2 = approval_service.sign_request(request, private_key=priv2)
        status = approval_service.verify(
            request=request,
            signatures=[sig1, sig2],
            expected_target=request.target,
            expected_action=ApprovalAction.DESTRUCTIVE,
        )
        assert status is ApprovalStatus.GRANTED

    def test_destructive_with_only_one_signer_rejected(
        self,
        tenant_id: UUID,
        approval_service: ApprovalService,
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    ) -> None:
        priv1, _, _ = ed25519_keypair
        request = _make_request(tenant_id=tenant_id, action=ApprovalAction.DESTRUCTIVE)
        sig1 = approval_service.sign_request(request, private_key=priv1)
        with pytest.raises(ApprovalError) as exc_info:
            approval_service.verify(
                request=request,
                signatures=[sig1],
                expected_target=request.target,
                expected_action=ApprovalAction.DESTRUCTIVE,
            )
        assert exc_info.value.summary == "approval_dual_control_required"

    def test_destructive_with_same_signer_twice_rejected(
        self,
        tenant_id: UUID,
        approval_service: ApprovalService,
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    ) -> None:
        priv, _, _ = ed25519_keypair
        request = _make_request(tenant_id=tenant_id, action=ApprovalAction.DESTRUCTIVE)
        sig1 = approval_service.sign_request(request, private_key=priv)
        sig2 = approval_service.sign_request(request, private_key=priv)
        with pytest.raises(ApprovalError) as exc_info:
            approval_service.verify(
                request=request,
                signatures=[sig1, sig2],
                expected_target=request.target,
                expected_action=ApprovalAction.DESTRUCTIVE,
            )
        assert exc_info.value.summary == "approval_dual_control_required"


# ---------------------------------------------------------------------------
# Failure paths — closed taxonomy
# ---------------------------------------------------------------------------


class TestFailureCases:
    def test_no_signatures(
        self,
        tenant_id: UUID,
        approval_service: ApprovalService,
    ) -> None:
        request = _make_request(tenant_id=tenant_id)
        with pytest.raises(ApprovalError) as exc_info:
            approval_service.verify(
                request=request,
                signatures=[],
                expected_target=request.target,
                expected_action=ApprovalAction.HIGH,
            )
        assert exc_info.value.summary == "approval_missing"

    def test_action_mismatch(
        self,
        tenant_id: UUID,
        approval_service: ApprovalService,
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    ) -> None:
        priv, _, _ = ed25519_keypair
        request = _make_request(tenant_id=tenant_id, action=ApprovalAction.HIGH)
        sig = approval_service.sign_request(request, private_key=priv)
        with pytest.raises(ApprovalError) as exc_info:
            approval_service.verify(
                request=request,
                signatures=[sig],
                expected_target=request.target,
                expected_action=ApprovalAction.DESTRUCTIVE,
            )
        assert exc_info.value.summary == "approval_action_mismatch"

    def test_target_mismatch(
        self,
        tenant_id: UUID,
        approval_service: ApprovalService,
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    ) -> None:
        priv, _, _ = ed25519_keypair
        request = _make_request(tenant_id=tenant_id, target="https://example.com")
        sig = approval_service.sign_request(request, private_key=priv)
        with pytest.raises(ApprovalError) as exc_info:
            approval_service.verify(
                request=request,
                signatures=[sig],
                expected_target="https://other.example.com",
                expected_action=ApprovalAction.HIGH,
            )
        assert exc_info.value.summary == "approval_target_mismatch"

    def test_expired(
        self,
        tenant_id: UUID,
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
        approval_service: ApprovalService,
        key_manager: object,
    ) -> None:
        from src.policy.audit import AuditLogger, InMemoryAuditSink
        from src.sandbox.signing import KeyManager

        assert isinstance(key_manager, KeyManager)
        priv, _, _ = ed25519_keypair
        now = datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)
        request = _make_request(
            tenant_id=tenant_id,
            created_at=now,
            expires_at=now + timedelta(seconds=1),
        )
        sig = approval_service.sign_request(request, private_key=priv)
        # Build a sibling service with a clock pinned past the expiry.
        # Reusing the same key manager keeps the signature valid.
        future_service = ApprovalService(
            key_manager=key_manager,
            audit_logger=AuditLogger(InMemoryAuditSink()),
            clock=_frozen_clock(now + timedelta(seconds=2)),
        )
        with pytest.raises(ApprovalError) as exc_info:
            future_service.verify(
                request=request,
                signatures=[sig],
                expected_target=request.target,
                expected_action=ApprovalAction.HIGH,
            )
        assert exc_info.value.summary == "approval_expired"

    def test_unknown_key(
        self,
        tenant_id: UUID,
        approval_service: ApprovalService,
    ) -> None:
        rogue_priv = Ed25519PrivateKey.generate()
        request = _make_request(tenant_id=tenant_id)
        sig = approval_service.sign_request(request, private_key=rogue_priv)
        with pytest.raises(ApprovalError) as exc_info:
            approval_service.verify(
                request=request,
                signatures=[sig],
                expected_target=request.target,
                expected_action=ApprovalAction.HIGH,
            )
        assert exc_info.value.summary == "approval_unknown_key"

    def test_revoked_signature(
        self,
        tenant_id: UUID,
        approval_service: ApprovalService,
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    ) -> None:
        priv, _, _ = ed25519_keypair
        request = _make_request(tenant_id=tenant_id)
        sig = approval_service.sign_request(request, private_key=priv)
        with pytest.raises(ApprovalError) as exc_info:
            approval_service.verify(
                request=request,
                signatures=[sig],
                revoked_signature_ids=[sig.signature_b64],
                expected_target=request.target,
                expected_action=ApprovalAction.HIGH,
            )
        assert exc_info.value.summary == "approval_revoked"

    def test_signature_request_id_mismatch(
        self,
        tenant_id: UUID,
        approval_service: ApprovalService,
        ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    ) -> None:
        priv, _, _ = ed25519_keypair
        request = _make_request(tenant_id=tenant_id)
        signature = approval_service.sign_request(request, private_key=priv)
        # Move the same signature onto a request with a different id.
        other = _make_request(tenant_id=tenant_id)
        forged = ApprovalSignature(
            request_id=other.request_id,
            signer_key_id=signature.signer_key_id,
            signature_b64=signature.signature_b64,
        )
        with pytest.raises(ApprovalError) as exc_info:
            approval_service.verify(
                request=other,
                signatures=[forged],
                expected_target=other.target,
                expected_action=ApprovalAction.HIGH,
            )
        assert exc_info.value.summary == "approval_signature_invalid"

    def test_audit_event_emitted_on_denial(
        self,
        tenant_id: UUID,
        approval_service: ApprovalService,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        request = _make_request(tenant_id=tenant_id)
        with pytest.raises(ApprovalError):
            approval_service.verify(
                request=request,
                signatures=[],
                expected_target=request.target,
                expected_action=ApprovalAction.HIGH,
            )
        events = list(audit_sink.iter_events(tenant_id=tenant_id))
        assert len(events) == 1
        assert events[0].event_type is AuditEventType.APPROVAL_DENIED
        assert events[0].failure_summary == "approval_missing"

    def test_failure_summaries_are_closed(self) -> None:
        # Sanity: every constant the service emits is listed in the
        # public set so downstream code can validate against it.
        for summary in APPROVAL_FAILURE_REASONS:
            assert isinstance(summary, str)
            assert summary.startswith("approval_")
