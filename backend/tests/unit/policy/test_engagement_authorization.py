"""Unit tests for the Engagement Authorization Profile (P4-SCENARIO-004).

Covers signature verification (valid / expired / tampered / unsigned / unknown
key), pre-authorization scoping (class + target allow-list), and the audited
auto-approval path (grant vs deny), enforcing SI-1: the EAP satisfies approval
pre-authorized with an audit trail and never bypasses a pending approval.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.pipeline.contracts.tool_job import TargetKind, TargetSpec
from src.policy.audit import AuditEventType, AuditLogger, InMemoryAuditSink
from src.policy.engagement_authorization import (
    ActionClass,
    EngagementAuthorizationError,
    EngagementAuthorizationProfile,
    EngagementAuthorizationService,
)
from src.sandbox.signing import KeyManager


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _profile(
    *,
    expires: datetime,
    targets: tuple[str, ...] = ("example.com",),
    classes: frozenset[ActionClass] = frozenset({ActionClass.INJECTION_SAFE}),
) -> EngagementAuthorizationProfile:
    return EngagementAuthorizationProfile(
        engagement_id="eng-2026-001",
        authorized_by="ciso@example.com",
        targets=targets,
        allow_action_classes=classes,
        max_request_budget=5000,
        expires=expires,
    )


@pytest.fixture()
def eap_service(
    key_manager: KeyManager, audit_logger: AuditLogger
) -> EngagementAuthorizationService:
    return EngagementAuthorizationService(
        key_manager=key_manager, audit_logger=audit_logger
    )


@pytest.fixture()
def in_scope_target() -> TargetSpec:
    return TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")


@pytest.fixture()
def out_of_scope_target() -> TargetSpec:
    return TargetSpec(kind=TargetKind.URL, url="https://evil.com/steal")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def test_verify_valid_signature_and_unexpired_passes(
    eap_service: EngagementAuthorizationService,
    ed25519_keypair: tuple[Ed25519PrivateKey, object, str],
) -> None:
    priv, _, _ = ed25519_keypair
    signed = EngagementAuthorizationService.sign_profile(
        _profile(expires=_now() + timedelta(days=1)), private_key=priv
    )
    eap_service.verify(signed)  # must not raise
    assert eap_service.is_verified(signed) is True


def test_verify_unsigned_fails(eap_service: EngagementAuthorizationService) -> None:
    with pytest.raises(EngagementAuthorizationError) as exc:
        eap_service.verify(_profile(expires=_now() + timedelta(days=1)))
    assert exc.value.summary == "eap_not_signed"


def test_verify_expired_fails(
    eap_service: EngagementAuthorizationService,
    ed25519_keypair: tuple[Ed25519PrivateKey, object, str],
) -> None:
    priv, _, _ = ed25519_keypair
    signed = EngagementAuthorizationService.sign_profile(
        _profile(expires=_now() - timedelta(seconds=1)), private_key=priv
    )
    with pytest.raises(EngagementAuthorizationError) as exc:
        eap_service.verify(signed)
    assert exc.value.summary == "eap_expired"


def test_verify_tampered_profile_fails(
    eap_service: EngagementAuthorizationService,
    ed25519_keypair: tuple[Ed25519PrivateKey, object, str],
) -> None:
    priv, _, _ = ed25519_keypair
    signed = EngagementAuthorizationService.sign_profile(
        _profile(expires=_now() + timedelta(days=1)), private_key=priv
    )
    # Widen the target allow-list after signing → canonical bytes change.
    tampered = signed.model_copy(update={"targets": ("example.com", "evil.com")})
    with pytest.raises(EngagementAuthorizationError) as exc:
        eap_service.verify(tampered)
    assert exc.value.summary == "eap_signature_invalid"


def test_verify_unknown_key_fails(
    eap_service: EngagementAuthorizationService,
) -> None:
    stranger = Ed25519PrivateKey.generate()  # not registered in key_manager
    signed = EngagementAuthorizationService.sign_profile(
        _profile(expires=_now() + timedelta(days=1)), private_key=stranger
    )
    with pytest.raises(EngagementAuthorizationError) as exc:
        eap_service.verify(signed)
    assert exc.value.summary == "eap_unknown_key"


# ---------------------------------------------------------------------------
# is_preauthorized
# ---------------------------------------------------------------------------


def test_is_preauthorized_class_and_target_in_scope_true(
    eap_service: EngagementAuthorizationService, in_scope_target: TargetSpec
) -> None:
    profile = _profile(
        expires=_now() + timedelta(days=1),
        classes=frozenset({ActionClass.INJECTION_SAFE}),
    )
    assert eap_service.is_preauthorized(
        profile, ActionClass.INJECTION_SAFE, in_scope_target
    )


def test_is_preauthorized_class_not_in_allowlist_false(
    eap_service: EngagementAuthorizationService, in_scope_target: TargetSpec
) -> None:
    profile = _profile(
        expires=_now() + timedelta(days=1),
        classes=frozenset({ActionClass.RECON}),
    )
    assert not eap_service.is_preauthorized(
        profile, ActionClass.RCE, in_scope_target
    )


def test_is_preauthorized_target_out_of_scope_false(
    eap_service: EngagementAuthorizationService, out_of_scope_target: TargetSpec
) -> None:
    profile = _profile(
        expires=_now() + timedelta(days=1),
        classes=frozenset({ActionClass.INJECTION_SAFE}),
    )
    assert not eap_service.is_preauthorized(
        profile, ActionClass.INJECTION_SAFE, out_of_scope_target
    )


# ---------------------------------------------------------------------------
# authorize (audited auto-approval) — SI-1
# ---------------------------------------------------------------------------


def test_authorize_grants_with_audit_trail(
    eap_service: EngagementAuthorizationService,
    ed25519_keypair: tuple[Ed25519PrivateKey, object, str],
    in_scope_target: TargetSpec,
    tenant_id: UUID,
    scan_id: UUID,
    audit_sink: InMemoryAuditSink,
) -> None:
    priv, _, _ = ed25519_keypair
    signed = EngagementAuthorizationService.sign_profile(
        _profile(
            expires=_now() + timedelta(days=1),
            classes=frozenset({ActionClass.INJECTION_SAFE}),
        ),
        private_key=priv,
    )
    decision = eap_service.authorize(
        signed,
        ActionClass.INJECTION_SAFE,
        in_scope_target,
        tenant_id=tenant_id,
        scan_id=scan_id,
    )
    assert decision.authorized is True
    assert decision.approval_id is not None
    assert decision.engagement_id == "eng-2026-001"

    events = list(audit_sink.iter_events(tenant_id=tenant_id))
    granted = [e for e in events if e.event_type is AuditEventType.APPROVAL_GRANTED]
    assert len(granted) == 1
    # Audit trail attributes who pre-authorized (engagement / authorized_by).
    assert granted[0].payload["engagement_id"] == "eng-2026-001"
    assert granted[0].payload["authorized_by"] == "ciso@example.com"
    assert granted[0].decision_allowed is True


def test_authorize_denies_when_class_not_preauthorized(
    eap_service: EngagementAuthorizationService,
    ed25519_keypair: tuple[Ed25519PrivateKey, object, str],
    in_scope_target: TargetSpec,
    tenant_id: UUID,
    audit_sink: InMemoryAuditSink,
) -> None:
    priv, _, _ = ed25519_keypair
    signed = EngagementAuthorizationService.sign_profile(
        _profile(
            expires=_now() + timedelta(days=1),
            classes=frozenset({ActionClass.RECON}),
        ),
        private_key=priv,
    )
    decision = eap_service.authorize(
        signed, ActionClass.RCE, in_scope_target, tenant_id=tenant_id
    )
    assert decision.authorized is False
    assert decision.approval_id is None
    assert decision.reason == "eap_action_class_not_preauthorized"
    events = list(audit_sink.iter_events(tenant_id=tenant_id))
    assert any(e.event_type is AuditEventType.APPROVAL_DENIED for e in events)


def test_authorize_denies_when_target_out_of_allowlist(
    eap_service: EngagementAuthorizationService,
    ed25519_keypair: tuple[Ed25519PrivateKey, object, str],
    out_of_scope_target: TargetSpec,
    tenant_id: UUID,
) -> None:
    priv, _, _ = ed25519_keypair
    signed = EngagementAuthorizationService.sign_profile(
        _profile(
            expires=_now() + timedelta(days=1),
            classes=frozenset({ActionClass.INJECTION_SAFE}),
        ),
        private_key=priv,
    )
    decision = eap_service.authorize(
        signed, ActionClass.INJECTION_SAFE, out_of_scope_target, tenant_id=tenant_id
    )
    assert decision.authorized is False
    assert decision.reason == "eap_target_not_in_allowlist"


def test_authorize_denies_expired_profile(
    eap_service: EngagementAuthorizationService,
    ed25519_keypair: tuple[Ed25519PrivateKey, object, str],
    in_scope_target: TargetSpec,
    tenant_id: UUID,
) -> None:
    priv, _, _ = ed25519_keypair
    signed = EngagementAuthorizationService.sign_profile(
        _profile(expires=_now() - timedelta(seconds=1)), private_key=priv
    )
    decision = eap_service.authorize(
        signed, ActionClass.INJECTION_SAFE, in_scope_target, tenant_id=tenant_id
    )
    assert decision.authorized is False
    assert decision.reason == "eap_expired"
