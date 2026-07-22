"""Preflight ↔ EAP integration tests (P4-SCENARIO-004, SI-1 / SI-2 / SI-7).

Proves that an Engagement Authorization Profile, wired as an optional
collaborator of :class:`PreflightChecker`:

* satisfies an approval requirement *pre-authorized* (with an audited
  ``approval_id``) when the action class + target are pre-agreed;
* does NOT bypass approval when the class is not pre-authorized (falls back to
  the normal, and here failing, cryptographic verification → deny);
* cannot widen scope — an out-of-scope target is denied before approval even
  with a matching EAP;
* leaves the no-EAP behaviour unchanged (back-compat).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel, TargetKind, TargetSpec
from src.policy.approval import ApprovalService
from src.policy.audit import AuditEventType, AuditLogger, InMemoryAuditSink
from src.policy.engagement_authorization import (
    ActionClass,
    EngagementAuthorizationProfile,
    EngagementAuthorizationService,
)
from src.policy.ownership import InMemoryOwnershipProofStore, OwnershipMethod, OwnershipProof
from src.policy.policy_engine import PolicyContext, PolicyEngine
from src.policy.preflight import PreflightChecker
from src.policy.scope import ScopeEngine
from src.sandbox.signing import KeyManager


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _proof(tenant_id: UUID, target: str) -> OwnershipProof:
    now = _now()
    return OwnershipProof(
        challenge_id=uuid4(),
        tenant_id=tenant_id,
        target=target,
        method=OwnershipMethod.HTTP_HEADER,
        verified_at=now,
        valid_until=now + timedelta(hours=1),
    )


def _high_risk_ctx(tenant_id: UUID, target: str) -> PolicyContext:
    return PolicyContext(
        tenant_id=tenant_id,
        scan_id=uuid4(),
        phase=ScanPhase.EXPLOITATION,
        risk_level=RiskLevel.HIGH,
        tool_id="metasploit",
        target=target,
        has_ownership_proof=True,
    )


def _signed_profile(
    priv: Ed25519PrivateKey,
    *,
    classes: frozenset[ActionClass],
    targets: tuple[str, ...] = ("example.com",),
) -> EngagementAuthorizationProfile:
    profile = EngagementAuthorizationProfile(
        engagement_id="eng-42",
        authorized_by="ciso@example.com",
        targets=targets,
        allow_action_classes=classes,
        max_request_budget=10_000,
        expires=_now() + timedelta(days=1),
    )
    return EngagementAuthorizationService.sign_profile(profile, private_key=priv)


def _checker(
    *,
    scope_engine: ScopeEngine,
    ownership_store: InMemoryOwnershipProofStore,
    policy_engine: PolicyEngine,
    approval_service: ApprovalService,
    audit_logger: AuditLogger,
    eap_service: EngagementAuthorizationService | None,
) -> PreflightChecker:
    return PreflightChecker(
        scope_engine=scope_engine,
        ownership_store=ownership_store,
        policy_engine=policy_engine,
        approval_service=approval_service,
        audit_logger=audit_logger,
        eap_service=eap_service,
    )


def test_preauthorized_class_satisfies_approval_with_audit(
    scope_engine: ScopeEngine,
    ownership_store: InMemoryOwnershipProofStore,
    policy_engine: PolicyEngine,
    approval_service: ApprovalService,
    audit_logger: AuditLogger,
    audit_sink: InMemoryAuditSink,
    key_manager: KeyManager,
    ed25519_keypair: tuple[Ed25519PrivateKey, object, str],
    tenant_id: UUID,
) -> None:
    priv, _, _ = ed25519_keypair
    eap_service = EngagementAuthorizationService(
        key_manager=key_manager, audit_logger=audit_logger
    )
    checker = _checker(
        scope_engine=scope_engine,
        ownership_store=ownership_store,
        policy_engine=policy_engine,
        approval_service=approval_service,
        audit_logger=audit_logger,
        eap_service=eap_service,
    )
    target = TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")
    ownership_store.save(_proof(tenant_id, target.value))
    profile = _signed_profile(priv, classes=frozenset({ActionClass.RCE}))

    decision = checker.check(
        target_spec=target,
        port=443,
        policy_context=_high_risk_ctx(tenant_id, target.value),
        engagement_profile=profile,
        action_class=ActionClass.RCE,
    )

    assert decision.allowed is True
    assert decision.approval_required is True
    assert decision.approval_verified is True
    assert decision.eap_approval_id is not None
    assert decision.eap_engagement_id == "eng-42"
    events = list(audit_sink.iter_events(tenant_id=tenant_id))
    assert any(e.event_type is AuditEventType.APPROVAL_GRANTED for e in events)
    assert events[-1].event_type is AuditEventType.PREFLIGHT_PASS


def test_non_preauthorized_class_falls_back_and_denies(
    scope_engine: ScopeEngine,
    ownership_store: InMemoryOwnershipProofStore,
    policy_engine: PolicyEngine,
    approval_service: ApprovalService,
    audit_logger: AuditLogger,
    key_manager: KeyManager,
    ed25519_keypair: tuple[Ed25519PrivateKey, object, str],
    tenant_id: UUID,
) -> None:
    priv, _, _ = ed25519_keypair
    eap_service = EngagementAuthorizationService(
        key_manager=key_manager, audit_logger=audit_logger
    )
    checker = _checker(
        scope_engine=scope_engine,
        ownership_store=ownership_store,
        policy_engine=policy_engine,
        approval_service=approval_service,
        audit_logger=audit_logger,
        eap_service=eap_service,
    )
    target = TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")
    ownership_store.save(_proof(tenant_id, target.value))
    # EAP only pre-authorizes RECON; the requested action is RCE and no
    # operator signatures are supplied → approval must NOT be satisfied.
    profile = _signed_profile(priv, classes=frozenset({ActionClass.RECON}))

    decision = checker.check(
        target_spec=target,
        port=443,
        policy_context=_high_risk_ctx(tenant_id, target.value),
        engagement_profile=profile,
        action_class=ActionClass.RCE,
    )

    assert decision.allowed is False
    assert decision.approval_required is True
    assert decision.approval_verified is False
    assert decision.failure_summary == "approval_missing"
    assert decision.eap_approval_id is None


def test_eap_cannot_widen_scope(
    scope_engine: ScopeEngine,
    ownership_store: InMemoryOwnershipProofStore,
    policy_engine: PolicyEngine,
    approval_service: ApprovalService,
    audit_logger: AuditLogger,
    key_manager: KeyManager,
    ed25519_keypair: tuple[Ed25519PrivateKey, object, str],
    tenant_id: UUID,
) -> None:
    priv, _, _ = ed25519_keypair
    eap_service = EngagementAuthorizationService(
        key_manager=key_manager, audit_logger=audit_logger
    )
    checker = _checker(
        scope_engine=scope_engine,
        ownership_store=ownership_store,
        policy_engine=policy_engine,
        approval_service=approval_service,
        audit_logger=audit_logger,
        eap_service=eap_service,
    )
    # Out-of-scope target — even though the EAP explicitly lists evil.com, the
    # ScopeEngine denies first (SI-2). The EAP never runs.
    target = TargetSpec(kind=TargetKind.URL, url="https://evil.com/pwn")
    profile = _signed_profile(
        priv, classes=frozenset({ActionClass.RCE}), targets=("evil.com",)
    )
    decision = checker.check(
        target_spec=target,
        port=443,
        policy_context=_high_risk_ctx(tenant_id, target.value),
        engagement_profile=profile,
        action_class=ActionClass.RCE,
    )
    assert decision.allowed is False
    assert decision.failure_summary == "target_not_in_scope"


def test_no_eap_service_is_back_compat(
    scope_engine: ScopeEngine,
    ownership_store: InMemoryOwnershipProofStore,
    policy_engine: PolicyEngine,
    approval_service: ApprovalService,
    audit_logger: AuditLogger,
    tenant_id: UUID,
) -> None:
    # Without an EAP collaborator, an approval-gated action with no signatures
    # denies exactly as before (SI-7).
    checker = _checker(
        scope_engine=scope_engine,
        ownership_store=ownership_store,
        policy_engine=policy_engine,
        approval_service=approval_service,
        audit_logger=audit_logger,
        eap_service=None,
    )
    target = TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")
    ownership_store.save(_proof(tenant_id, target.value))
    decision = checker.check(
        target_spec=target,
        port=443,
        policy_context=_high_risk_ctx(tenant_id, target.value),
    )
    assert decision.allowed is False
    assert decision.failure_summary == "approval_missing"
    assert decision.eap_approval_id is None
