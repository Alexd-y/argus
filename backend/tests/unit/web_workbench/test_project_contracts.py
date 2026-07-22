"""Unit tests for Web Workbench project/scope/EAP contracts (WB-P1-FOUNDATION).

Covers:

* strict contract validation (``extra="forbid"``, default-deny scope);
* scope evaluation delegating to the shared :class:`ScopeEngine`
  (allow / out-of-scope / deny-shadows-allow);
* fail-closed EAP evaluation (unparseable / unsigned / expired / valid).

No database and no network — pure domain logic (SI-WB-1 gate + shared EAP).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from src.pipeline.contracts.tool_job import TargetKind, TargetSpec
from src.policy.audit import AuditLogger, InMemoryAuditSink
from src.policy.engagement_authorization import (
    ActionClass,
    EngagementAuthorizationProfile,
    EngagementAuthorizationService,
)
from src.policy.scope import ScopeKind, ScopeRule
from src.sandbox.signing import KeyManager, public_key_id
from src.web_workbench.contracts import WorkbenchProjectCreate
from src.web_workbench.projects import (
    EAP_STATUS_EXPIRED,
    EAP_STATUS_INVALID,
    EAP_STATUS_VERIFIED,
    ProjectScopeService,
    evaluate_eap,
)


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Contracts
# ---------------------------------------------------------------------------


def test_project_create_requires_at_least_one_scope_rule() -> None:
    with pytest.raises(ValidationError):
        WorkbenchProjectCreate(name="app", scope_rules=())


def test_project_create_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        WorkbenchProjectCreate(
            name="app",
            scope_rules=(ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com"),),
            bogus_field="x",  # type: ignore[call-arg]
        )


def test_project_create_never_accepts_raw_secret_only_a_ref() -> None:
    project = WorkbenchProjectCreate(
        name="app",
        scope_rules=(ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com"),),
        secrets_ref="vault://tenant/app/creds",
    )
    assert project.secrets_ref == "vault://tenant/app/creds"
    assert not hasattr(project, "password")


# ---------------------------------------------------------------------------
# Scope service (delegates to shared ScopeEngine)
# ---------------------------------------------------------------------------


@pytest.fixture()
def scope_rules() -> tuple[ScopeRule, ...]:
    return (
        ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com"),
        ScopeRule(kind=ScopeKind.HOST, pattern="staging.example.com", deny=True),
    )


def test_scope_service_allows_in_scope_target(
    scope_rules: tuple[ScopeRule, ...],
) -> None:
    service = ProjectScopeService(scope_rules)
    target = TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1")
    assert service.is_in_scope(target) is True


def test_scope_service_denies_out_of_scope_target(
    scope_rules: tuple[ScopeRule, ...],
) -> None:
    service = ProjectScopeService(scope_rules)
    target = TargetSpec(kind=TargetKind.URL, url="https://evil.com/steal")
    decision = service.check(target)
    assert decision.allowed is False


def test_scope_service_deny_rule_shadows_allow(
    scope_rules: tuple[ScopeRule, ...],
) -> None:
    service = ProjectScopeService(scope_rules)
    target = TargetSpec(kind=TargetKind.HOST, host="staging.example.com")
    assert service.is_in_scope(target) is False


def test_scope_service_empty_rules_is_default_deny() -> None:
    service = ProjectScopeService(())
    target = TargetSpec(kind=TargetKind.DOMAIN, domain="example.com")
    assert service.is_in_scope(target) is False


# ---------------------------------------------------------------------------
# EAP evaluation (fail-closed, delegates to EngagementAuthorizationService)
# ---------------------------------------------------------------------------


@pytest.fixture()
def keypair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    return priv, public_key_id(priv.public_key())


@pytest.fixture()
def eap_service(
    tmp_path: Path, keypair: tuple[Ed25519PrivateKey, str]
) -> EngagementAuthorizationService:
    priv, kid = keypair
    keys_dir = tmp_path / "_keys"
    keys_dir.mkdir()
    (keys_dir / f"{kid}.ed25519.pub").write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    manager = KeyManager(keys_dir)
    manager.load()
    return EngagementAuthorizationService(
        key_manager=manager, audit_logger=AuditLogger(InMemoryAuditSink())
    )


def _profile(expires: datetime) -> EngagementAuthorizationProfile:
    return EngagementAuthorizationProfile(
        engagement_id="eng-wb-001",
        authorized_by="ciso@example.com",
        targets=("example.com",),
        allow_action_classes=frozenset({ActionClass.INJECTION_SAFE}),
        max_request_budget=1000,
        expires=expires,
    )


def test_evaluate_eap_unparseable_blob_is_invalid(
    eap_service: EngagementAuthorizationService,
) -> None:
    result = evaluate_eap({"not": "a-profile"}, eap_service=eap_service)
    assert result.status == EAP_STATUS_INVALID
    assert result.profile is None


def test_evaluate_eap_unsigned_profile_is_invalid(
    eap_service: EngagementAuthorizationService,
) -> None:
    unsigned = _profile(_now() + timedelta(days=1)).model_dump(mode="json")
    result = evaluate_eap(unsigned, eap_service=eap_service)
    assert result.status == EAP_STATUS_INVALID
    assert result.profile is not None  # parsed but not signed


def test_evaluate_eap_valid_signed_profile_is_verified(
    eap_service: EngagementAuthorizationService,
    keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    priv, _ = keypair
    signed = EngagementAuthorizationService.sign_profile(
        _profile(_now() + timedelta(days=1)), private_key=priv
    )
    result = evaluate_eap(signed.model_dump(mode="json"), eap_service=eap_service)
    assert result.status == EAP_STATUS_VERIFIED
    assert result.engagement_id == "eng-wb-001"
    assert result.signer_key_id is not None


def test_evaluate_eap_expired_signed_profile_is_expired(
    eap_service: EngagementAuthorizationService,
    keypair: tuple[Ed25519PrivateKey, str],
) -> None:
    priv, _ = keypair
    signed = EngagementAuthorizationService.sign_profile(
        _profile(_now() - timedelta(seconds=1)), private_key=priv
    )
    result = evaluate_eap(signed.model_dump(mode="json"), eap_service=eap_service)
    assert result.status == EAP_STATUS_EXPIRED
