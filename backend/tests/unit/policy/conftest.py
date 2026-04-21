"""Shared fixtures for the :mod:`src.policy` unit-test suite.

The fixtures here build minimal, deterministic instances of every policy
plane object so individual test files can stay focused on assertions.
Nothing in this module touches the network, the database, or the real
Kubernetes SDK — pure dependency injection.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import (
    RiskLevel,
    TargetKind,
    TargetSpec,
    ToolJob,
)
from src.policy.approval import ApprovalService
from src.policy.audit import AuditLogger, InMemoryAuditSink
from src.policy.ownership import (
    InMemoryOwnershipProofStore,
    OwnershipProofStore,
)
from src.policy.policy_engine import (
    PhaseRiskCap,
    PlanTier,
    PolicyEngine,
    TenantPolicy,
)
from src.policy.preflight import PreflightChecker
from src.policy.scope import (
    PortRange,
    ScopeEngine,
    ScopeKind,
    ScopeRule,
)
from src.sandbox.signing import KeyManager, public_key_id


# ---------------------------------------------------------------------------
# UUID generation helpers (deterministic when the test caller wants reuse)
# ---------------------------------------------------------------------------


@pytest.fixture()
def tenant_id() -> UUID:
    return UUID("11111111-1111-4111-8111-111111111111")


@pytest.fixture()
def scan_id() -> UUID:
    return UUID("22222222-2222-4222-8222-222222222222")


@pytest.fixture()
def actor_id() -> UUID:
    return UUID("33333333-3333-4333-8333-333333333333")


# ---------------------------------------------------------------------------
# Cryptographic key plumbing
# ---------------------------------------------------------------------------


@pytest.fixture()
def ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key, public_key_id(public_key)


@pytest.fixture()
def second_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    """Distinct keypair used for dual-control assertions."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key, public_key_id(public_key)


@pytest.fixture()
def key_manager(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    second_ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> KeyManager:
    keys_dir = tmp_path / "_keys"
    keys_dir.mkdir()
    for _, public_key, kid in (ed25519_keypair, second_ed25519_keypair):
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        (keys_dir / f"{kid}.ed25519.pub").write_bytes(pub_bytes)
    manager = KeyManager(keys_dir)
    manager.load()
    return manager


# ---------------------------------------------------------------------------
# Audit + ownership stores
# ---------------------------------------------------------------------------


@pytest.fixture()
def audit_sink() -> InMemoryAuditSink:
    return InMemoryAuditSink()


@pytest.fixture()
def audit_logger(audit_sink: InMemoryAuditSink) -> AuditLogger:
    return AuditLogger(audit_sink)


@pytest.fixture()
def ownership_store() -> InMemoryOwnershipProofStore:
    return InMemoryOwnershipProofStore()


# ---------------------------------------------------------------------------
# Scope / policy / approval engines
# ---------------------------------------------------------------------------


_DEFAULT_SCOPE_RULES = (
    ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com"),
    ScopeRule(
        kind=ScopeKind.URL,
        pattern="https://api.example.com/v1",
        ports=(PortRange(low=443, high=443),),
    ),
    ScopeRule(kind=ScopeKind.CIDR, pattern="10.0.0.0/8"),
    ScopeRule(kind=ScopeKind.HOST, pattern="staging.example.com", deny=True),
)


@pytest.fixture()
def scope_rules() -> tuple[ScopeRule, ...]:
    return _DEFAULT_SCOPE_RULES


@pytest.fixture()
def scope_engine(scope_rules: tuple[ScopeRule, ...]) -> ScopeEngine:
    return ScopeEngine(scope_rules)


@pytest.fixture()
def tenant_policy(tenant_id: UUID) -> TenantPolicy:
    """Permissive default policy used by happy-path tests.

    Tests that specifically need a restrictive plan tier (FREE / STARTER /
    PRO) build their own :class:`TenantPolicy` instance instead of mutating
    this fixture.
    """
    return TenantPolicy(
        tenant_id=tenant_id,
        plan_tier=PlanTier.ENTERPRISE,
        default_phase_max_risk=RiskLevel.LOW,
        phase_caps=(
            PhaseRiskCap(
                phase=ScanPhase.RECON,
                max_risk=RiskLevel.LOW,
            ),
            PhaseRiskCap(
                phase=ScanPhase.VULN_ANALYSIS,
                max_risk=RiskLevel.MEDIUM,
            ),
            PhaseRiskCap(
                phase=ScanPhase.EXPLOITATION,
                max_risk=RiskLevel.HIGH,
                requires_approval_at_or_above=RiskLevel.HIGH,
            ),
        ),
        require_ownership_proof=True,
    )


@pytest.fixture()
def policy_engine(tenant_policy: TenantPolicy) -> PolicyEngine:
    return PolicyEngine(tenant_policy)


@pytest.fixture()
def approval_service(
    key_manager: KeyManager, audit_logger: AuditLogger
) -> ApprovalService:
    return ApprovalService(key_manager=key_manager, audit_logger=audit_logger)


@pytest.fixture()
def preflight_checker(
    scope_engine: ScopeEngine,
    ownership_store: OwnershipProofStore,
    policy_engine: PolicyEngine,
    approval_service: ApprovalService,
    audit_logger: AuditLogger,
) -> PreflightChecker:
    return PreflightChecker(
        scope_engine=scope_engine,
        ownership_store=ownership_store,
        policy_engine=policy_engine,
        approval_service=approval_service,
        audit_logger=audit_logger,
    )


# ---------------------------------------------------------------------------
# Domain-object factories used across modules
# ---------------------------------------------------------------------------


@pytest.fixture()
def url_target() -> TargetSpec:
    return TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")


@pytest.fixture()
def host_target() -> TargetSpec:
    return TargetSpec(kind=TargetKind.HOST, host="api.example.com")


@pytest.fixture()
def ip_target() -> TargetSpec:
    return TargetSpec(kind=TargetKind.IP, ip="10.1.2.3")


def _make_tool_job(
    *,
    tenant_id: UUID,
    scan_id: UUID,
    target: TargetSpec,
    tool_id: str = "nmap_quick",
    phase: ScanPhase = ScanPhase.RECON,
    risk_level: RiskLevel = RiskLevel.PASSIVE,
    requires_approval: bool = False,
    approval_id: UUID | None = None,
    correlation_id: str = "trace-abcd",
) -> ToolJob:
    return ToolJob(
        id=uuid4(),
        tenant_id=tenant_id,
        scan_id=scan_id,
        tool_id=tool_id,
        phase=phase,
        risk_level=risk_level,
        target=target,
        outputs_dir="/tmp/argus-out",
        timeout_s=300,
        requires_approval=requires_approval,
        approval_id=approval_id,
        correlation_id=correlation_id,
    )


@pytest.fixture()
def tool_job_factory(tenant_id: UUID, scan_id: UUID) -> Callable[..., ToolJob]:
    """Return a factory that builds :class:`ToolJob` with sane defaults."""

    def _factory(**overrides: Any) -> ToolJob:
        kwargs: dict[str, Any] = {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
            "target": TargetSpec(
                kind=TargetKind.URL, url="https://api.example.com/v1/users"
            ),
        }
        kwargs.update(overrides)
        return _make_tool_job(**kwargs)

    return _factory


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def fixed_now() -> datetime:
    """A stable UTC instant used by ``frozen_clock`` tests."""
    return datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def expires_in_one_hour(fixed_now: datetime) -> datetime:
    return fixed_now + timedelta(hours=1)


@pytest.fixture()
def expired_at(fixed_now: datetime) -> datetime:
    return fixed_now - timedelta(seconds=1)
