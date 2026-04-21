"""Shared fixtures for the :mod:`src.policy` integration-test suite.

Mirrors the unit-test conftest but lives in its own module so test
discovery is local. Integration tests compose the policy plane with
``KubernetesSandboxAdapter`` (DRY_RUN) and :class:`PayloadBuilder` to
verify the closed-taxonomy denial path end-to-end.
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
    OwnershipMethod,
    OwnershipProof,
)
from src.policy.policy_engine import (
    PhaseRiskCap,
    PlanTier,
    PolicyContext,
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


@pytest.fixture()
def tenant_id() -> UUID:
    return UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")


@pytest.fixture()
def scan_id() -> UUID:
    return UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")


@pytest.fixture()
def ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key, public_key_id(public_key)


@pytest.fixture()
def key_manager(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> KeyManager:
    keys_dir = tmp_path / "_policy_int_keys"
    keys_dir.mkdir()
    _, public_key, kid = ed25519_keypair
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    (keys_dir / f"{kid}.ed25519.pub").write_bytes(pub_bytes)
    manager = KeyManager(keys_dir)
    manager.load()
    return manager


@pytest.fixture()
def audit_sink() -> InMemoryAuditSink:
    return InMemoryAuditSink()


@pytest.fixture()
def audit_logger(audit_sink: InMemoryAuditSink) -> AuditLogger:
    return AuditLogger(audit_sink)


@pytest.fixture()
def ownership_store() -> InMemoryOwnershipProofStore:
    return InMemoryOwnershipProofStore()


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
def scope_engine() -> ScopeEngine:
    return ScopeEngine(_DEFAULT_SCOPE_RULES)


@pytest.fixture()
def tenant_policy(tenant_id: UUID) -> TenantPolicy:
    return TenantPolicy(
        tenant_id=tenant_id,
        plan_tier=PlanTier.ENTERPRISE,
        default_phase_max_risk=RiskLevel.LOW,
        phase_caps=(
            PhaseRiskCap(phase=ScanPhase.RECON, max_risk=RiskLevel.LOW),
            PhaseRiskCap(phase=ScanPhase.VULN_ANALYSIS, max_risk=RiskLevel.MEDIUM),
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
    ownership_store: InMemoryOwnershipProofStore,
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


@pytest.fixture()
def http_target() -> TargetSpec:
    return TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")


@pytest.fixture()
def fresh_proof(tenant_id: UUID, http_target: TargetSpec) -> OwnershipProof:
    now = datetime.now(tz=timezone.utc)
    return OwnershipProof(
        challenge_id=uuid4(),
        tenant_id=tenant_id,
        target=http_target.value,
        method=OwnershipMethod.HTTP_HEADER,
        verified_at=now,
        valid_until=now + timedelta(hours=1),
    )


def _build_tool_job(
    *,
    tenant_id: UUID,
    scan_id: UUID,
    target: TargetSpec,
    tool_id: str,
    phase: ScanPhase,
    risk_level: RiskLevel,
    parameters: dict[str, str] | None = None,
    requires_approval: bool = False,
    approval_id: UUID | None = None,
) -> ToolJob:
    return ToolJob(
        id=uuid4(),
        tenant_id=tenant_id,
        scan_id=scan_id,
        tool_id=tool_id,
        phase=phase,
        risk_level=risk_level,
        target=target,
        parameters=parameters or {},
        outputs_dir="/tmp/argus-out",
        timeout_s=300,
        requires_approval=requires_approval,
        approval_id=approval_id,
        correlation_id=f"argus-int-{tool_id}",
    )


@pytest.fixture()
def tool_job_factory(tenant_id: UUID, scan_id: UUID) -> Callable[..., ToolJob]:
    def _factory(**overrides: Any) -> ToolJob:
        kwargs: dict[str, Any] = {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
            "target": TargetSpec(
                kind=TargetKind.URL, url="https://api.example.com/v1/users"
            ),
            "tool_id": "nmap_quick",
            "phase": ScanPhase.RECON,
            "risk_level": RiskLevel.PASSIVE,
        }
        kwargs.update(overrides)
        return _build_tool_job(**kwargs)

    return _factory


def _policy_context(
    *,
    tenant_id: UUID,
    scan_id: UUID,
    target: TargetSpec,
    risk_level: RiskLevel = RiskLevel.LOW,
    phase: ScanPhase = ScanPhase.RECON,
    tool_id: str = "nmap_quick",
    has_ownership_proof: bool = False,
) -> PolicyContext:
    return PolicyContext(
        tenant_id=tenant_id,
        scan_id=scan_id,
        phase=phase,
        risk_level=risk_level,
        tool_id=tool_id,
        target=target.value,
        has_ownership_proof=has_ownership_proof,
    )


@pytest.fixture()
def policy_context_factory(
    tenant_id: UUID, scan_id: UUID
) -> Callable[..., PolicyContext]:
    def _factory(**overrides: Any) -> PolicyContext:
        kwargs: dict[str, Any] = {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
            "target": TargetSpec(
                kind=TargetKind.URL, url="https://api.example.com/v1/users"
            ),
        }
        kwargs.update(overrides)
        return _policy_context(**kwargs)

    return _factory
