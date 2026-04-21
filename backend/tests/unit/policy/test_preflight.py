"""Unit tests for :mod:`src.policy.preflight`.

Verifies composition order, denial short-circuiting, ownership lookup,
the ``check_tool_job`` defense-in-depth path, and that pass / deny audit
events are emitted with stable taxonomy values.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import (
    RiskLevel,
    TargetKind,
    TargetSpec,
    ToolJob,
)
from src.policy.approval import (
    ApprovalAction,
    ApprovalRequest,
    ApprovalService,
)
from src.policy.audit import AuditEventType, InMemoryAuditSink
from src.policy.ownership import (
    InMemoryOwnershipProofStore,
    OwnershipMethod,
    OwnershipProof,
)
from src.policy.policy_engine import PolicyContext
from src.policy.preflight import (
    PREFLIGHT_DENIED_TAXONOMY,
    PreflightChecker,
    PreflightDeniedError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_proof(
    *,
    tenant_id: UUID,
    target: str,
    valid_for: timedelta = timedelta(hours=1),
) -> OwnershipProof:
    now = datetime.now(tz=timezone.utc)
    return OwnershipProof(
        challenge_id=uuid4(),
        tenant_id=tenant_id,
        target=target,
        method=OwnershipMethod.HTTP_HEADER,
        verified_at=now,
        valid_until=now + valid_for,
    )


def _ctx(
    *,
    tenant_id: UUID,
    risk_level: RiskLevel = RiskLevel.LOW,
    phase: ScanPhase = ScanPhase.RECON,
    tool_id: str = "nmap_quick",
    target: str = "https://api.example.com/v1/users",
) -> PolicyContext:
    return PolicyContext(
        tenant_id=tenant_id,
        scan_id=uuid4(),
        phase=phase,
        risk_level=risk_level,
        tool_id=tool_id,
        target=target,
    )


# ---------------------------------------------------------------------------
# Composition order
# ---------------------------------------------------------------------------


class TestCompositionOrder:
    def test_scope_denial_short_circuits(
        self,
        tenant_id: UUID,
        ownership_store: InMemoryOwnershipProofStore,
        preflight_checker: PreflightChecker,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        # Out-of-scope target — scope denies immediately, ownership lookup
        # never happens, policy / approval never happen.
        target = TargetSpec(kind=TargetKind.URL, url="https://other.com/")
        ownership_store.save(
            _make_proof(tenant_id=tenant_id, target="https://other.com/")
        )
        decision = preflight_checker.check(
            target_spec=target,
            port=None,
            policy_context=_ctx(tenant_id=tenant_id, target="https://other.com/"),
        )
        assert decision.allowed is False
        assert decision.failure_summary == "target_not_in_scope"
        events = list(audit_sink.iter_events(tenant_id=tenant_id))
        # Only the preflight DENY event — ownership/policy/approval never ran.
        assert {e.event_type for e in events} == {AuditEventType.PREFLIGHT_DENY}

    def test_ownership_denial_after_scope_pass(
        self,
        tenant_id: UUID,
        preflight_checker: PreflightChecker,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        target = TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")
        decision = preflight_checker.check(
            target_spec=target,
            port=None,
            policy_context=_ctx(tenant_id=tenant_id, risk_level=RiskLevel.LOW),
        )
        assert decision.allowed is False
        assert decision.failure_summary == "preflight_ownership_missing"
        # Scope passed → no scope event yet, but preflight DENY emitted.
        events = list(audit_sink.iter_events(tenant_id=tenant_id))
        assert events[-1].event_type is AuditEventType.PREFLIGHT_DENY


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestPreflightHappyPath:
    def test_low_risk_with_proof_passes(
        self,
        tenant_id: UUID,
        ownership_store: InMemoryOwnershipProofStore,
        preflight_checker: PreflightChecker,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        target = TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")
        ownership_store.save(_make_proof(tenant_id=tenant_id, target=target.value))
        decision = preflight_checker.check(
            target_spec=target,
            port=443,
            policy_context=_ctx(tenant_id=tenant_id, target=target.value),
        )
        assert decision.allowed is True
        assert decision.failure_summary is None
        assert decision.approval_required is False
        events = list(audit_sink.iter_events(tenant_id=tenant_id))
        assert events[-1].event_type is AuditEventType.PREFLIGHT_PASS

    def test_passive_action_skips_ownership(
        self,
        tenant_id: UUID,
        preflight_checker: PreflightChecker,
    ) -> None:
        target = TargetSpec(kind=TargetKind.HOST, host="api.example.com")
        decision = preflight_checker.check(
            target_spec=target,
            port=None,
            policy_context=_ctx(
                tenant_id=tenant_id,
                target=target.value,
                risk_level=RiskLevel.PASSIVE,
            ),
        )
        assert decision.allowed is True


# ---------------------------------------------------------------------------
# Approval requirement
# ---------------------------------------------------------------------------


class TestApprovalGate:
    def test_high_risk_without_approval_denied(
        self,
        tenant_id: UUID,
        ownership_store: InMemoryOwnershipProofStore,
        preflight_checker: PreflightChecker,
    ) -> None:
        target = TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")
        ownership_store.save(_make_proof(tenant_id=tenant_id, target=target.value))
        decision = preflight_checker.check(
            target_spec=target,
            port=443,
            policy_context=_ctx(
                tenant_id=tenant_id,
                target=target.value,
                risk_level=RiskLevel.HIGH,
                phase=ScanPhase.EXPLOITATION,
                tool_id="metasploit",
            ),
        )
        assert decision.allowed is False
        assert decision.failure_summary == "approval_missing"
        assert decision.approval_required is True

    def test_high_risk_with_valid_approval_passes(
        self,
        tenant_id: UUID,
        ownership_store: InMemoryOwnershipProofStore,
        preflight_checker: PreflightChecker,
        ed25519_keypair: tuple[Ed25519PrivateKey, object, str],
        approval_service: ApprovalService,
    ) -> None:
        priv, _, _ = ed25519_keypair
        target = TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")
        ownership_store.save(_make_proof(tenant_id=tenant_id, target=target.value))
        now = datetime.now(tz=timezone.utc)
        request = ApprovalRequest(
            tenant_id=tenant_id,
            action=ApprovalAction.HIGH,
            tool_id="metasploit",
            target=target.value,
            justification="Pre-engagement signoff for exploit phase",
            created_at=now,
            expires_at=now + timedelta(hours=1),
        )
        signature = approval_service.sign_request(request, private_key=priv)
        decision = preflight_checker.check(
            target_spec=target,
            port=443,
            policy_context=_ctx(
                tenant_id=tenant_id,
                target=target.value,
                risk_level=RiskLevel.HIGH,
                phase=ScanPhase.EXPLOITATION,
                tool_id="metasploit",
            ),
            approval_request=request,
            approval_signatures=[signature],
        )
        assert decision.allowed is True
        assert decision.approval_required is True
        assert decision.approval_verified is True


# ---------------------------------------------------------------------------
# assert_allowed
# ---------------------------------------------------------------------------


class TestPreflightAssertAllowed:
    def test_raises_on_denial(
        self, tenant_id: UUID, preflight_checker: PreflightChecker
    ) -> None:
        target = TargetSpec(kind=TargetKind.URL, url="https://blocked.com/")
        with pytest.raises(PreflightDeniedError) as exc_info:
            preflight_checker.assert_allowed(
                target_spec=target,
                port=None,
                policy_context=_ctx(tenant_id=tenant_id, target="https://blocked.com/"),
            )
        assert exc_info.value.summary == "target_not_in_scope"
        assert exc_info.value.decision.allowed is False

    def test_returns_decision_on_pass(
        self,
        tenant_id: UUID,
        ownership_store: InMemoryOwnershipProofStore,
        preflight_checker: PreflightChecker,
    ) -> None:
        target = TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")
        ownership_store.save(_make_proof(tenant_id=tenant_id, target=target.value))
        decision = preflight_checker.assert_allowed(
            target_spec=target,
            port=443,
            policy_context=_ctx(tenant_id=tenant_id, target=target.value),
        )
        assert decision.allowed is True


# ---------------------------------------------------------------------------
# check_tool_job convenience
# ---------------------------------------------------------------------------


class TestCheckToolJob:
    def test_passes_with_proof_in_store(
        self,
        tenant_id: UUID,
        ownership_store: InMemoryOwnershipProofStore,
        preflight_checker: PreflightChecker,
        tool_job_factory: Callable[..., ToolJob],
    ) -> None:
        target = TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")
        ownership_store.save(_make_proof(tenant_id=tenant_id, target=target.value))
        job = tool_job_factory(target=target)
        decision = preflight_checker.check_tool_job(job)
        assert decision.allowed is True

    def test_denies_when_ownership_expired(
        self,
        tenant_id: UUID,
        ownership_store: InMemoryOwnershipProofStore,
        preflight_checker: PreflightChecker,
        tool_job_factory: Callable[..., ToolJob],
    ) -> None:
        target = TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")
        now = datetime.now(tz=timezone.utc)
        expired = OwnershipProof(
            challenge_id=uuid4(),
            tenant_id=tenant_id,
            target=target.value,
            method=OwnershipMethod.HTTP_HEADER,
            verified_at=now - timedelta(hours=2),
            valid_until=now - timedelta(seconds=1),
        )
        ownership_store.save(expired)
        job = tool_job_factory(target=target, risk_level=RiskLevel.LOW)
        decision = preflight_checker.check_tool_job(job)
        assert decision.allowed is False
        assert decision.failure_summary == "preflight_ownership_expired"

    def test_high_risk_with_approval_id_passes_without_signatures(
        self,
        tenant_id: UUID,
        ownership_store: InMemoryOwnershipProofStore,
        preflight_checker: PreflightChecker,
        tool_job_factory: Callable[..., ToolJob],
    ) -> None:
        target = TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")
        ownership_store.save(_make_proof(tenant_id=tenant_id, target=target.value))
        # ToolJob requires ``approval_id`` whenever ``requires_approval``
        # is True. The convenience ``check_tool_job`` path is a defense-
        # in-depth re-check; without signatures it only verifies that
        # ``approval_id`` was set upstream — the orchestrator is
        # responsible for verifying signatures BEFORE enqueueing.
        approval_id = uuid4()
        job: ToolJob = tool_job_factory(
            target=target,
            risk_level=RiskLevel.HIGH,
            phase=ScanPhase.EXPLOITATION,
            tool_id="metasploit",
            requires_approval=True,
            approval_id=approval_id,
        )
        decision = preflight_checker.check_tool_job(job)
        assert decision.allowed is True
        assert decision.approval_required is True
        # ``approval_verified`` is False because the convenience path does
        # not have signatures available.
        assert decision.approval_verified is False

    def test_high_risk_without_approval_id_denied(
        self,
        tenant_id: UUID,
        ownership_store: InMemoryOwnershipProofStore,
        preflight_checker: PreflightChecker,
        scan_id: UUID,
    ) -> None:
        # Build a HIGH-risk job WITHOUT approval_id by hand (the
        # ``ToolJob`` validator rejects this combination, so we can only
        # exercise the deny branch through the underlying ``check`` call
        # with a HIGH-risk policy context).
        target = TargetSpec(kind=TargetKind.URL, url="https://api.example.com/v1/users")
        ownership_store.save(_make_proof(tenant_id=tenant_id, target=target.value))
        ctx = PolicyContext(
            tenant_id=tenant_id,
            scan_id=scan_id,
            phase=ScanPhase.EXPLOITATION,
            risk_level=RiskLevel.HIGH,
            tool_id="metasploit",
            target=target.value,
            has_ownership_proof=True,
        )
        decision = preflight_checker.check(
            target_spec=target, port=443, policy_context=ctx
        )
        assert decision.allowed is False
        assert decision.failure_summary == "approval_missing"
        assert decision.approval_required is True


# ---------------------------------------------------------------------------
# Public taxonomy constant
# ---------------------------------------------------------------------------


def test_preflight_denied_taxonomy_constant() -> None:
    # The constant is consumed by sandbox + payloads to render a stable
    # ``failure_reason``. Drift would silently break audit consumers.
    assert PREFLIGHT_DENIED_TAXONOMY == "preflight_denied"
