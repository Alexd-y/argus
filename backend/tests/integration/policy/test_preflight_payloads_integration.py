"""Integration: ``PreflightChecker`` + :class:`PayloadBuilder`.

Exercises the closed-loop flow where the builder consults the policy
plane BEFORE materialising any payload bytes:

#. Out-of-scope target → :class:`PreflightDeniedError`, no bundle.
#. Missing ownership proof → :class:`PreflightDeniedError`, no bundle.
#. High-risk family + missing approval → :class:`PreflightDeniedError`
   (the policy engine's approval gate fires before the family's own
   approval gate, so the payload bytes never exist in memory).
#. Allowed path → real signed catalog produces a deterministic bundle
   without ever touching production secrets.

The signed-catalog round trip is exercised by
``backend/tests/integration/payloads`` already; here we focus on the
preflight-denial behaviour.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

from src.payloads.builder import (
    PayloadApprovalRequiredError,
    PayloadBuildError,
    PayloadBuildRequest,
    PayloadBuilder,
)
from src.payloads.registry import PayloadRegistry
from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import (
    RiskLevel,
    TargetKind,
    TargetSpec,
)
from src.policy.approval import ApprovalAction, ApprovalRequest
from src.policy.audit import AuditEventType, InMemoryAuditSink
from src.policy.ownership import (
    InMemoryOwnershipProofStore,
    OwnershipMethod,
    OwnershipProof,
)
from src.policy.policy_engine import PolicyContext
from src.policy.preflight import PreflightChecker, PreflightDeniedError


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def real_payload_registry() -> PayloadRegistry:
    here = Path(__file__).resolve()
    backend_dir = here.parents[3]
    catalog = backend_dir / "config" / "payloads"
    if not catalog.is_dir():
        pytest.skip(
            f"signed payload catalog not present at {catalog}; "
            "policy/payloads integration test requires it"
        )
    registry = PayloadRegistry(payloads_dir=catalog)
    registry.load()
    return registry


def _fresh_proof(*, tenant_id: UUID, target: TargetSpec) -> OwnershipProof:
    now = datetime.now(tz=timezone.utc)
    return OwnershipProof(
        challenge_id=uuid4(),
        tenant_id=tenant_id,
        target=target.value,
        method=OwnershipMethod.HTTP_HEADER,
        verified_at=now,
        valid_until=now + timedelta(hours=1),
    )


def _ctx_for(
    *,
    tenant_id: UUID,
    scan_id: UUID,
    target: TargetSpec,
    risk_level: RiskLevel = RiskLevel.LOW,
    phase: ScanPhase = ScanPhase.VULN_ANALYSIS,
    tool_id: str = "sqlmap",
) -> PolicyContext:
    return PolicyContext(
        tenant_id=tenant_id,
        scan_id=scan_id,
        phase=phase,
        risk_level=risk_level,
        tool_id=tool_id,
        target=target.value,
    )


# ---------------------------------------------------------------------------
# Backward compatibility — builder without preflight still works
# ---------------------------------------------------------------------------


def test_builder_without_preflight_runs_unchanged(
    real_payload_registry: PayloadRegistry,
) -> None:
    builder = PayloadBuilder(real_payload_registry)
    bundle = builder.build(
        PayloadBuildRequest(
            family_id="sqli",
            correlation_key="policy-int-1",
            parameters={"param": "id", "canary": "argus-canary-policy-1"},
        )
    )
    assert bundle.family_id == "sqli"
    assert bundle.payloads


# ---------------------------------------------------------------------------
# Allowed path with preflight
# ---------------------------------------------------------------------------


def test_builder_with_preflight_allowed_returns_bundle(
    real_payload_registry: PayloadRegistry,
    preflight_checker: PreflightChecker,
    ownership_store: InMemoryOwnershipProofStore,
    audit_sink: InMemoryAuditSink,
    tenant_id: UUID,
    scan_id: UUID,
    http_target: TargetSpec,
) -> None:
    ownership_store.save(_fresh_proof(tenant_id=tenant_id, target=http_target))
    builder = PayloadBuilder(real_payload_registry, preflight_checker=preflight_checker)
    bundle = builder.build(
        PayloadBuildRequest(
            family_id="sqli",
            correlation_key="policy-int-2",
            parameters={"param": "id", "canary": "argus-canary-policy-2"},
        ),
        preflight_context=_ctx_for(
            tenant_id=tenant_id,
            scan_id=scan_id,
            target=http_target,
            risk_level=RiskLevel.MEDIUM,
        ),
        target_spec=http_target,
    )
    assert bundle.family_id == "sqli"
    assert bundle.payloads
    pass_events = [
        e
        for e in audit_sink.iter_events(tenant_id=tenant_id)
        if e.event_type is AuditEventType.PREFLIGHT_PASS
    ]
    assert pass_events


# ---------------------------------------------------------------------------
# Denial: out-of-scope target
# ---------------------------------------------------------------------------


def test_builder_denies_out_of_scope_target(
    real_payload_registry: PayloadRegistry,
    preflight_checker: PreflightChecker,
    tenant_id: UUID,
    scan_id: UUID,
) -> None:
    out_of_scope = TargetSpec(
        kind=TargetKind.URL, url="https://attacker-controlled.com/login"
    )
    builder = PayloadBuilder(real_payload_registry, preflight_checker=preflight_checker)
    with pytest.raises(PreflightDeniedError) as exc_info:
        builder.build(
            PayloadBuildRequest(
                family_id="sqli",
                correlation_key="policy-int-3",
                parameters={"param": "id", "canary": "argus-canary-policy-3"},
            ),
            preflight_context=_ctx_for(
                tenant_id=tenant_id,
                scan_id=scan_id,
                target=out_of_scope,
                risk_level=RiskLevel.MEDIUM,
            ),
            target_spec=out_of_scope,
        )
    assert exc_info.value.summary == "target_not_in_scope"


# ---------------------------------------------------------------------------
# Denial: missing ownership proof
# ---------------------------------------------------------------------------


def test_builder_denies_missing_ownership(
    real_payload_registry: PayloadRegistry,
    preflight_checker: PreflightChecker,
    tenant_id: UUID,
    scan_id: UUID,
    http_target: TargetSpec,
) -> None:
    builder = PayloadBuilder(real_payload_registry, preflight_checker=preflight_checker)
    with pytest.raises(PreflightDeniedError) as exc_info:
        builder.build(
            PayloadBuildRequest(
                family_id="sqli",
                correlation_key="policy-int-4",
                parameters={"param": "id", "canary": "argus-canary-policy-4"},
            ),
            preflight_context=_ctx_for(
                tenant_id=tenant_id,
                scan_id=scan_id,
                target=http_target,
                risk_level=RiskLevel.MEDIUM,
            ),
            target_spec=http_target,
        )
    assert exc_info.value.summary == "preflight_ownership_missing"


# ---------------------------------------------------------------------------
# Denial: high-risk family without approval flag from caller
# ---------------------------------------------------------------------------


def test_builder_denies_high_risk_without_approval_short_circuits_payload(
    real_payload_registry: PayloadRegistry,
    preflight_checker: PreflightChecker,
    ownership_store: InMemoryOwnershipProofStore,
    tenant_id: UUID,
    scan_id: UUID,
    http_target: TargetSpec,
) -> None:
    ownership_store.save(_fresh_proof(tenant_id=tenant_id, target=http_target))
    builder = PayloadBuilder(real_payload_registry, preflight_checker=preflight_checker)
    # A HIGH-risk EXPLOITATION request without an approval signature MUST
    # surface as a preflight denial — never a PayloadApprovalRequiredError —
    # so payload bytes are never materialised.
    with pytest.raises(PreflightDeniedError) as exc_info:
        builder.build(
            PayloadBuildRequest(
                family_id="rce",
                correlation_key="policy-int-5",
                parameters={
                    "param": "id",
                    "canary": "argus-canary-policy-5",
                    "oast_host": "oast.example.com",
                },
            ),
            preflight_context=_ctx_for(
                tenant_id=tenant_id,
                scan_id=scan_id,
                target=http_target,
                risk_level=RiskLevel.HIGH,
                phase=ScanPhase.EXPLOITATION,
                tool_id="metasploit",
            ),
            target_spec=http_target,
        )
    assert exc_info.value.summary == "approval_missing"


# ---------------------------------------------------------------------------
# Misconfiguration: preflight checker but no context / target
# ---------------------------------------------------------------------------


def test_builder_with_preflight_requires_context_and_target(
    real_payload_registry: PayloadRegistry,
    preflight_checker: PreflightChecker,
) -> None:
    builder = PayloadBuilder(real_payload_registry, preflight_checker=preflight_checker)
    with pytest.raises(PayloadBuildError):
        builder.build(
            PayloadBuildRequest(
                family_id="sqli",
                correlation_key="policy-int-6",
                parameters={"param": "id", "canary": "argus-canary-policy-6"},
            ),
        )


# ---------------------------------------------------------------------------
# Family-level approval gate still fires when preflight ALLOWS the build
# ---------------------------------------------------------------------------


def test_family_approval_gate_still_enforced_after_preflight_pass(
    real_payload_registry: PayloadRegistry,
    preflight_checker: PreflightChecker,
    ownership_store: InMemoryOwnershipProofStore,
    tenant_id: UUID,
    scan_id: UUID,
    http_target: TargetSpec,
    ed25519_keypair: Any,
    approval_service: Any,
) -> None:
    """Belt-and-braces: preflight approval-gate satisfied → family gate still applies.

    The family-level ``requires_approval`` is an independent invariant
    enforced by ``PayloadBuilder.build``. With a HIGH-risk preflight
    approval signature the policy engine allows the build, but the
    builder still demands ``request.approval_id`` for high-risk families.
    """
    ownership_store.save(_fresh_proof(tenant_id=tenant_id, target=http_target))

    private_key, _, _ = ed25519_keypair
    now = datetime.now(tz=timezone.utc)
    request = ApprovalRequest(
        tenant_id=tenant_id,
        action=ApprovalAction.HIGH,
        tool_id="metasploit",
        target=http_target.value,
        justification="Pre-engagement signoff for exploitation phase test",
        created_at=now,
        expires_at=now + timedelta(hours=1),
    )
    signature = approval_service.sign_request(request, private_key=private_key)

    # Build a checker-aware builder, but avoid the family-level approval
    # by *not* providing approval_id; the family gate must still fire as
    # PayloadApprovalRequiredError after preflight clears.
    def _build_with_signed_approval() -> None:
        # Re-run preflight directly to confirm it allows; bypass the
        # builder-level preflight by routing the signed approval through
        # the ``check`` API (the builder always re-checks without
        # signatures).
        decision = preflight_checker.check(
            target_spec=http_target,
            port=None,
            policy_context=_ctx_for(
                tenant_id=tenant_id,
                scan_id=scan_id,
                target=http_target,
                risk_level=RiskLevel.HIGH,
                phase=ScanPhase.EXPLOITATION,
                tool_id="metasploit",
            ),
            approval_request=request,
            approval_signatures=[signature],
        )
        assert decision.allowed is True
        # Now run the builder WITHOUT the preflight checker (signed-approval
        # path lives at the orchestrator boundary, not the builder one).
        plain_builder = PayloadBuilder(real_payload_registry)
        plain_builder.build(
            PayloadBuildRequest(
                family_id="rce",
                correlation_key="policy-int-7",
                parameters={
                    "param": "id",
                    "canary": "argus-canary-policy-7",
                    "oast_host": "oast.example.com",
                },
            ),
        )

    with pytest.raises(PayloadApprovalRequiredError):
        _build_with_signed_approval()
