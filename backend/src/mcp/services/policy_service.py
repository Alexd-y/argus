"""Policy / scope helpers consumed by MCP ``policy.*`` and ``scope.*`` tools.

The MCP layer treats :class:`PolicyEngine` and :class:`ScopeEngine` as pure
functions — callers project the relevant counters / rule sets into the
engine via dependency injection. Production deployments bind these
factories to per-tenant DB lookups; tests bind them to in-memory fixtures.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from uuid import UUID

from src.mcp.exceptions import ValidationError
from src.mcp.schemas.policy import (
    PolicyEvaluateInput,
    PolicyEvaluateResult,
    PolicyEvaluationOutcome,
    ScopeVerifyInput,
    ScopeVerifyResult,
)
from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel, TargetKind, TargetSpec
from src.policy.policy_engine import (
    PlanTier,
    PolicyContext,
    PolicyEngine,
    TenantPolicy,
)
from src.policy.scope import ScopeEngine

_logger = logging.getLogger(__name__)

ScopeEngineFactory = Callable[[str], ScopeEngine]
PolicyEngineFactory = Callable[[str], tuple[PolicyEngine, TenantPolicy]]

_FACTORY_LOCK = threading.Lock()
_SCOPE_FACTORY: ScopeEngineFactory | None = None
_POLICY_FACTORY: PolicyEngineFactory | None = None


def set_scope_engine_factory(factory: ScopeEngineFactory | None) -> None:
    """Inject a per-tenant scope engine builder (test / app startup hook)."""
    global _SCOPE_FACTORY
    with _FACTORY_LOCK:
        _SCOPE_FACTORY = factory


def set_policy_engine_factory(factory: PolicyEngineFactory | None) -> None:
    """Inject a per-tenant policy engine + policy builder (test / startup hook)."""
    global _POLICY_FACTORY
    with _FACTORY_LOCK:
        _POLICY_FACTORY = factory


def _scope_engine_for(tenant_id: str) -> ScopeEngine:
    if _SCOPE_FACTORY is not None:
        return _SCOPE_FACTORY(tenant_id)
    return ScopeEngine(rules=())


def _policy_engine_for(tenant_id: str) -> tuple[PolicyEngine, TenantPolicy]:
    if _POLICY_FACTORY is not None:
        return _POLICY_FACTORY(tenant_id)
    policy = TenantPolicy(
        tenant_id=_coerce_tenant_uuid(tenant_id),
        plan_tier=PlanTier.FREE,
    )
    return PolicyEngine(policy), policy


def _coerce_tenant_uuid(tenant_id: str) -> UUID:
    try:
        return UUID(str(tenant_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValidationError("tenant_id must be a valid UUID.") from exc


def _coerce_target_spec(raw: str) -> TargetSpec:
    """Map a user-provided target string to a :class:`TargetSpec`.

    Defaults to :attr:`TargetKind.URL` when the value contains ``://``,
    falls back to :attr:`TargetKind.DOMAIN` otherwise. CIDR / IP detection
    is left to the caller — operators can submit them directly via the
    sandbox API.
    """
    cleaned = (raw or "").strip()
    if not cleaned:
        raise ValidationError("target must be a non-empty string.")
    try:
        if "://" in cleaned:
            return TargetSpec(kind=TargetKind.URL, url=cleaned)
        return TargetSpec(kind=TargetKind.DOMAIN, domain=cleaned)
    except Exception as exc:  # pragma: no cover — pydantic raises ValidationError
        raise ValidationError(f"target {cleaned!r} is not a valid target.") from exc


def verify_scope(*, tenant_id: str, payload: ScopeVerifyInput) -> ScopeVerifyResult:
    """Run the customer-scope check for ``payload.target``.

    Returns a structured decision; raises :class:`ScopeViolationError` only
    when the caller asked for strict enforcement (currently never — the
    tool surface returns the structured decision so the LLM can decide).
    """
    target = _coerce_target_spec(payload.target)
    engine = _scope_engine_for(tenant_id)
    decision = engine.check(target, port=payload.port)
    return ScopeVerifyResult(
        target=payload.target,
        allowed=decision.allowed,
        failure_summary=decision.failure_summary,
        matched_rule_index=decision.matched_rule_index,
    )


def evaluate_policy(
    *, tenant_id: str, payload: PolicyEvaluateInput
) -> PolicyEvaluateResult:
    """Run :class:`PolicyEngine.evaluate` and translate to MCP enums."""
    engine, policy = _policy_engine_for(tenant_id)

    risk = RiskLevel(payload.risk_level.value)

    target = _coerce_target_spec(payload.target)
    scope_engine = _scope_engine_for(tenant_id)
    scope_decision = scope_engine.check(target)
    target_owned = scope_decision.allowed

    context = PolicyContext(
        tenant_id=policy.tenant_id,
        scan_id=None,
        phase=_phase_for_risk(risk),
        tool_id=payload.tool_id,
        family_id=payload.payload_family,
        target=payload.target,
        has_ownership_proof=target_owned,
        risk_level=risk,
        recent_invocations=0,
        spend_today_cents=0,
        spend_this_month_cents=0,
        estimated_cost_cents=int(payload.estimated_cost_cents),
    )
    decision = engine.evaluate(context)
    if not decision.allowed:
        return PolicyEvaluateResult(
            outcome=PolicyEvaluationOutcome.DENIED,
            failure_summary=decision.failure_summary,
            requires_approval=False,
            risk_level=payload.risk_level,
        )
    if decision.requires_approval:
        return PolicyEvaluateResult(
            outcome=PolicyEvaluationOutcome.REQUIRES_APPROVAL,
            failure_summary=None,
            requires_approval=True,
            risk_level=payload.risk_level,
        )
    return PolicyEvaluateResult(
        outcome=PolicyEvaluationOutcome.ALLOWED,
        failure_summary=None,
        requires_approval=False,
        risk_level=payload.risk_level,
    )


def _phase_for_risk(risk: RiskLevel) -> ScanPhase:
    if risk in {RiskLevel.PASSIVE}:
        return ScanPhase.RECON
    if risk in {RiskLevel.LOW, RiskLevel.MEDIUM}:
        return ScanPhase.VULN_ANALYSIS
    return ScanPhase.EXPLOITATION


__all__ = [
    "PolicyEngineFactory",
    "ScopeEngineFactory",
    "evaluate_policy",
    "set_policy_engine_factory",
    "set_scope_engine_factory",
    "verify_scope",
]
