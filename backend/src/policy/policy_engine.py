"""Per-tenant policy evaluation (Backlog/dev1_md §8, §9, §16).

The :class:`PolicyEngine` is a **pure function**: given a per-tenant
:class:`TenantPolicy` and a :class:`PolicyContext` describing the
proposed action, it returns a :class:`PolicyDecision`.

Concerns covered:

* **Per-phase risk caps** — e.g. recon may run ``RiskLevel.PASSIVE`` and
  ``LOW`` only; exploitation is the only phase allowed to touch ``HIGH``.
* **Per-family bans** — a tenant may explicitly forbid a payload family
  (e.g. ``demo_rce``) regardless of plan tier.
* **Per-tool rate limits** — sliding-window counters keyed on
  ``(tool_id, scan_id)``. The engine is stateless; the caller passes
  the counter snapshot via :attr:`PolicyContext.recent_invocations`.
* **Budget caps** — daily / monthly budget in cents; failure surfaces a
  closed-taxonomy reason without echoing the actual numbers.
* **Approval gate** — flags whether an approval is required for the
  given ``risk_level``, deferring the actual signature check to
  :class:`~src.policy.approval.ApprovalService`.

Design notes:

* No I/O. The engine never reads from a DB, network, or filesystem;
  callers project the relevant counters into :class:`PolicyContext`.
* Pydantic models are frozen + ``extra="forbid"`` so misconfigured policy
  rows fail closed at load time.
* All failure summaries belong to a closed taxonomy mirrored by the
  preflight composer (see :mod:`src.policy.preflight`).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Self
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel

if TYPE_CHECKING:  # pragma: no cover — type-only to avoid runtime cycle
    from src.policy.kill_switch import KillSwitchVerdict


_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Failure taxonomy
# ---------------------------------------------------------------------------


_REASON_PHASE_RISK_OVER_CAP: Final[str] = "policy_phase_risk_over_cap"
_REASON_FAMILY_BANNED: Final[str] = "policy_family_banned"
_REASON_TOOL_BANNED: Final[str] = "policy_tool_banned"
_REASON_RATE_LIMIT: Final[str] = "policy_rate_limit_exceeded"
_REASON_BUDGET_EXCEEDED: Final[str] = "policy_budget_exceeded"
_REASON_PLAN_TIER_BLOCKED: Final[str] = "policy_plan_tier_blocked"
_REASON_TARGET_NOT_OWNED: Final[str] = "policy_target_not_owned"
_REASON_EMERGENCY_GLOBAL: Final[str] = "policy_emergency_global"
_REASON_EMERGENCY_TENANT: Final[str] = "policy_emergency_tenant"

POLICY_FAILURE_REASONS: Final[frozenset[str]] = frozenset(
    {
        _REASON_PHASE_RISK_OVER_CAP,
        _REASON_FAMILY_BANNED,
        _REASON_TOOL_BANNED,
        _REASON_RATE_LIMIT,
        _REASON_BUDGET_EXCEEDED,
        _REASON_PLAN_TIER_BLOCKED,
        _REASON_TARGET_NOT_OWNED,
        _REASON_EMERGENCY_GLOBAL,
        _REASON_EMERGENCY_TENANT,
    }
)


#: Type alias for the optional kill-switch checker injected into ``PolicyEngine``.
KillSwitchChecker = Callable[[UUID], "KillSwitchVerdict"]


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class PlanTier(StrEnum):
    """Subscription tier — controls maximum allowable risk."""

    FREE = "free"
    STARTER = "starter"
    PRO = "pro"
    ENTERPRISE = "enterprise"


_RISK_ORDER: Final[Mapping[RiskLevel, int]] = {
    RiskLevel.PASSIVE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.DESTRUCTIVE: 4,
}


def _is_at_or_below(risk: RiskLevel, cap: RiskLevel) -> bool:
    return _RISK_ORDER[risk] <= _RISK_ORDER[cap]


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class RateLimit(BaseModel):
    """Sliding-window invocation cap.

    The engine never tracks state itself — the caller projects the
    relevant invocation count via :attr:`PolicyContext.recent_invocations`
    and the engine compares to ``max_per_window``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    window_seconds: StrictInt = Field(ge=1, le=86_400)
    max_per_window: StrictInt = Field(ge=1, le=10_000)


class BudgetCap(BaseModel):
    """Spend cap in fractional cents (1/100 of a cent for tax granularity)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    daily_cents: StrictInt = Field(ge=0, le=10_000_000)
    monthly_cents: StrictInt = Field(ge=0, le=300_000_000)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.monthly_cents < self.daily_cents:
            raise ValueError("monthly_cents must be >= daily_cents")
        return self


class PhaseRiskCap(BaseModel):
    """Maximum risk level allowed for a given :class:`ScanPhase`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    phase: ScanPhase
    max_risk: RiskLevel
    requires_approval_at_or_above: RiskLevel = RiskLevel.HIGH


class TenantPolicy(BaseModel):
    """Per-tenant configuration consumed by the engine.

    Notes
    -----
    * ``phase_caps`` is a tuple of :class:`PhaseRiskCap`. Phases not listed
      default to :attr:`default_phase_max_risk`.
    * ``banned_tools`` and ``banned_families`` are lowercase, snake_case
      identifiers (matching the tool / family ID validators upstream).
    * ``rate_limits`` is keyed on ``tool_id``; tools without an entry are
      unconstrained at this layer (other guardrails — sandbox concurrency,
      cluster quota — still apply).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    plan_tier: PlanTier
    default_phase_max_risk: RiskLevel = RiskLevel.LOW
    phase_caps: tuple[PhaseRiskCap, ...] = Field(default_factory=tuple, max_length=16)
    banned_tools: frozenset[StrictStr] = Field(default_factory=frozenset)
    banned_families: frozenset[StrictStr] = Field(default_factory=frozenset)
    rate_limits: Mapping[StrictStr, RateLimit] = Field(default_factory=dict)
    budget: BudgetCap | None = None
    require_ownership_proof: StrictBool = True

    @model_validator(mode="after")
    def _validate(self) -> Self:
        seen: set[ScanPhase] = set()
        for cap in self.phase_caps:
            if cap.phase in seen:
                raise ValueError(f"duplicate phase_cap for phase={cap.phase.value}")
            seen.add(cap.phase)
        return self

    def cap_for_phase(self, phase: ScanPhase) -> PhaseRiskCap:
        for cap in self.phase_caps:
            if cap.phase is phase:
                return cap
        return PhaseRiskCap(phase=phase, max_risk=self.default_phase_max_risk)


class PolicyContext(BaseModel):
    """Inputs the engine needs to evaluate a single proposed action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: UUID
    scan_id: UUID | None = None
    phase: ScanPhase
    risk_level: RiskLevel
    tool_id: StrictStr = Field(min_length=2, max_length=64)
    family_id: StrictStr | None = Field(default=None, min_length=3, max_length=32)
    target: StrictStr = Field(min_length=1, max_length=2_048)
    has_ownership_proof: StrictBool = False
    has_valid_approval: StrictBool = False
    recent_invocations: StrictInt = Field(default=0, ge=0, le=1_000_000)
    spend_today_cents: StrictInt = Field(default=0, ge=0, le=10_000_000)
    spend_this_month_cents: StrictInt = Field(default=0, ge=0, le=300_000_000)
    estimated_cost_cents: StrictInt = Field(default=0, ge=0, le=10_000_000)
    requested_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.requested_at.tzinfo is None:
            raise ValueError("requested_at must be timezone-aware")
        return self


class PolicyDecision(BaseModel):
    """Output of :meth:`PolicyEngine.evaluate`.

    ``decision_id`` matches the ID required by
    :attr:`src.pipeline.contracts.tool_job.ToolJob.policy_decision_id` so
    upstream code can persist it immutably with the dispatch record.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    scan_id: UUID | None = None
    allowed: StrictBool
    requires_approval: StrictBool = False
    failure_summary: StrictStr | None = Field(default=None, max_length=64)
    matched_cap: PhaseRiskCap | None = None
    decided_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Plan-tier defaults
# ---------------------------------------------------------------------------


PLAN_MAX_RISK: Final[Mapping[PlanTier, RiskLevel]] = {
    PlanTier.FREE: RiskLevel.PASSIVE,
    PlanTier.STARTER: RiskLevel.LOW,
    PlanTier.PRO: RiskLevel.MEDIUM,
    PlanTier.ENTERPRISE: RiskLevel.DESTRUCTIVE,
}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Stateless per-tenant policy evaluator.

    Optional ``kill_switch_checker`` (a callable returning
    :class:`~src.policy.kill_switch.KillSwitchVerdict`) is consulted FIRST in
    :meth:`evaluate` so a global emergency or per-tenant throttle short-
    circuits all other rules. The checker is the ONLY I/O surface this class
    accepts; it is injected by the caller (e.g. orchestrator startup) so the
    pure-function contract holds for callers that opt out (default ``None``).
    """

    def __init__(
        self,
        policy: TenantPolicy,
        *,
        kill_switch_checker: KillSwitchChecker | None = None,
    ) -> None:
        # Defensive runtime guard — ``TenantPolicy | None`` is not part
        # of the public signature, but a misconfigured caller could
        # still pass ``None``.
        if policy is None:
            raise ValueError("policy must not be None")
        self._policy = policy
        self._kill_switch_checker = kill_switch_checker

    @property
    def policy(self) -> TenantPolicy:
        return self._policy

    def evaluate(self, context: PolicyContext) -> PolicyDecision:
        """Evaluate ``context`` against the engine's :class:`TenantPolicy`.

        Decision algorithm (short-circuit on first failure):

        0. Emergency kill-switch (when checker injected) — global stop or
           per-tenant throttle deny first; nothing else is evaluated.
        1. Plan-tier ceiling — risk_level must be at or below the tier cap.
        2. Phase-risk cap — risk_level must be at or below the phase cap.
        3. Banned tools / families.
        4. Ownership proof — when required and absent.
        5. Rate limit window.
        6. Budget cap — proposed spend must fit today and this-month limits.
        7. Approval requirement — flag (does not deny on its own).
        """
        if self._policy.tenant_id != context.tenant_id:
            raise ValueError(
                "PolicyContext.tenant_id does not match the engine's tenant_id"
            )

        if self._kill_switch_checker is not None:
            verdict = self._kill_switch_checker(context.tenant_id)
            if verdict.blocked:
                summary = (
                    _REASON_EMERGENCY_GLOBAL
                    if verdict.scope is not None and verdict.scope.value == "global"
                    else _REASON_EMERGENCY_TENANT
                )
                return self._deny(context, summary, matched_cap=None)

        plan_cap = PLAN_MAX_RISK[self._policy.plan_tier]
        if not _is_at_or_below(context.risk_level, plan_cap):
            return self._deny(context, _REASON_PLAN_TIER_BLOCKED, matched_cap=None)

        phase_cap = self._policy.cap_for_phase(context.phase)
        if not _is_at_or_below(context.risk_level, phase_cap.max_risk):
            return self._deny(
                context, _REASON_PHASE_RISK_OVER_CAP, matched_cap=phase_cap
            )

        if context.tool_id in self._policy.banned_tools:
            return self._deny(context, _REASON_TOOL_BANNED, matched_cap=phase_cap)

        if (
            context.family_id is not None
            and context.family_id in self._policy.banned_families
        ):
            return self._deny(context, _REASON_FAMILY_BANNED, matched_cap=phase_cap)

        if (
            self._policy.require_ownership_proof
            and not context.has_ownership_proof
            and context.risk_level is not RiskLevel.PASSIVE
        ):
            return self._deny(context, _REASON_TARGET_NOT_OWNED, matched_cap=phase_cap)

        rate_limit = self._policy.rate_limits.get(context.tool_id)
        if (
            rate_limit is not None
            and context.recent_invocations >= rate_limit.max_per_window
        ):
            return self._deny(context, _REASON_RATE_LIMIT, matched_cap=phase_cap)

        if self._policy.budget is not None:
            new_today = context.spend_today_cents + context.estimated_cost_cents
            new_month = context.spend_this_month_cents + context.estimated_cost_cents
            if (
                new_today > self._policy.budget.daily_cents
                or new_month > self._policy.budget.monthly_cents
            ):
                return self._deny(
                    context, _REASON_BUDGET_EXCEEDED, matched_cap=phase_cap
                )

        approval_threshold = _RISK_ORDER[phase_cap.requires_approval_at_or_above]
        requires_approval = _RISK_ORDER[context.risk_level] >= approval_threshold

        return PolicyDecision(
            tenant_id=context.tenant_id,
            scan_id=context.scan_id,
            allowed=True,
            requires_approval=requires_approval,
            failure_summary=None,
            matched_cap=phase_cap,
        )

    # -- Helpers -------------------------------------------------------------

    def _deny(
        self,
        context: PolicyContext,
        summary: str,
        *,
        matched_cap: PhaseRiskCap | None,
    ) -> PolicyDecision:
        _logger.info(
            "policy.engine.deny",
            extra={
                "tenant_id": str(context.tenant_id),
                "scan_id": str(context.scan_id) if context.scan_id else None,
                "tool_id": context.tool_id,
                "phase": context.phase.value,
                "risk_level": context.risk_level.value,
                "summary": summary,
            },
        )
        return PolicyDecision(
            tenant_id=context.tenant_id,
            scan_id=context.scan_id,
            allowed=False,
            requires_approval=False,
            failure_summary=summary,
            matched_cap=matched_cap,
        )


__all__ = [
    "POLICY_FAILURE_REASONS",
    "BudgetCap",
    "PLAN_MAX_RISK",
    "PhaseRiskCap",
    "PlanTier",
    "PolicyContext",
    "PolicyDecision",
    "PolicyEngine",
    "RateLimit",
    "TenantPolicy",
]
