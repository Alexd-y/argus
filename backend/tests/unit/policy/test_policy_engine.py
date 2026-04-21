"""Unit tests for :mod:`src.policy.policy_engine`.

Covers per-tenant evaluation: plan-tier ceilings, phase risk caps, banned
tools / families, ownership requirements, rate limits, budget caps, and
the approval flag computation.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel
from src.policy.policy_engine import (
    PLAN_MAX_RISK,
    POLICY_FAILURE_REASONS,
    BudgetCap,
    PhaseRiskCap,
    PlanTier,
    PolicyContext,
    PolicyEngine,
    RateLimit,
    TenantPolicy,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ctx(
    *,
    tenant_id: UUID,
    risk_level: RiskLevel = RiskLevel.LOW,
    phase: ScanPhase = ScanPhase.RECON,
    tool_id: str = "nmap_quick",
    family_id: str | None = None,
    target: str = "https://example.com/api",
    has_ownership_proof: bool = True,
    recent_invocations: int = 0,
    spend_today: int = 0,
    spend_month: int = 0,
    estimated_cost: int = 0,
) -> PolicyContext:
    return PolicyContext(
        tenant_id=tenant_id,
        scan_id=uuid4(),
        phase=phase,
        risk_level=risk_level,
        tool_id=tool_id,
        family_id=family_id,
        target=target,
        has_ownership_proof=has_ownership_proof,
        recent_invocations=recent_invocations,
        spend_today_cents=spend_today,
        spend_this_month_cents=spend_month,
        estimated_cost_cents=estimated_cost,
    )


# ---------------------------------------------------------------------------
# Pydantic model validation
# ---------------------------------------------------------------------------


class TestPolicyEngineModels:
    def test_budget_monthly_must_be_at_least_daily(self) -> None:
        with pytest.raises(ValidationError):
            BudgetCap(daily_cents=10_000, monthly_cents=5_000)

    def test_phase_risk_cap_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            PhaseRiskCap.model_validate(
                {
                    "phase": "recon",
                    "max_risk": "low",
                    "extra": "nope",
                }
            )

    def test_rate_limit_bounds(self) -> None:
        with pytest.raises(ValidationError):
            RateLimit(window_seconds=0, max_per_window=10)
        with pytest.raises(ValidationError):
            RateLimit(window_seconds=60, max_per_window=0)

    def test_duplicate_phase_caps_rejected(self, tenant_id: UUID) -> None:
        with pytest.raises(ValidationError):
            TenantPolicy(
                tenant_id=tenant_id,
                plan_tier=PlanTier.PRO,
                phase_caps=(
                    PhaseRiskCap(phase=ScanPhase.RECON, max_risk=RiskLevel.LOW),
                    PhaseRiskCap(phase=ScanPhase.RECON, max_risk=RiskLevel.MEDIUM),
                ),
            )

    def test_policy_context_naive_datetime_rejected(self, tenant_id: UUID) -> None:
        with pytest.raises(ValidationError):
            PolicyContext(
                tenant_id=tenant_id,
                phase=ScanPhase.RECON,
                risk_level=RiskLevel.LOW,
                tool_id="nmap_quick",
                target="https://example.com",
                requested_at=datetime(2026, 4, 17, 12, 0, 0),
            )

    def test_cap_for_phase_falls_back_to_default(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.PRO,
            default_phase_max_risk=RiskLevel.MEDIUM,
            phase_caps=(),
        )
        cap = policy.cap_for_phase(ScanPhase.EXPLOITATION)
        assert cap.max_risk is RiskLevel.MEDIUM
        assert cap.phase is ScanPhase.EXPLOITATION


# ---------------------------------------------------------------------------
# Engine — happy path
# ---------------------------------------------------------------------------


class TestPolicyEngineHappyPath:
    def test_low_risk_recon_allowed(
        self, tenant_id: UUID, policy_engine: PolicyEngine
    ) -> None:
        decision = policy_engine.evaluate(
            _ctx(tenant_id=tenant_id, risk_level=RiskLevel.LOW)
        )
        assert decision.allowed is True
        assert decision.failure_summary is None
        assert decision.requires_approval is False

    def test_high_risk_exploitation_with_ownership_allowed_but_flags_approval(
        self, tenant_id: UUID, policy_engine: PolicyEngine
    ) -> None:
        decision = policy_engine.evaluate(
            _ctx(
                tenant_id=tenant_id,
                phase=ScanPhase.EXPLOITATION,
                risk_level=RiskLevel.HIGH,
                tool_id="metasploit",
            )
        )
        assert decision.allowed is True
        assert decision.requires_approval is True

    def test_passive_recon_skips_ownership(
        self, tenant_id: UUID, policy_engine: PolicyEngine
    ) -> None:
        decision = policy_engine.evaluate(
            _ctx(
                tenant_id=tenant_id,
                risk_level=RiskLevel.PASSIVE,
                has_ownership_proof=False,
            )
        )
        assert decision.allowed is True


# ---------------------------------------------------------------------------
# Plan-tier ceiling
# ---------------------------------------------------------------------------


class TestPlanTierCeiling:
    def test_free_tier_blocks_low_risk(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(tenant_id=tenant_id, plan_tier=PlanTier.FREE)
        engine = PolicyEngine(policy)
        decision = engine.evaluate(_ctx(tenant_id=tenant_id, risk_level=RiskLevel.LOW))
        assert decision.allowed is False
        assert decision.failure_summary == "policy_plan_tier_blocked"

    def test_pro_tier_allows_medium(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.PRO,
            default_phase_max_risk=RiskLevel.MEDIUM,
        )
        engine = PolicyEngine(policy)
        decision = engine.evaluate(
            _ctx(
                tenant_id=tenant_id,
                phase=ScanPhase.VULN_ANALYSIS,
                risk_level=RiskLevel.MEDIUM,
            )
        )
        assert decision.allowed is True

    def test_pro_tier_blocks_high(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.PRO,
            default_phase_max_risk=RiskLevel.HIGH,
        )
        engine = PolicyEngine(policy)
        decision = engine.evaluate(
            _ctx(
                tenant_id=tenant_id,
                phase=ScanPhase.EXPLOITATION,
                risk_level=RiskLevel.HIGH,
                tool_id="metasploit",
            )
        )
        assert decision.allowed is False
        assert decision.failure_summary == "policy_plan_tier_blocked"

    def test_enterprise_tier_allows_destructive(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.ENTERPRISE,
            default_phase_max_risk=RiskLevel.DESTRUCTIVE,
            require_ownership_proof=False,
        )
        engine = PolicyEngine(policy)
        decision = engine.evaluate(
            _ctx(
                tenant_id=tenant_id,
                phase=ScanPhase.EXPLOITATION,
                risk_level=RiskLevel.DESTRUCTIVE,
                tool_id="metasploit",
            )
        )
        assert decision.allowed is True
        assert decision.requires_approval is True


# ---------------------------------------------------------------------------
# Phase risk cap
# ---------------------------------------------------------------------------


class TestPhaseRiskCap:
    def test_recon_blocks_medium(
        self, tenant_id: UUID, policy_engine: PolicyEngine
    ) -> None:
        decision = policy_engine.evaluate(
            _ctx(
                tenant_id=tenant_id,
                phase=ScanPhase.RECON,
                risk_level=RiskLevel.MEDIUM,
            )
        )
        assert decision.allowed is False
        assert decision.failure_summary == "policy_phase_risk_over_cap"
        assert decision.matched_cap is not None
        assert decision.matched_cap.phase is ScanPhase.RECON


# ---------------------------------------------------------------------------
# Banned tools / families
# ---------------------------------------------------------------------------


class TestBans:
    def test_banned_tool_rejected(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.PRO,
            banned_tools=frozenset({"nmap_quick"}),
        )
        engine = PolicyEngine(policy)
        decision = engine.evaluate(_ctx(tenant_id=tenant_id))
        assert decision.allowed is False
        assert decision.failure_summary == "policy_tool_banned"

    def test_banned_family_rejected(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.PRO,
            banned_families=frozenset({"demo_rce"}),
        )
        engine = PolicyEngine(policy)
        decision = engine.evaluate(_ctx(tenant_id=tenant_id, family_id="demo_rce"))
        assert decision.allowed is False
        assert decision.failure_summary == "policy_family_banned"


# ---------------------------------------------------------------------------
# Ownership requirement
# ---------------------------------------------------------------------------


class TestOwnership:
    def test_missing_ownership_blocks_low(
        self, tenant_id: UUID, policy_engine: PolicyEngine
    ) -> None:
        decision = policy_engine.evaluate(
            _ctx(
                tenant_id=tenant_id,
                risk_level=RiskLevel.LOW,
                has_ownership_proof=False,
            )
        )
        assert decision.allowed is False
        assert decision.failure_summary == "policy_target_not_owned"

    def test_ownership_optional_when_disabled(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.PRO,
            require_ownership_proof=False,
        )
        engine = PolicyEngine(policy)
        decision = engine.evaluate(
            _ctx(
                tenant_id=tenant_id,
                risk_level=RiskLevel.LOW,
                has_ownership_proof=False,
            )
        )
        assert decision.allowed is True


# ---------------------------------------------------------------------------
# Rate limits
# ---------------------------------------------------------------------------


class TestRateLimit:
    def test_under_limit_allowed(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.PRO,
            rate_limits={"nmap_quick": RateLimit(window_seconds=60, max_per_window=10)},
        )
        engine = PolicyEngine(policy)
        decision = engine.evaluate(_ctx(tenant_id=tenant_id, recent_invocations=9))
        assert decision.allowed is True

    def test_at_limit_rejected(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.PRO,
            rate_limits={"nmap_quick": RateLimit(window_seconds=60, max_per_window=10)},
        )
        engine = PolicyEngine(policy)
        decision = engine.evaluate(_ctx(tenant_id=tenant_id, recent_invocations=10))
        assert decision.allowed is False
        assert decision.failure_summary == "policy_rate_limit_exceeded"

    def test_no_limit_for_unlisted_tool(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.PRO,
            rate_limits={"nmap_quick": RateLimit(window_seconds=60, max_per_window=1)},
        )
        engine = PolicyEngine(policy)
        decision = engine.evaluate(
            _ctx(
                tenant_id=tenant_id,
                tool_id="other_tool",
                recent_invocations=1_000,
            )
        )
        assert decision.allowed is True


# ---------------------------------------------------------------------------
# Budget caps
# ---------------------------------------------------------------------------


class TestBudget:
    def test_under_daily_cap_allowed(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.PRO,
            budget=BudgetCap(daily_cents=1_000, monthly_cents=10_000),
        )
        engine = PolicyEngine(policy)
        decision = engine.evaluate(
            _ctx(
                tenant_id=tenant_id,
                spend_today=500,
                spend_month=2_000,
                estimated_cost=400,
            )
        )
        assert decision.allowed is True

    def test_over_daily_cap_rejected(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.PRO,
            budget=BudgetCap(daily_cents=1_000, monthly_cents=10_000),
        )
        engine = PolicyEngine(policy)
        decision = engine.evaluate(
            _ctx(
                tenant_id=tenant_id,
                spend_today=900,
                spend_month=2_000,
                estimated_cost=200,
            )
        )
        assert decision.allowed is False
        assert decision.failure_summary == "policy_budget_exceeded"

    def test_over_monthly_cap_rejected(self, tenant_id: UUID) -> None:
        # Daily and monthly caps are validated to satisfy
        # ``monthly_cents >= daily_cents``; we pick small numbers and
        # exhaust the monthly bucket while staying inside the daily one.
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.PRO,
            budget=BudgetCap(daily_cents=1_000, monthly_cents=1_000),
        )
        engine = PolicyEngine(policy)
        decision = engine.evaluate(
            _ctx(
                tenant_id=tenant_id,
                spend_today=0,
                spend_month=900,
                estimated_cost=200,
            )
        )
        assert decision.allowed is False
        assert decision.failure_summary == "policy_budget_exceeded"


# ---------------------------------------------------------------------------
# Approval flag
# ---------------------------------------------------------------------------


class TestApprovalFlag:
    def test_low_risk_does_not_flag_approval(
        self, tenant_id: UUID, policy_engine: PolicyEngine
    ) -> None:
        decision = policy_engine.evaluate(
            _ctx(tenant_id=tenant_id, risk_level=RiskLevel.LOW)
        )
        assert decision.requires_approval is False

    def test_high_risk_flags_approval(
        self, tenant_id: UUID, policy_engine: PolicyEngine
    ) -> None:
        decision = policy_engine.evaluate(
            _ctx(
                tenant_id=tenant_id,
                phase=ScanPhase.EXPLOITATION,
                risk_level=RiskLevel.HIGH,
                tool_id="metasploit",
            )
        )
        assert decision.requires_approval is True

    def test_custom_threshold_lowered_to_medium(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.PRO,
            phase_caps=(
                PhaseRiskCap(
                    phase=ScanPhase.VULN_ANALYSIS,
                    max_risk=RiskLevel.MEDIUM,
                    requires_approval_at_or_above=RiskLevel.MEDIUM,
                ),
            ),
        )
        engine = PolicyEngine(policy)
        decision = engine.evaluate(
            _ctx(
                tenant_id=tenant_id,
                phase=ScanPhase.VULN_ANALYSIS,
                risk_level=RiskLevel.MEDIUM,
            )
        )
        assert decision.allowed is True
        assert decision.requires_approval is True


# ---------------------------------------------------------------------------
# Cross-cutting
# ---------------------------------------------------------------------------


class TestCrossCutting:
    def test_engine_rejects_mismatched_tenant_in_context(
        self, tenant_id: UUID, policy_engine: PolicyEngine
    ) -> None:
        with pytest.raises(ValueError):
            policy_engine.evaluate(_ctx(tenant_id=uuid4()))

    def test_failure_summaries_are_in_closed_set(self, tenant_id: UUID) -> None:
        policy = TenantPolicy(
            tenant_id=tenant_id,
            plan_tier=PlanTier.FREE,
            banned_tools=frozenset({"nmap_quick"}),
        )
        engine = PolicyEngine(policy)
        decision = engine.evaluate(_ctx(tenant_id=tenant_id, risk_level=RiskLevel.LOW))
        assert decision.failure_summary in POLICY_FAILURE_REASONS

    def test_decision_id_unique_per_call(
        self, tenant_id: UUID, policy_engine: PolicyEngine
    ) -> None:
        d1 = policy_engine.evaluate(_ctx(tenant_id=tenant_id))
        d2 = policy_engine.evaluate(_ctx(tenant_id=tenant_id))
        assert d1.decision_id != d2.decision_id

    def test_plan_max_risk_constants(self) -> None:
        # Sanity — every tier maps to a known risk level.
        for tier, risk in PLAN_MAX_RISK.items():
            assert isinstance(tier, PlanTier)
            assert isinstance(risk, RiskLevel)
