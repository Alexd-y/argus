"""Unit tests for :mod:`src.orchestrator.orchestrator` (ARG-008)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest

from src.orchestrator.agents import AgentContext, CriticVerdict, ReportNarrative
from src.orchestrator.cost_tracker import CostTracker
from src.orchestrator.llm_provider import EchoLLMProvider
from src.orchestrator.orchestrator import (
    Orchestrator,
    OrchestratorBudgetExceeded,
    OrchestratorParseFailure,
    OrchestratorPlanRejected,
    OrchestratorProviderFailure,
)
from src.orchestrator.prompt_registry import PromptRegistry
from src.orchestrator.retry_loop import RetryConfig
from src.orchestrator.schemas.loader import ValidationPlanV1
from src.pipeline.contracts.finding_dto import FindingDTO
from src.policy.audit import AuditEventType, AuditLogger


def _build_orchestrator(
    registry: PromptRegistry,
    provider: EchoLLMProvider,
    cost_tracker: CostTracker,
    audit_logger: AuditLogger,
    *,
    retry_config: RetryConfig | None = None,
) -> Orchestrator:
    return Orchestrator(
        provider=provider,
        registry=registry,
        cost_tracker=cost_tracker,
        audit_logger=audit_logger,
        retry_config=retry_config
        or RetryConfig(
            max_retries=2,
            backoff_initial_s=0.0,
            backoff_factor=1.0,
            total_budget_usd=0.5,
            total_budget_tokens=16_384,
        ),
    )


# ---------------------------------------------------------------------------
# plan()
# ---------------------------------------------------------------------------


class TestOrchestratorPlan:
    @pytest.mark.asyncio
    async def test_plan_returns_validated_plan_when_critic_approves(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        audit_logger: AuditLogger,
        canned_validation_plan: Callable[[], dict[str, Any]],
        canned_critic_verdict: Callable[..., dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory(
            {
                "planner_v1": canned_validation_plan(),
                "critic_v1": canned_critic_verdict(approved=True),
            }
        )
        orchestrator = _build_orchestrator(
            registry, provider, cost_tracker, audit_logger
        )
        plan = await orchestrator.plan(agent_context, policy={"k": "v"})
        assert isinstance(plan, ValidationPlanV1)

        # Cost recorded for both planner + critic.
        summary = orchestrator.cost_summary_for_scan(agent_context.scan_id)
        assert summary.record_count == 2
        assert "planner" in summary.by_role
        assert "critic" in summary.by_role

        # Audit logger received the policy decision.
        events = list(audit_logger.sink.iter_events(tenant_id=agent_context.tenant_id))
        assert any(e.event_type is AuditEventType.POLICY_DECISION for e in events)
        assert all(e.decision_allowed for e in events)

    @pytest.mark.asyncio
    async def test_plan_raises_when_critic_rejects(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        audit_logger: AuditLogger,
        canned_validation_plan: Callable[[], dict[str, Any]],
        canned_critic_verdict: Callable[..., dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory(
            {
                "planner_v1": canned_validation_plan(),
                "critic_v1": canned_critic_verdict(approved=False),
            }
        )
        orchestrator = _build_orchestrator(
            registry, provider, cost_tracker, audit_logger
        )
        with pytest.raises(OrchestratorPlanRejected) as exc_info:
            await orchestrator.plan(agent_context, policy={})
        assert isinstance(exc_info.value.verdict, CriticVerdict)
        assert exc_info.value.verdict.approved is False
        # Audit recorded a denied decision.
        events = list(audit_logger.sink.iter_events(tenant_id=agent_context.tenant_id))
        assert any(
            e.event_type is AuditEventType.POLICY_DECISION and not e.decision_allowed
            for e in events
        )

    @pytest.mark.asyncio
    async def test_plan_skip_critic_returns_draft(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        audit_logger: AuditLogger,
        canned_validation_plan: Callable[[], dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"planner_v1": canned_validation_plan()})
        orchestrator = _build_orchestrator(
            registry, provider, cost_tracker, audit_logger
        )
        plan = await orchestrator.plan(agent_context, run_critic=False)
        assert isinstance(plan, ValidationPlanV1)
        # Critic skipped → only one cost record.
        summary = orchestrator.cost_summary_for_scan(agent_context.scan_id)
        assert summary.record_count == 1

    @pytest.mark.asyncio
    async def test_plan_provider_failure_translated(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        audit_logger: AuditLogger,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory()  # no canned planner_v1
        orchestrator = _build_orchestrator(
            registry, provider, cost_tracker, audit_logger
        )
        with pytest.raises(OrchestratorProviderFailure):
            await orchestrator.plan(agent_context, policy={})

    @pytest.mark.asyncio
    async def test_plan_parse_failure_translated(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        audit_logger: AuditLogger,
        canned_validation_plan: Callable[[], dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        bad = canned_validation_plan()
        bad.pop("hypothesis")
        provider = echo_provider_factory({"planner_v1": bad, "fixer_v1": bad})
        orchestrator = _build_orchestrator(
            registry, provider, cost_tracker, audit_logger
        )
        with pytest.raises(OrchestratorParseFailure):
            await orchestrator.plan(agent_context, policy={})

    @pytest.mark.asyncio
    async def test_plan_budget_exceeded_translated(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        audit_logger: AuditLogger,
        canned_validation_plan: Callable[[], dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        bad = canned_validation_plan()
        bad.pop("hypothesis")
        provider = echo_provider_factory({"planner_v1": bad, "fixer_v1": bad})
        orchestrator = _build_orchestrator(
            registry,
            provider,
            cost_tracker,
            audit_logger,
            retry_config=RetryConfig(
                max_retries=2,
                backoff_initial_s=0.0,
                backoff_factor=1.0,
                total_budget_usd=1e-9,
                total_budget_tokens=1,
            ),
        )
        with pytest.raises(OrchestratorBudgetExceeded):
            await orchestrator.plan(agent_context, policy={})
        # Audit recorded the budget abort.
        events = list(audit_logger.sink.iter_events(tenant_id=agent_context.tenant_id))
        assert any(
            e.event_type is AuditEventType.POLICY_DECISION
            and e.failure_summary == "budget_exhausted"
            for e in events
        )


# ---------------------------------------------------------------------------
# verify()
# ---------------------------------------------------------------------------


class TestOrchestratorVerify:
    @pytest.mark.asyncio
    async def test_verify_returns_findings(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        audit_logger: AuditLogger,
        canned_findings_payload: Callable[..., dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory(
            {
                "verifier_v1": canned_findings_payload(
                    agent_context.scan_id, agent_context.tenant_id, count=3
                )
            }
        )
        orchestrator = _build_orchestrator(
            registry, provider, cost_tracker, audit_logger
        )
        findings = await orchestrator.verify(
            agent_context, tool_output={"x": 1}, oast_evidence=None
        )
        assert len(findings) == 3
        assert all(isinstance(f, FindingDTO) for f in findings)


# ---------------------------------------------------------------------------
# report()
# ---------------------------------------------------------------------------


class TestOrchestratorReport:
    @pytest.mark.asyncio
    async def test_report_returns_narrative(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        audit_logger: AuditLogger,
        canned_report_narrative: Callable[[], dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"reporter_v1": canned_report_narrative()})
        orchestrator = _build_orchestrator(
            registry, provider, cost_tracker, audit_logger
        )
        narrative = await orchestrator.report(agent_context, findings=[])
        assert isinstance(narrative, ReportNarrative)
        assert narrative.recommendations


# ---------------------------------------------------------------------------
# Audit-failure resilience
# ---------------------------------------------------------------------------


class TestOrchestratorAuditFailure:
    @pytest.mark.asyncio
    async def test_audit_failure_does_not_crash_plan(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        audit_logger: AuditLogger,
        canned_validation_plan: Callable[[], dict[str, Any]],
        canned_critic_verdict: Callable[..., dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory(
            {
                "planner_v1": canned_validation_plan(),
                "critic_v1": canned_critic_verdict(approved=True),
            }
        )
        orchestrator = _build_orchestrator(
            registry, provider, cost_tracker, audit_logger
        )

        def boom(**_kwargs: object) -> None:
            raise RuntimeError("audit sink down")

        with patch.object(audit_logger, "emit", side_effect=boom):
            plan = await orchestrator.plan(agent_context, policy={})
        assert isinstance(plan, ValidationPlanV1)


# ---------------------------------------------------------------------------
# Property accessors
# ---------------------------------------------------------------------------


class TestOrchestratorAccessors:
    def test_property_accessors_return_components(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        cost_tracker: CostTracker,
        audit_logger: AuditLogger,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory()
        orchestrator = _build_orchestrator(
            registry, provider, cost_tracker, audit_logger
        )
        assert orchestrator.cost_tracker is cost_tracker
        assert orchestrator.retry_loop is not None
        assert orchestrator.planner.role.value == "planner"
        assert orchestrator.critic.role.value == "critic"
        assert orchestrator.verifier.role.value == "verifier"
        assert orchestrator.reporter.role.value == "reporter"
        assert orchestrator.fixer.role.value == "fixer"
