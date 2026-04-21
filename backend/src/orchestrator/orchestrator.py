"""High-level :class:`Orchestrator` composing every agent in one facade.

The :class:`Orchestrator` is the **only** object the rest of the codebase
needs to know about for AI orchestration. It owns:

* the :class:`~src.orchestrator.llm_provider.LLMProvider` (any vendor),
* the :class:`~src.orchestrator.prompt_registry.PromptRegistry` (signed
  prompts loaded fail-closed at boot),
* the :class:`~src.orchestrator.retry_loop.RetryLoop` (retries with
  Fixer + budget caps),
* the :class:`~src.orchestrator.cost_tracker.CostTracker` (per-tenant /
  per-scan token + USD bookkeeping),
* a reference to the policy plane's
  :class:`~src.policy.audit.AuditLogger` so Critic verdicts and budget
  aborts produce tamper-evident audit rows.

Three top-level capabilities map to the three pipeline phases that need
LLM input (Backlog/dev1_md §17):

* :meth:`Orchestrator.plan` — Planner → Critic → typed
  :class:`~src.orchestrator.schemas.loader.ValidationPlanV1` (or
  :class:`OrchestratorPlanRejected` if the Critic vetoed the draft).
* :meth:`Orchestrator.verify` — Verifier → ``list[FindingDTO]`` (already
  schema-validated against :class:`FindingDTO`).
* :meth:`Orchestrator.report` — Reporter →
  :class:`~src.orchestrator.agents.ReportNarrative`.

Every call goes through the :class:`RetryLoop` (so cost is accounted and
the Fixer is invoked on malformed JSON). On any unrecoverable retry-loop
abort, the orchestrator surfaces a domain-specific error
(:class:`OrchestratorBudgetExceeded`, :class:`OrchestratorParseFailure`,
:class:`OrchestratorProviderFailure`) so the caller can route on the
abort reason without parsing exception strings.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from src.oast.correlator import OASTInteraction
from src.orchestrator.agents import (
    AgentContext,
    CriticAgent,
    CriticVerdict,
    FixerAgent,
    PlannerAgent,
    ReporterAgent,
    ReportNarrative,
    VerifierAgent,
)
from src.orchestrator.cost_tracker import CostSummary, CostTracker
from src.orchestrator.llm_provider import LLMProvider
from src.orchestrator.prompt_registry import AgentRole, PromptRegistry
from src.orchestrator.retry_loop import (
    AttemptLog,
    RetryAbortReason,
    RetryConfig,
    RetryLoop,
)
from src.orchestrator.schemas.loader import ValidationPlanV1
from src.pipeline.contracts.finding_dto import FindingDTO
from src.policy.audit import AuditEventType, AuditLogger

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OrchestratorError(Exception):
    """Base class for every orchestrator-layer error."""


class OrchestratorPlanRejected(OrchestratorError):
    """Raised when the Critic vetoes the Planner's draft plan.

    Carries the rejected :class:`CriticVerdict` so callers can surface the
    sanitised reasons / suggestions to the audit log or the operator UI.
    """

    def __init__(self, verdict: CriticVerdict) -> None:
        self.verdict = verdict
        super().__init__(
            "validation plan rejected by Critic: " + "; ".join(verdict.reasons)
        )


class OrchestratorBudgetExceeded(OrchestratorError):
    """Raised when an agent call exhausts the configured retry budget."""

    def __init__(self, agent_role: AgentRole, attempt_log: AttemptLog) -> None:
        self.agent_role = agent_role
        self.attempt_log = attempt_log
        super().__init__(
            f"{agent_role.value} agent exceeded retry budget "
            f"(usd={attempt_log.total_usd_cost:.6f}, "
            f"tokens={attempt_log.total_prompt_tokens + attempt_log.total_completion_tokens})"
        )


class OrchestratorParseFailure(OrchestratorError):
    """Raised when the Fixer can't repair a malformed LLM response."""

    def __init__(self, agent_role: AgentRole, attempt_log: AttemptLog) -> None:
        self.agent_role = agent_role
        self.attempt_log = attempt_log
        super().__init__(
            f"{agent_role.value} agent could not produce a valid response "
            f"after {len(attempt_log.attempts)} attempts"
        )


class OrchestratorProviderFailure(OrchestratorError):
    """Raised when the underlying LLM provider is unreachable / errored."""

    def __init__(self, agent_role: AgentRole, attempt_log: AttemptLog) -> None:
        self.agent_role = agent_role
        self.attempt_log = attempt_log
        super().__init__(
            f"{agent_role.value} agent failed: provider unavailable / errored"
        )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class Orchestrator:
    """Single entry point for every LLM-driven pentest decision.

    Construction is dependency-injected so unit tests can swap any
    component for a stub. The default ``RetryLoop`` is built from the
    same provider + registry + cost tracker if the caller doesn't supply
    one.
    """

    def __init__(
        self,
        *,
        provider: LLMProvider,
        registry: PromptRegistry,
        cost_tracker: CostTracker,
        audit_logger: AuditLogger,
        retry_loop: RetryLoop | None = None,
        retry_config: RetryConfig | None = None,
        planner_prompt_id: str = "planner_v1",
        critic_prompt_id: str = "critic_v1",
        verifier_prompt_id: str = "verifier_v1",
        reporter_prompt_id: str = "reporter_v1",
        fixer_prompt_id: str = "fixer_v1",
    ) -> None:
        self._provider = provider
        self._registry = registry
        self._cost_tracker = cost_tracker
        self._audit_logger = audit_logger

        self._planner = PlannerAgent(provider, registry, prompt_id=planner_prompt_id)
        self._critic = CriticAgent(provider, registry, prompt_id=critic_prompt_id)
        self._verifier = VerifierAgent(provider, registry, prompt_id=verifier_prompt_id)
        self._reporter = ReporterAgent(provider, registry, prompt_id=reporter_prompt_id)
        self._fixer = FixerAgent(provider, registry, prompt_id=fixer_prompt_id)

        if retry_loop is not None:
            self._retry_loop = retry_loop
        else:
            self._retry_loop = RetryLoop(
                cost_tracker=cost_tracker,
                fixer_agent=self._fixer,
                config=retry_config,
            )

    # -- public API ----------------------------------------------------------

    @property
    def cost_tracker(self) -> CostTracker:
        return self._cost_tracker

    @property
    def retry_loop(self) -> RetryLoop:
        return self._retry_loop

    @property
    def planner(self) -> PlannerAgent:
        return self._planner

    @property
    def critic(self) -> CriticAgent:
        return self._critic

    @property
    def verifier(self) -> VerifierAgent:
        return self._verifier

    @property
    def reporter(self) -> ReporterAgent:
        return self._reporter

    @property
    def fixer(self) -> FixerAgent:
        return self._fixer

    async def plan(
        self,
        context: AgentContext,
        *,
        policy: Mapping[str, Any] | None = None,
        run_critic: bool = True,
    ) -> ValidationPlanV1:
        """Generate a validation plan for ``context`` and (optionally) review it.

        Pipeline:
        1. PlannerAgent produces a draft :class:`ValidationPlanV1`.
        2. If ``run_critic=True`` (default), CriticAgent reviews the plan
           against the supplied ``policy`` snapshot.
        3. On approval, the plan is returned. On rejection, a
           :class:`OrchestratorPlanRejected` is raised carrying the
           critic verdict (also recorded as a ``POLICY_DECISION`` audit
           event with ``decision_allowed=False``).
        """
        plan, _planner_log = await self._run_agent(
            self._planner,
            context,
            agent_role=AgentRole.PLANNER,
            kwargs={},
        )
        typed_plan: ValidationPlanV1 = plan
        _logger.info(
            "orchestrator.plan.draft",
            extra={
                "tenant_id": str(context.tenant_id),
                "scan_id": str(context.scan_id),
                "correlation_id": str(context.correlation_id),
                "phase": context.phase.value,
                "registry_family": typed_plan.payload_strategy.registry_family,
                "risk": typed_plan.risk.value,
            },
        )

        if not run_critic:
            return typed_plan

        verdict, _critic_log = await self._run_agent(
            self._critic,
            context,
            agent_role=AgentRole.CRITIC,
            kwargs={
                "plan_json": typed_plan,
                "policy": dict(policy or {}),
            },
        )
        typed_verdict: CriticVerdict = verdict
        self._audit_critic_verdict(context, typed_verdict)
        if not typed_verdict.approved:
            raise OrchestratorPlanRejected(typed_verdict)
        return typed_plan

    async def verify(
        self,
        context: AgentContext,
        *,
        tool_output: Mapping[str, Any],
        oast_evidence: list[OASTInteraction] | None = None,
    ) -> list[FindingDTO]:
        """Classify ``tool_output`` (+ OAST evidence) into typed findings."""
        result, _log = await self._run_agent(
            self._verifier,
            context,
            agent_role=AgentRole.VERIFIER,
            kwargs={
                "tool_output": dict(tool_output),
                "oast_evidence": list(oast_evidence or []),
            },
        )
        typed_findings: list[FindingDTO] = result
        _logger.info(
            "orchestrator.verify.findings",
            extra={
                "tenant_id": str(context.tenant_id),
                "scan_id": str(context.scan_id),
                "correlation_id": str(context.correlation_id),
                "finding_count": len(typed_findings),
            },
        )
        return typed_findings

    async def report(
        self,
        context: AgentContext,
        findings: list[FindingDTO],
    ) -> ReportNarrative:
        """Generate the executive / technical narrative for ``findings``."""
        result, _log = await self._run_agent(
            self._reporter,
            context,
            agent_role=AgentRole.REPORTER,
            kwargs={"findings": list(findings)},
        )
        typed_narrative: ReportNarrative = result
        _logger.info(
            "orchestrator.report.narrative",
            extra={
                "tenant_id": str(context.tenant_id),
                "scan_id": str(context.scan_id),
                "correlation_id": str(context.correlation_id),
                "executive_summary_len": len(typed_narrative.executive_summary),
                "recommendation_count": len(typed_narrative.recommendations),
            },
        )
        return typed_narrative

    def cost_summary_for_scan(self, scan_id: UUID) -> CostSummary:
        """Return the aggregated :class:`CostSummary` for ``scan_id``."""
        return self._cost_tracker.total_for_scan(scan_id)

    # -- internal helpers ----------------------------------------------------

    async def _run_agent(
        self,
        agent: PlannerAgent | CriticAgent | VerifierAgent | ReporterAgent,
        context: AgentContext,
        *,
        agent_role: AgentRole,
        kwargs: dict[str, Any],
    ) -> tuple[Any, AttemptLog]:
        """Dispatch ``agent`` through the retry loop and translate aborts.

        Returns a ``(result, attempt_log)`` pair on success. Translates
        every non-success :class:`RetryAbortReason` into the matching
        :class:`OrchestratorError` subclass.
        """
        result, attempt_log = await self._retry_loop.run(
            agent,
            context,
            **kwargs,
        )
        match attempt_log.abort_reason:
            case RetryAbortReason.VALIDATED_OK:
                return result, attempt_log
            case RetryAbortReason.BUDGET_EXHAUSTED:
                self._audit_budget_exhausted(context, agent_role, attempt_log)
                raise OrchestratorBudgetExceeded(agent_role, attempt_log)
            case (
                RetryAbortReason.MAX_RETRIES_EXHAUSTED
                | RetryAbortReason.UNRECOVERABLE_SCHEMA_ERROR
            ):
                raise OrchestratorParseFailure(agent_role, attempt_log)
            case RetryAbortReason.PROVIDER_ERROR:
                raise OrchestratorProviderFailure(agent_role, attempt_log)
        # mypy exhaustiveness — every RetryAbortReason handled above.
        raise AssertionError(  # pragma: no cover - defensive
            f"unhandled retry abort reason {attempt_log.abort_reason!r}"
        )

    def _audit_critic_verdict(
        self,
        context: AgentContext,
        verdict: CriticVerdict,
    ) -> None:
        """Emit a ``POLICY_DECISION`` audit event for the Critic verdict."""
        try:
            self._audit_logger.emit(
                event_type=AuditEventType.POLICY_DECISION,
                tenant_id=context.tenant_id,
                scan_id=context.scan_id,
                decision_allowed=verdict.approved,
                failure_summary=None if verdict.approved else "critic_rejected",
                payload={
                    "agent_role": AgentRole.CRITIC.value,
                    "correlation_id": str(context.correlation_id),
                    "phase": context.phase.value,
                    "reason_count": len(verdict.reasons),
                },
            )
        except Exception:  # noqa: BLE001 — audit failures must never crash the orchestrator
            _logger.exception(
                "orchestrator.audit.critic_emit_failed",
                extra={
                    "tenant_id": str(context.tenant_id),
                    "scan_id": str(context.scan_id),
                    "correlation_id": str(context.correlation_id),
                },
            )

    def _audit_budget_exhausted(
        self,
        context: AgentContext,
        agent_role: AgentRole,
        attempt_log: AttemptLog,
    ) -> None:
        """Emit an audit event when the retry loop trips the budget cap."""
        try:
            self._audit_logger.emit(
                event_type=AuditEventType.POLICY_DECISION,
                tenant_id=context.tenant_id,
                scan_id=context.scan_id,
                decision_allowed=False,
                failure_summary="budget_exhausted",
                payload={
                    "agent_role": agent_role.value,
                    "correlation_id": str(context.correlation_id),
                    "phase": context.phase.value,
                    "total_usd": attempt_log.total_usd_cost,
                    "total_tokens": (
                        attempt_log.total_prompt_tokens
                        + attempt_log.total_completion_tokens
                    ),
                },
            )
        except Exception:  # noqa: BLE001 — audit failures must never crash the orchestrator
            _logger.exception(
                "orchestrator.audit.budget_emit_failed",
                extra={
                    "tenant_id": str(context.tenant_id),
                    "scan_id": str(context.scan_id),
                    "correlation_id": str(context.correlation_id),
                },
            )


__all__ = [
    "Orchestrator",
    "OrchestratorBudgetExceeded",
    "OrchestratorError",
    "OrchestratorParseFailure",
    "OrchestratorPlanRejected",
    "OrchestratorProviderFailure",
]
