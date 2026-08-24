"""Scenario executor for declarative playbooks (P4-SCENARIO-004).

The :class:`ScenarioExecutor` runs a signed :class:`~src.playbooks.schema.Playbook`
against a target and drives its lifecycle:

    PLANNED → RUNNING → (PARTIAL | CONFIRMED | REJECTED) → (CLEANUP_COMPLETE |
    CLEANUP_FAILED)

Design / security invariants:

* **Per-principal session isolation (G-2, SI-3).** Each step runs as
  ``step.principal``; the :class:`SessionAwareHttpClient` injects *that*
  principal's isolated cookie jar + auth headers (resolved from the
  :class:`~src.auth.session_store.SessionStore`) and never mixes two
  principals' credentials.
* **Approval gate first (SI-1).** Before executing an approval-gated /
  high-risk playbook the executor asks a :class:`ScenarioApprovalGate`
  (typically backed by preflight + EAP). If it is not authorized the scenario
  transitions to ``WAITING_APPROVAL`` and *does not run* — an approval-gated
  step can never execute without a valid approval / EAP pre-authorization.
* **Network behind an abstraction.** All HTTP goes through the injected
  :class:`ScenarioTransport`; unit / P5 integration tests substitute a stub
  target. No production network is hard-coded. Tool execution stays argv-only
  through the declarative action interpreter (SI-4).
* **Evidence is always redacted (SI-3).** Baseline / mutated exchanges and
  their diff are built via :func:`~src.playbooks.evidence.build_evidence_bundle`,
  which redacts secrets before anything is persisted.
* **Cleanup always runs.** Even on PARTIAL / REJECTED / execution error, the
  :class:`~src.playbooks.cleanup.CleanupRunner` executes teardown steps.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable
from uuid import UUID

from src.auth.session_store import SessionStore
from src.pipeline.contracts.tool_job import TargetSpec
from src.playbooks.actions import (
    ActionContext,
    HttpExchange,
    HttpRequestSpec,
    HttpResponse,
    execute_step,
)
from src.playbooks.cleanup import CleanupOutcome, CleanupRunner
from src.playbooks.evidence import EvidenceBundle, build_evidence_bundle
from src.playbooks.lifecycle import ScenarioState, ScenarioStatus
from src.playbooks.oracles import OracleResult, OracleVerdict, get_oracle
from src.playbooks.schema import Playbook
from src.policy.engagement_authorization import (
    ActionClass,
    EngagementAuthorizationProfile,
    EngagementAuthorizationService,
    default_action_class,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Network transport abstraction
# ---------------------------------------------------------------------------


@runtime_checkable
class ScenarioTransport(Protocol):
    """The single network boundary a scenario is allowed to touch.

    Implementations perform the actual HTTP call. Unit and P5 integration
    tests inject a deterministic stub so no production network is contacted.
    """

    def send(self, spec: HttpRequestSpec, *, principal: str | None = None) -> HttpResponse:
        """Send ``spec`` (already carrying the principal's auth) and respond."""
        ...


class SessionAwareHttpClient:
    """``HttpClient`` that applies a principal's isolated session before sending.

    Secrets (cookies, bearer / API-key headers) are merged into the request
    here — the execution layer — and never before (SI-3). Two principals never
    share a jar because each :class:`~src.auth.session_store.PrincipalSession`
    owns its own.
    """

    def __init__(self, transport: ScenarioTransport, session_store: SessionStore) -> None:
        self._transport = transport
        self._store = session_store

    def send(self, spec: HttpRequestSpec, *, principal: str | None = None) -> HttpResponse:
        merged = self._apply_session(spec, principal)
        return self._transport.send(merged, principal=principal)

    def _apply_session(self, spec: HttpRequestSpec, principal: str | None) -> HttpRequestSpec:
        if principal is None:
            return spec
        session = self._store.get_session(principal)
        if session is None:
            return spec
        headers: dict[str, str] = dict(spec.headers)
        # Principal auth headers (Authorization / X-API-Key / CSRF) win over
        # any placeholder headers declared in the playbook step.
        headers.update(session.headers())
        cookie_header = session.cookie_header()
        if cookie_header:
            headers["Cookie"] = cookie_header
        return HttpRequestSpec(
            method=spec.method,
            url=spec.url,
            headers=headers,
            query=dict(spec.query),
            body=spec.body,
        )


# ---------------------------------------------------------------------------
# Approval gate abstraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ApprovalGateDecision:
    """Verdict of an approval gate for one approval-gated scenario."""

    authorized: bool
    approval_id: UUID | None = None
    reason: str | None = None


@runtime_checkable
class ScenarioApprovalGate(Protocol):
    """Answers "may this approval-gated playbook run against this target?".

    Implementations typically consult preflight (scope / ownership / policy)
    and the EAP as an audited source of auto-approval. A ``False`` decision
    keeps the scenario in ``WAITING_APPROVAL`` (SI-1).
    """

    def authorize(self, playbook: Playbook, target: TargetSpec) -> ApprovalGateDecision:
        """Return whether the playbook is authorized to execute."""
        ...


class EapApprovalGate:
    """Approval gate backed by an :class:`EngagementAuthorizationService`.

    Maps the playbook to an :class:`ActionClass` and asks the EAP to satisfy
    the approval pre-authorized (with an audit trail). If the class / target is
    not pre-authorized the gate denies — the scenario stays ``WAITING_APPROVAL``
    (SI-1). The EAP does not weaken preflight; callers that also need scope /
    ownership / policy enforcement run the full :class:`PreflightChecker`
    separately at dispatch (the EAP only satisfies the *approval* guardrail).
    """

    def __init__(
        self,
        *,
        eap_service: EngagementAuthorizationService,
        profile: EngagementAuthorizationProfile,
        tenant_id: UUID,
        scan_id: UUID | None = None,
        action_class_resolver: Callable[[Playbook], ActionClass] | None = None,
    ) -> None:
        self._eap = eap_service
        self._profile = profile
        self._tenant_id = tenant_id
        self._scan_id = scan_id
        self._resolver = action_class_resolver or _default_resolver

    def authorize(self, playbook: Playbook, target: TargetSpec) -> ApprovalGateDecision:
        action_class = self._resolver(playbook)
        decision = self._eap.authorize(
            self._profile,
            action_class,
            target,
            tenant_id=self._tenant_id,
            scan_id=self._scan_id,
        )
        return ApprovalGateDecision(
            authorized=decision.authorized,
            approval_id=decision.approval_id,
            reason=decision.reason,
        )


def _default_resolver(playbook: Playbook) -> ActionClass:
    return default_action_class(
        category=playbook.category.value, risk_level=playbook.risk_level.value
    )


# ---------------------------------------------------------------------------
# Result value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScenarioResult:
    """Immutable outcome of executing one scenario."""

    playbook_id: str
    state: ScenarioState
    executed: bool
    oracle_results: tuple[OracleResult, ...] = field(default_factory=tuple)
    evidence: EvidenceBundle | None = None
    cleanup: CleanupOutcome | None = None
    approval_id: UUID | None = None
    history: tuple[ScenarioState, ...] = field(default_factory=tuple)

    @property
    def status(self) -> ScenarioStatus:
        return self.state.status

    @property
    def is_confirmed(self) -> bool:
        # A scenario reaches CONFIRMED before cleanup; the terminal state is a
        # cleanup status, so consult the history too.
        return any(s.status is ScenarioStatus.CONFIRMED for s in self.history) or (
            self.state.status is ScenarioStatus.CONFIRMED
        )


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------


class ScenarioExecutor:
    """Execute a playbook end-to-end with lifecycle, oracles, evidence, cleanup."""

    def __init__(
        self,
        *,
        transport: ScenarioTransport,
        session_store: SessionStore,
        approval_gate: ScenarioApprovalGate | None = None,
        cleanup_runner: CleanupRunner | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._http = SessionAwareHttpClient(transport, session_store)
        self._approval_gate = approval_gate
        self._cleanup = cleanup_runner or CleanupRunner()
        self._sleep = sleep or time.sleep

    def execute(self, playbook: Playbook, *, target: TargetSpec) -> ScenarioResult:
        """Run ``playbook`` against ``target`` and return the terminal result."""
        history: list[ScenarioState] = []
        state = ScenarioState(status=ScenarioStatus.PLANNED)
        history.append(state)

        approval_id: UUID | None = None
        if playbook.requires_approval:
            gate = self._check_approval(playbook, target)
            if not gate.authorized:
                state = state.transition(
                    ScenarioStatus.WAITING_APPROVAL,
                    reason=gate.reason or "approval required but not authorized",
                )
                history.append(state)
                _logger.info(
                    "playbook.scenario.waiting_approval",
                    extra={"playbook_id": playbook.playbook_id, "reason": state.reason},
                )
                return ScenarioResult(
                    playbook_id=playbook.playbook_id,
                    state=state,
                    executed=False,
                    history=tuple(history),
                )
            approval_id = gate.approval_id

        ctx = ActionContext(http=self._http, sleep=self._sleep)
        state = state.transition(ScenarioStatus.RUNNING)
        history.append(state)

        exec_error: Exception | None = None
        try:
            for step in playbook.steps:
                execute_step(step, ctx)
        except Exception as exc:  # noqa: BLE001 — record, then always clean up
            exec_error = exc
            _logger.warning(
                "playbook.scenario.step_error",
                extra={
                    "playbook_id": playbook.playbook_id,
                    "error_class": type(exc).__name__,
                },
            )

        oracle_results: tuple[OracleResult, ...] = ()
        evidence: EvidenceBundle | None = None
        if exec_error is None:
            oracle_results = self._evaluate(playbook, ctx)
            evidence = self._build_evidence(ctx)
            verdict_status, reason = self._verdict(oracle_results)
            state = state.transition(verdict_status, reason=reason)
        else:
            state = state.transition(
                ScenarioStatus.REJECTED,
                reason=f"execution error: {type(exec_error).__name__}",
            )
        history.append(state)

        cleanup = self._cleanup.run(playbook, ctx)
        state = state.transition(cleanup.status, reason=cleanup.reason)
        history.append(state)

        return ScenarioResult(
            playbook_id=playbook.playbook_id,
            state=state,
            executed=True,
            oracle_results=oracle_results,
            evidence=evidence,
            cleanup=cleanup,
            approval_id=approval_id,
            history=tuple(history),
        )

    # -- helpers -------------------------------------------------------------

    def _check_approval(self, playbook: Playbook, target: TargetSpec) -> ApprovalGateDecision:
        if self._approval_gate is None:
            # Fail-closed: an approval-gated playbook with no gate configured
            # can never execute.
            return ApprovalGateDecision(
                authorized=False,
                reason="approval required but no approval gate is configured",
            )
        return self._approval_gate.authorize(playbook, target)

    def _evaluate(self, playbook: Playbook, ctx: ActionContext) -> tuple[OracleResult, ...]:
        if not ctx.exchanges:
            return ()
        baseline: HttpExchange = ctx.exchanges[0]
        mutated: HttpExchange = ctx.exchanges[-1]
        results: list[OracleResult] = []
        for assertion in playbook.assertions:
            params: Mapping[str, object] = assertion.params
            oracle = get_oracle(assertion.type)
            results.append(oracle.evaluate(baseline, mutated, params))
        return tuple(results)

    def _build_evidence(self, ctx: ActionContext) -> EvidenceBundle | None:
        if not ctx.exchanges:
            return None
        baseline = ctx.exchanges[0]
        mutated = ctx.exchanges[-1]
        return build_evidence_bundle(baseline, mutated)

    @staticmethod
    def _verdict(results: tuple[OracleResult, ...]) -> tuple[ScenarioStatus, str | None]:
        if not results:
            return (
                ScenarioStatus.REJECTED,
                "no oracle could be evaluated (no HTTP exchanges recorded)",
            )
        if any(r.verdict is OracleVerdict.FINDING for r in results):
            confirmed = [r for r in results if r.verdict is OracleVerdict.FINDING]
            return (
                ScenarioStatus.CONFIRMED,
                "; ".join(r.reason for r in confirmed)[:2000],
            )
        if any(r.verdict is OracleVerdict.INCONCLUSIVE for r in results):
            return (
                ScenarioStatus.PARTIAL,
                "oracle verdicts were inconclusive; manual review required",
            )
        return (
            ScenarioStatus.REJECTED,
            "; ".join(r.reason for r in results)[:2000] or "all oracles returned no finding",
        )


__all__ = [
    "ApprovalGateDecision",
    "EapApprovalGate",
    "ScenarioApprovalGate",
    "ScenarioExecutor",
    "ScenarioResult",
    "ScenarioTransport",
    "SessionAwareHttpClient",
]
