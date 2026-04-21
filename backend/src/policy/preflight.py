"""Preflight composer (Backlog/dev1_md §8).

The :class:`PreflightChecker` combines four orthogonal guardrails into a
single ``check`` call returned to the caller as a :class:`PreflightDecision`:

1. :class:`~src.policy.scope.ScopeEngine` — is the target inside the
   customer's authorised scope?
2. :class:`~src.policy.ownership.OwnershipProofStore` — has the customer
   proven they control the target?
3. :class:`~src.policy.policy_engine.PolicyEngine` — does the requested
   action fit within plan tier, phase risk caps, banned tools / families,
   rate limits, and budget caps?
4. :class:`~src.policy.approval.ApprovalService` — when the policy demands
   an approval (HIGH / DESTRUCTIVE), are the cryptographic signatures
   present and valid?

Composition order matters — the cheapest pure check (scope) runs first,
followed by ownership (cheap lookup), then policy (pure), then approval
(cryptographic verification). On the first failure the composer
short-circuits and emits an :class:`~src.policy.audit.AuditEventType.PREFLIGHT_DENY`
event. On full success it emits :class:`~src.policy.audit.AuditEventType.PREFLIGHT_PASS`.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Final
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
)

# Pure-DTO imports — these load no heavyweight transitive dependencies
# (signing / audit / payloads / pipeline.contracts) so they are safe to
# pull in unconditionally at module top.
from src.policy.approval_dto import (
    ApprovalAction,
    ApprovalError,
    ApprovalRequest,
    ApprovalSignature,
)
from src.policy.audit import AuditEventType, AuditLogger
from src.policy.ownership import OwnershipProofStore

if TYPE_CHECKING:
    # ALL cross-module imports below are type-only at module load time.
    # T02 follow-up: importing ``pipeline.contracts.tool_job``,
    # ``policy.policy_engine``, or ``policy.scope`` at module top eagerly
    # triggers ``pipeline.contracts.__init__`` which transitively loads
    # ``payloads.builder`` — and ``payloads.builder`` itself does
    # ``from src.policy.preflight import PreflightDeniedError`` at module
    # top. That round-trip is what makes the cycle close *before*
    # ``policy_engine`` / ``scope`` finish defining the symbols ``preflight``
    # would then need (``PolicyContext``, ``ScopeDecision`` etc.).
    #
    # Keeping these imports behind ``TYPE_CHECKING`` + ``from __future__
    # import annotations`` means:
    #   * Type hints in method signatures stay correct for static checkers.
    #   * Pydantic field types in :class:`PreflightDecision` are forward
    #     references resolved lazily by :func:`_ensure_pydantic_built`.
    # ``ApprovalService`` is also wired in by the caller via constructor
    # injection, so the runtime never needs the heavyweight
    # ``approval_service`` module on this import path.
    from src.pipeline.contracts.tool_job import TargetSpec, ToolJob
    from src.policy.approval_service import ApprovalService
    from src.policy.policy_engine import (
        PolicyContext,
        PolicyDecision,
        PolicyEngine,
    )
    from src.policy.scope import ScopeDecision, ScopeEngine


_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Failure taxonomy
# ---------------------------------------------------------------------------


_REASON_OWNERSHIP_MISSING: Final[str] = "preflight_ownership_missing"
_REASON_OWNERSHIP_EXPIRED: Final[str] = "preflight_ownership_expired"
_REASON_APPROVAL_TOKEN_MISSING: Final[str] = "preflight_approval_token_missing"

PREFLIGHT_FAILURE_REASONS: Final[frozenset[str]] = frozenset(
    {
        _REASON_OWNERSHIP_MISSING,
        _REASON_OWNERSHIP_EXPIRED,
        _REASON_APPROVAL_TOKEN_MISSING,
    }
)


PREFLIGHT_DENIED_TAXONOMY: Final[str] = "preflight_denied"
"""Compact summary used by the sandbox / payload shims when emitting a
:class:`~src.sandbox.k8s_adapter.SandboxRunResult` after a denial — keeps
``failure_reason`` short while the structured ``PreflightDecision`` carries
the precise sub-reason for audit consumers.
"""


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PreflightDeniedError(Exception):
    """Raised by call-sites that want preflight denial to surface as an exception.

    ``summary`` is the closed-taxonomy failure reason from one of the
    underlying guardrails — safe to surface to the customer.
    """

    def __init__(self, summary: str, *, decision: "PreflightDecision") -> None:
        super().__init__(summary)
        self.summary = summary
        self.decision = decision


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class PreflightDecision(BaseModel):
    """Composed verdict returned by :meth:`PreflightChecker.check`.

    The decision carries pointers to each sub-decision (scope / policy /
    approval status) so the caller can persist them immutably for audit.
    Free-form text is intentionally absent — failure reasons are pulled
    from the four sub-modules' closed taxonomies.

    ``defer_build=True`` is set because the ``ScopeDecision`` / ``PolicyDecision``
    field types are imported lazily (see :func:`_ensure_pydantic_built`).
    The first call to :meth:`PreflightChecker.__init__` — or the best-effort
    rebuild at the end of this module — finalises the schema before any
    instance is created.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, defer_build=True)

    decision_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    scan_id: UUID | None = None
    allowed: StrictBool
    failure_summary: StrictStr | None = Field(default=None, max_length=64)
    scope_decision: ScopeDecision
    policy_decision: PolicyDecision | None = None
    approval_required: StrictBool = False
    approval_verified: StrictBool = False
    decided_at: datetime = Field(default_factory=_utcnow)


def _ensure_pydantic_built() -> None:
    """Resolve :class:`PreflightDecision`'s deferred forward references.

    The model fields ``scope_decision`` and ``policy_decision`` reference
    :class:`~src.policy.scope.ScopeDecision` and
    :class:`~src.policy.policy_engine.PolicyDecision` — both of which can
    only be imported AFTER this module has finished its own load (otherwise
    the legacy ``policy.preflight ↔ pipeline.contracts ↔ payloads.builder``
    cycle slams shut, see the module-level ``TYPE_CHECKING`` comment).

    The function also injects :class:`PolicyContext` into module globals
    because :meth:`PreflightChecker.check_tool_job` constructs it directly
    at runtime — the ``TYPE_CHECKING``-only top-level import keeps
    ``policy_engine`` out of the cold-import path, but the class itself
    must be reachable through module globals once the policy plane is up.

    Idempotent: returns immediately once the schema is built.
    """
    if PreflightDecision.__pydantic_complete__:
        return
    from src.policy.policy_engine import (
        PolicyContext as _PolicyContext,
        PolicyDecision as _PolicyDecision,
    )
    from src.policy.scope import ScopeDecision as _ScopeDecision

    globals()["PolicyContext"] = _PolicyContext
    globals()["PolicyDecision"] = _PolicyDecision
    globals()["ScopeDecision"] = _ScopeDecision
    PreflightDecision.model_rebuild()


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------


class PreflightChecker:
    """Compose scope + ownership + policy + approval into a single decision.

    Parameters
    ----------
    scope_engine
        :class:`ScopeEngine` instance scoped to the tenant.
    ownership_store
        Persistence backend used to look up an existing
        :class:`~src.policy.ownership.OwnershipProof`.
    policy_engine
        :class:`PolicyEngine` for the same tenant.
    approval_service
        :class:`ApprovalService` used to verify Ed25519 signatures when
        the policy decision flags ``requires_approval``.
    audit_logger
        :class:`AuditLogger` to which final pass / deny events are
        written.
    skip_ownership_for_passive
        When ``True`` (default), ``RiskLevel.PASSIVE`` actions skip the
        ownership proof requirement at the preflight layer (the policy
        engine still applies its own rule via
        :attr:`~src.policy.policy_engine.TenantPolicy.require_ownership_proof`).
    """

    def __init__(
        self,
        *,
        scope_engine: ScopeEngine,
        ownership_store: OwnershipProofStore,
        policy_engine: PolicyEngine,
        approval_service: ApprovalService,
        audit_logger: AuditLogger,
    ) -> None:
        # By the time a caller has constructed real ``ScopeEngine`` /
        # ``PolicyEngine`` / ``ApprovalService`` instances, the modules
        # those classes live in are fully loaded — safe moment to finish
        # building :class:`PreflightDecision`'s deferred schema.
        _ensure_pydantic_built()
        self._scope_engine = scope_engine
        self._ownership_store = ownership_store
        self._policy_engine = policy_engine
        self._approval_service = approval_service
        self._audit_logger = audit_logger

    def check(
        self,
        *,
        target_spec: TargetSpec,
        port: int | None,
        policy_context: PolicyContext,
        approval_request: ApprovalRequest | None = None,
        approval_signatures: Sequence[ApprovalSignature] | None = None,
        revoked_signature_ids: Iterable[str] | None = None,
    ) -> PreflightDecision:
        """Run all four guardrails and return the composed decision.

        ``approval_request`` and ``approval_signatures`` are required only
        when the policy engine flags ``requires_approval``; the caller
        SHOULD always pass them when available so a single call is
        sufficient.
        """
        scope_decision = self._scope_engine.check(target_spec, port=port)
        if not scope_decision.allowed:
            return self._finalise_denial(
                tenant_id=policy_context.tenant_id,
                scan_id=policy_context.scan_id,
                summary=scope_decision.failure_summary or "scope_denied",
                scope_decision=scope_decision,
            )

        ownership_summary = self._evaluate_ownership(policy_context, target_spec)
        if ownership_summary is not None:
            return self._finalise_denial(
                tenant_id=policy_context.tenant_id,
                scan_id=policy_context.scan_id,
                summary=ownership_summary,
                scope_decision=scope_decision,
            )

        # Project the ownership lookup result back into the policy
        # context so the engine sees ``has_ownership_proof=True`` even
        # when the caller did not pre-populate it. Without this step the
        # policy engine would re-deny in the immediate next step.
        effective_context = self._with_ownership_resolved(policy_context, target_spec)
        policy_decision = self._policy_engine.evaluate(effective_context)
        if not policy_decision.allowed:
            return self._finalise_denial(
                tenant_id=policy_context.tenant_id,
                scan_id=policy_context.scan_id,
                summary=policy_decision.failure_summary or "policy_denied",
                scope_decision=scope_decision,
                policy_decision=policy_decision,
            )

        approval_required = policy_decision.requires_approval
        approval_verified = False
        if approval_required:
            try:
                self._verify_approval(
                    target_spec=target_spec,
                    policy_context=policy_context,
                    approval_request=approval_request,
                    approval_signatures=approval_signatures,
                    revoked_signature_ids=revoked_signature_ids,
                )
                approval_verified = True
            except ApprovalError as exc:
                return self._finalise_denial(
                    tenant_id=policy_context.tenant_id,
                    scan_id=policy_context.scan_id,
                    summary=exc.summary,
                    scope_decision=scope_decision,
                    policy_decision=policy_decision,
                    approval_required=True,
                )

        decision = PreflightDecision(
            tenant_id=policy_context.tenant_id,
            scan_id=policy_context.scan_id,
            allowed=True,
            failure_summary=None,
            scope_decision=scope_decision,
            policy_decision=policy_decision,
            approval_required=approval_required,
            approval_verified=approval_verified,
        )
        self._emit(decision, event_type=AuditEventType.PREFLIGHT_PASS)
        return decision

    def assert_allowed(
        self,
        *,
        target_spec: TargetSpec,
        port: int | None,
        policy_context: PolicyContext,
        approval_request: ApprovalRequest | None = None,
        approval_signatures: Sequence[ApprovalSignature] | None = None,
        revoked_signature_ids: Iterable[str] | None = None,
    ) -> PreflightDecision:
        """Like :meth:`check`, but raise :class:`PreflightDeniedError` on deny."""
        decision = self.check(
            target_spec=target_spec,
            port=port,
            policy_context=policy_context,
            approval_request=approval_request,
            approval_signatures=approval_signatures,
            revoked_signature_ids=revoked_signature_ids,
        )
        if not decision.allowed:
            assert decision.failure_summary is not None
            raise PreflightDeniedError(decision.failure_summary, decision=decision)
        return decision

    def check_tool_job(
        self,
        tool_job: ToolJob,
        *,
        approval_request: ApprovalRequest | None = None,
        approval_signatures: Sequence[ApprovalSignature] | None = None,
        revoked_signature_ids: Iterable[str] | None = None,
    ) -> PreflightDecision:
        """Defense-in-depth re-check of an already-dispatched :class:`ToolJob`.

        The orchestrator runs the FULL preflight (with rate-limit
        counters, budget projections, and approval signatures) before
        enqueueing the job. The sandbox adapter / payload builder calls
        this convenience to verify scope + ownership + minimal policy one
        more time so a stale or replayed message can never bypass the
        guardrails.

        Approval signatures are verified ONLY when the caller supplies
        them; without signatures, the check still requires
        ``tool_job.approval_id`` to be set whenever the policy engine
        flags ``requires_approval``.
        """
        proof = self._ownership_store.get(
            tenant_id=tool_job.tenant_id, target=tool_job.target.value
        )
        context = PolicyContext(
            tenant_id=tool_job.tenant_id,
            scan_id=tool_job.scan_id,
            phase=tool_job.phase,
            risk_level=tool_job.risk_level,
            tool_id=tool_job.tool_id,
            target=tool_job.target.value,
            has_ownership_proof=proof is not None,
            has_valid_approval=tool_job.approval_id is not None,
        )

        if approval_request is not None and approval_signatures is not None:
            return self.check(
                target_spec=tool_job.target,
                port=None,
                policy_context=context,
                approval_request=approval_request,
                approval_signatures=approval_signatures,
                revoked_signature_ids=revoked_signature_ids,
            )

        scope_decision = self._scope_engine.check(tool_job.target, port=None)
        if not scope_decision.allowed:
            return self._finalise_denial(
                tenant_id=tool_job.tenant_id,
                scan_id=tool_job.scan_id,
                summary=scope_decision.failure_summary or "scope_denied",
                scope_decision=scope_decision,
            )

        ownership_summary = self._evaluate_ownership(context, tool_job.target)
        if ownership_summary is not None:
            return self._finalise_denial(
                tenant_id=tool_job.tenant_id,
                scan_id=tool_job.scan_id,
                summary=ownership_summary,
                scope_decision=scope_decision,
            )

        policy_decision = self._policy_engine.evaluate(context)
        if not policy_decision.allowed:
            return self._finalise_denial(
                tenant_id=tool_job.tenant_id,
                scan_id=tool_job.scan_id,
                summary=policy_decision.failure_summary or "policy_denied",
                scope_decision=scope_decision,
                policy_decision=policy_decision,
            )

        if policy_decision.requires_approval and tool_job.approval_id is None:
            return self._finalise_denial(
                tenant_id=tool_job.tenant_id,
                scan_id=tool_job.scan_id,
                summary=_REASON_APPROVAL_TOKEN_MISSING,
                scope_decision=scope_decision,
                policy_decision=policy_decision,
                approval_required=True,
            )

        decision = PreflightDecision(
            tenant_id=tool_job.tenant_id,
            scan_id=tool_job.scan_id,
            allowed=True,
            failure_summary=None,
            scope_decision=scope_decision,
            policy_decision=policy_decision,
            approval_required=policy_decision.requires_approval,
            approval_verified=False,
        )
        self._emit(decision, event_type=AuditEventType.PREFLIGHT_PASS)
        return decision

    # -- Helpers -------------------------------------------------------------

    def _evaluate_ownership(
        self, policy_context: PolicyContext, target_spec: TargetSpec
    ) -> str | None:
        """Return ``None`` on success or a closed-taxonomy failure summary."""
        if not self._policy_engine.policy.require_ownership_proof:
            return None
        if policy_context.risk_level.value == "passive":
            return None
        existing = self._ownership_store.get(
            tenant_id=policy_context.tenant_id, target=target_spec.value
        )
        if existing is None:
            if policy_context.has_ownership_proof:
                return None
            return _REASON_OWNERSHIP_MISSING
        if existing.valid_until <= _utcnow():
            return _REASON_OWNERSHIP_EXPIRED
        return None

    def _with_ownership_resolved(
        self, policy_context: PolicyContext, target_spec: TargetSpec
    ) -> PolicyContext:
        """Return a copy of ``policy_context`` reflecting an in-store proof.

        Pydantic models are frozen, so we materialise a sibling instance
        whenever the proof was already in the store but the caller did
        not project it onto the context. Passive risk levels are left
        untouched — the policy engine never demands ownership for them.
        """
        if policy_context.has_ownership_proof:
            return policy_context
        if policy_context.risk_level.value == "passive":
            return policy_context
        existing = self._ownership_store.get(
            tenant_id=policy_context.tenant_id, target=target_spec.value
        )
        if existing is None:
            return policy_context
        return policy_context.model_copy(update={"has_ownership_proof": True})

    def _verify_approval(
        self,
        *,
        target_spec: TargetSpec,
        policy_context: PolicyContext,
        approval_request: ApprovalRequest | None,
        approval_signatures: Sequence[ApprovalSignature] | None,
        revoked_signature_ids: Iterable[str] | None,
    ) -> None:
        if approval_request is None or approval_signatures is None:
            raise ApprovalError("approval_missing")
        action = (
            ApprovalAction.DESTRUCTIVE
            if policy_context.risk_level.value == "destructive"
            else ApprovalAction.HIGH
        )
        self._approval_service.verify(
            request=approval_request,
            signatures=approval_signatures,
            revoked_signature_ids=revoked_signature_ids,
            expected_target=target_spec.value,
            expected_action=action,
        )

    def _finalise_denial(
        self,
        *,
        tenant_id: UUID,
        scan_id: UUID | None,
        summary: str,
        scope_decision: ScopeDecision,
        policy_decision: PolicyDecision | None = None,
        approval_required: bool = False,
    ) -> PreflightDecision:
        decision = PreflightDecision(
            tenant_id=tenant_id,
            scan_id=scan_id,
            allowed=False,
            failure_summary=summary,
            scope_decision=scope_decision,
            policy_decision=policy_decision,
            approval_required=approval_required,
            approval_verified=False,
        )
        self._emit(decision, event_type=AuditEventType.PREFLIGHT_DENY)
        return decision

    def _emit(self, decision: PreflightDecision, *, event_type: AuditEventType) -> None:
        self._audit_logger.emit(
            event_type=event_type,
            tenant_id=decision.tenant_id,
            scan_id=decision.scan_id,
            decision_allowed=decision.allowed,
            failure_summary=decision.failure_summary,
            payload={
                "decision_id": decision.decision_id,
                "approval_required": decision.approval_required,
                "approval_verified": decision.approval_verified,
            },
        )
        _logger.info(
            "policy.preflight.decision",
            extra={
                "tenant_id": str(decision.tenant_id),
                "scan_id": str(decision.scan_id) if decision.scan_id else None,
                "allowed": decision.allowed,
                "failure_summary": decision.failure_summary,
            },
        )


__all__ = [
    "PREFLIGHT_DENIED_TAXONOMY",
    "PREFLIGHT_FAILURE_REASONS",
    "PreflightChecker",
    "PreflightDecision",
    "PreflightDeniedError",
]


# Best-effort eager finalisation: in production / regular test runs the
# whole policy plane is already loaded by the time this line executes, so
# the rebuild succeeds and downstream callers get a fully-built schema
# without paying the lazy cost on first use.
#
# In the cyclic-import probe (``test_no_cyclic_imports.py``) an arbitrary
# policy module may be the *first* thing imported from a cold interpreter.
# In that scenario ``policy_engine`` / ``scope`` are still mid-load when
# this rebuild runs, so the import below raises ``ImportError`` (cannot
# import a name from a partially-initialised module). That is **expected
# and harmless** — :class:`PreflightChecker.__init__` re-runs the rebuild
# lazily before any decision is materialised, so the model is always
# complete before its first instantiation. We swallow the ImportError to
# keep the module itself importable in any order.
try:
    _ensure_pydantic_built()
except ImportError:
    _logger.debug(
        "policy.preflight.lazy_rebuild_pending",
        extra={
            "reason": "cyclic_import_in_progress",
            "resolved_at": "PreflightChecker.__init__",
        },
    )
