"""ARGUS policy plane — preflight guardrails (Backlog/dev1_md §8, §9, §16).

This package owns the four orthogonal pre-engagement guardrails that
every tool / payload run MUST consult before any side-effect-producing
operation:

* :mod:`src.policy.scope` — :class:`ScopeEngine`. Default-deny target
  matcher; deny rules override allow rules.
* :mod:`src.policy.ownership` — :class:`OwnershipVerifier`. DNS / HTTP
  ownership-of-target proof, with DRY-RUN mode for staging.
* :mod:`src.policy.policy_engine` — :class:`PolicyEngine`. Pure
  per-tenant policy evaluator: plan-tier ceiling, phase risk caps,
  banned tools / families, rate limits, budget caps.
* :mod:`src.policy.approval_dto` — pure pydantic DTOs (``ApprovalRequest``,
  ``ApprovalSignature``, enums, closed failure taxonomy). Zero
  dependencies on signing / audit; safe to import from anywhere.
* :mod:`src.policy.approval_service` — :class:`ApprovalService`. Ed25519
  verification + dual control + audit emission. Depends on
  ``sandbox.signing`` and ``policy.audit``.
* :mod:`src.policy.approval` — backward-compatibility shim that
  re-exports the DTOs and the service together (``from src.policy.approval
  import ApprovalService`` keeps working).
* :mod:`src.policy.preflight` — :class:`PreflightChecker`. Composes the
  four into a single :class:`PreflightDecision`. Depends on
  ``approval_dto`` only at runtime; ``ApprovalService`` is wired in via
  constructor injection so this module never re-creates the cycle.
* :mod:`src.policy.audit` — :class:`AuditLogger` + tamper-evident
  hash-chained :class:`AuditEvent` rows.

Lazy re-export discipline (T02 follow-up)
-----------------------------------------
Historically this ``__init__`` did eager ``from src.policy.<sub> import …``
re-exports for every public symbol. That made *any* access to the policy
package — even ``import src.policy.approval_dto`` — drag the entire
heavyweight chain (``src.sandbox.signing``, ``src.policy.audit``,
``src.payloads.builder``, ``src.pipeline.contracts.tool_job``) into
``sys.modules``. The pure-DTO layer is supposed to be importable in
isolation precisely so it never re-introduces the latent cycle T02
broke; eager re-exports defeated that guarantee.

This module now uses :pep:`562` ``__getattr__`` to resolve public names
on first access via :data:`_LAZY_MAP`. Every legacy convenience import
(``from src.policy import ApprovalService`` etc.) keeps working — the
import is just deferred until the symbol is actually touched. Direct
submodule imports (``import src.policy.approval_dto``) hit the lazy
``__init__`` body, find no eager imports to run, and finish without
loading any heavy dependency.

The package is execution-plane safe: nothing here imports
:mod:`src.db` / FastAPI / Celery, so it can be re-used from CLIs,
isolated unit tests, and the sandbox runner without dragging the
application stack.
"""

from __future__ import annotations

import importlib
from typing import Any


# Map: public attribute name → fully-qualified submodule that owns it.
# PEP 562 ``__getattr__`` resolves the import on first access so the
# package's import-time footprint stays minimal — critically, ``import
# src.policy.approval_dto`` no longer drags ``signing`` / ``audit`` /
# ``payloads`` into ``sys.modules``.
_LAZY_MAP: dict[str, str] = {
    # approval_dto — pure pydantic DTOs
    "APPROVAL_FAILURE_REASONS": "src.policy.approval_dto",
    "ApprovalAction": "src.policy.approval_dto",
    "ApprovalError": "src.policy.approval_dto",
    "ApprovalRequest": "src.policy.approval_dto",
    "ApprovalSignature": "src.policy.approval_dto",
    "ApprovalStatus": "src.policy.approval_dto",
    # approval_service — heavyweight verification engine
    "ApprovalService": "src.policy.approval_service",
    # audit
    "AuditChainError": "src.policy.audit",
    "AuditEvent": "src.policy.audit",
    "AuditEventType": "src.policy.audit",
    "AuditLogger": "src.policy.audit",
    "AuditPayloadError": "src.policy.audit",
    "AuditSink": "src.policy.audit",
    "GENESIS_HASH": "src.policy.audit",
    "InMemoryAuditSink": "src.policy.audit",
    # ownership
    "CLOUD_IAM_FAILURE_REASONS": "src.policy.ownership",
    "CLOUD_IAM_METHODS": "src.policy.ownership",
    "CLOUD_IAM_TTL_S": "src.policy.ownership",
    "CLOUD_SDK_TIMEOUT_S": "src.policy.ownership",
    "CloudOwnershipVerifierProtocol": "src.policy.ownership",
    "InMemoryOwnershipProofStore": "src.policy.ownership",
    "OWNERSHIP_FAILURE_REASONS": "src.policy.ownership",
    "OwnershipChallenge": "src.policy.ownership",
    "OwnershipMethod": "src.policy.ownership",
    "OwnershipProof": "src.policy.ownership",
    "OwnershipProofStore": "src.policy.ownership",
    "OwnershipTimeoutError": "src.policy.ownership",
    "OwnershipVerificationError": "src.policy.ownership",
    "OwnershipVerifier": "src.policy.ownership",
    "hash_identifier": "src.policy.ownership",
    # policy_engine
    "BudgetCap": "src.policy.policy_engine",
    "PLAN_MAX_RISK": "src.policy.policy_engine",
    "POLICY_FAILURE_REASONS": "src.policy.policy_engine",
    "PhaseRiskCap": "src.policy.policy_engine",
    "PlanTier": "src.policy.policy_engine",
    "PolicyContext": "src.policy.policy_engine",
    "PolicyDecision": "src.policy.policy_engine",
    "PolicyEngine": "src.policy.policy_engine",
    "RateLimit": "src.policy.policy_engine",
    "TenantPolicy": "src.policy.policy_engine",
    # preflight
    "PREFLIGHT_DENIED_TAXONOMY": "src.policy.preflight",
    "PREFLIGHT_FAILURE_REASONS": "src.policy.preflight",
    "PreflightChecker": "src.policy.preflight",
    "PreflightDecision": "src.policy.preflight",
    "PreflightDeniedError": "src.policy.preflight",
    # scope
    "PortRange": "src.policy.scope",
    "SCOPE_FAILURE_REASONS": "src.policy.scope",
    "ScopeDecision": "src.policy.scope",
    "ScopeEngine": "src.policy.scope",
    "ScopeKind": "src.policy.scope",
    "ScopeRule": "src.policy.scope",
    "ScopeViolation": "src.policy.scope",
}


def __getattr__(name: str) -> Any:
    """Resolve attribute lookups lazily via :data:`_LAZY_MAP`.

    PEP 562 module ``__getattr__`` fires whenever an attribute is missing
    from this module's globals. We import the owning submodule on demand,
    cache the resolved object back into globals so subsequent lookups are
    O(1), and re-raise :class:`AttributeError` for unknown names so
    ``hasattr`` / introspection behave normally.

    Identity is preserved: every legacy caller of
    ``from src.policy import ApprovalService`` receives the *same* class
    object that ``src.policy.approval_service.ApprovalService`` exposes —
    the lazy resolution does no wrapping or copying.
    """
    module_path = _LAZY_MAP.get(name)
    if module_path is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(module_path)
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Expose lazily-loaded names for :func:`dir` / IDE autocomplete."""
    return sorted(set(globals()) | set(_LAZY_MAP))


__all__ = [
    "APPROVAL_FAILURE_REASONS",
    "ApprovalAction",
    "ApprovalError",
    "ApprovalRequest",
    "ApprovalService",
    "ApprovalSignature",
    "ApprovalStatus",
    "AuditChainError",
    "AuditEvent",
    "AuditEventType",
    "AuditLogger",
    "AuditPayloadError",
    "AuditSink",
    "BudgetCap",
    "CLOUD_IAM_FAILURE_REASONS",
    "CLOUD_IAM_METHODS",
    "CLOUD_IAM_TTL_S",
    "CLOUD_SDK_TIMEOUT_S",
    "CloudOwnershipVerifierProtocol",
    "GENESIS_HASH",
    "InMemoryAuditSink",
    "InMemoryOwnershipProofStore",
    "OWNERSHIP_FAILURE_REASONS",
    "OwnershipChallenge",
    "OwnershipMethod",
    "OwnershipProof",
    "OwnershipProofStore",
    "OwnershipTimeoutError",
    "OwnershipVerificationError",
    "OwnershipVerifier",
    "PLAN_MAX_RISK",
    "POLICY_FAILURE_REASONS",
    "PREFLIGHT_DENIED_TAXONOMY",
    "PREFLIGHT_FAILURE_REASONS",
    "PhaseRiskCap",
    "PlanTier",
    "PolicyContext",
    "PolicyDecision",
    "PolicyEngine",
    "PortRange",
    "PreflightChecker",
    "PreflightDecision",
    "PreflightDeniedError",
    "RateLimit",
    "SCOPE_FAILURE_REASONS",
    "ScopeDecision",
    "ScopeEngine",
    "ScopeKind",
    "ScopeRule",
    "ScopeViolation",
    "TenantPolicy",
    "hash_identifier",
]
