"""Mandatory forward gate for the workbench proxy (WB-P2a, SI-WB-1).

Every request the proxy would forward upstream MUST pass this gate first. The
gate is fail-closed and layered:

1. **Scope** — the request's target is checked against the project's scope
   rules via the shared :class:`~src.policy.scope.ScopeEngine` (default-deny;
   deny rules shadow allow rules). An out-of-scope or explicitly-denied target
   is blocked here and never leaves the proxy.
2. **Preflight (optional hook)** — when a full
   :class:`~src.policy.preflight.PreflightChecker`-backed callable is wired
   (the live daemon does this in WB-P2b), it runs after scope and can block on
   ownership / policy / approval grounds. Without it, the gate enforces scope
   only — it never fails *open*.

The gate returns a :class:`ForwardDecision` carrying a closed-taxonomy reason so
user-facing messages never echo scope internals or rule indexes.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from src.pipeline.contracts.tool_job import TargetSpec
from src.web_workbench.projects.service import ProjectScopeService
from src.web_workbench.proxy.transport import HttpMessageError, NormalizedRequest


class ForwardOutcome(StrEnum):
    """Terminal disposition for a candidate forward."""

    FORWARD = "forward"
    BLOCKED = "blocked"


#: Closed-taxonomy block reasons (never free-form; never echo scope internals).
REASON_OUT_OF_SCOPE = "out_of_scope"
REASON_PREFLIGHT_DENIED = "preflight_denied"
REASON_UNRESOLVABLE_TARGET = "unresolvable_target"


@dataclass(frozen=True)
class ForwardDecision:
    """Result of the forward gate.

    ``allowed`` is ``True`` only when every layer passed. ``reason`` is ``None``
    on allow, otherwise a closed-taxonomy summary. ``scope_summary`` mirrors the
    scope engine's closed failure summary for audit (never shown raw to users).
    """

    outcome: ForwardOutcome
    reason: str | None
    scope_summary: str | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome is ForwardOutcome.FORWARD


#: A preflight hook takes the derived target + port and returns
#: ``(allowed, reason)``. It must be fail-closed. Wired by the live daemon.
PreflightHook = Callable[[TargetSpec, int], tuple[bool, str | None]]


class ForwardGate:
    """Scope-first, fail-closed gate for proxy forwarding.

    Construct once per project (the scope rule set is closed over via
    :class:`ProjectScopeService`); optionally supply a ``preflight_hook`` for
    the full ownership/policy/approval guardrail in the live daemon.
    """

    def __init__(
        self,
        scope_service: ProjectScopeService,
        *,
        preflight_hook: PreflightHook | None = None,
    ) -> None:
        self._scope = scope_service
        self._preflight = preflight_hook

    def evaluate(self, request: NormalizedRequest) -> ForwardDecision:
        """Decide whether ``request`` may be forwarded upstream."""
        try:
            target, port = request.to_target_spec()
        except HttpMessageError:
            return ForwardDecision(
                outcome=ForwardOutcome.BLOCKED,
                reason=REASON_UNRESOLVABLE_TARGET,
            )

        scope_decision = self._scope.check(target, port=port)
        if not scope_decision.allowed:
            return ForwardDecision(
                outcome=ForwardOutcome.BLOCKED,
                reason=REASON_OUT_OF_SCOPE,
                scope_summary=scope_decision.failure_summary,
            )

        if self._preflight is not None:
            allowed, reason = self._preflight(target, port)
            if not allowed:
                return ForwardDecision(
                    outcome=ForwardOutcome.BLOCKED,
                    reason=reason or REASON_PREFLIGHT_DENIED,
                )

        return ForwardDecision(outcome=ForwardOutcome.FORWARD, reason=None)


__all__ = [
    "REASON_OUT_OF_SCOPE",
    "REASON_PREFLIGHT_DENIED",
    "REASON_UNRESOLVABLE_TARGET",
    "ForwardDecision",
    "ForwardGate",
    "ForwardOutcome",
    "PreflightHook",
]
