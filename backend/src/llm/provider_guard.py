"""Provider-call guard: distributed pool slot + budget reserve→settle (§8.1/§8.3).

A single async context manager wrapped around every real LLM provider dispatch
in :mod:`src.llm.facade`. It composes the two platform-hardening §8 concerns at
one choke point so the facade helpers stay readable:

* **§8.1 pool slot** — hold one ``provider`` concurrency slot via
  :func:`src.orchestration.pool_leases.apool_slot` (no-op unless ``LEASE_ENABLED``
  and Redis are configured).
* **§8.3 reserve-before-call** — when ``BUDGET_LEDGER_ENABLED`` and a ledger is
  registered for the scan, reserve budget *before* the call, settle it with
  provider-metadata usage afterwards, and leave the reservation ``uncertain``
  when the call started but its usage is unknown (an ambiguous post-send
  failure). A ``BudgetDeniedError`` propagates so the caller stops the call
  instead of spending unbounded.

The call scope (tenant/scan + a conservative token/cost estimate) is carried in
a :class:`contextvars.ContextVar` set by the facade at entry, so provider helpers
need no new parameters. The var is reset by the facade in a ``finally`` block so
it never leaks across calls sharing a task.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass

from src.core.config import settings
from src.orchestration.agent_contracts import AgentUsage
from src.orchestration.budget_ledger import BudgetDeniedError, BudgetScope
from src.orchestration.budget_scan_registry import get_scan_ledger
from src.orchestration.pool_leases import apool_slot

logger = logging.getLogger(__name__)

# Providers that incur real, external spend. Local engines (WhiteRabbitNeo via
# vLLM, a local OpenAI-compatible server) are zero-cost and are never denied on
# a budget-store outage — only *paid* calls fail closed (§8.3).
_PAID_PROVIDERS = frozenset({"cloud"})


@dataclass(frozen=True)
class CallScope:
    """Budget scope + conservative pre-call estimate for one LLM call."""

    tenant_id: str = ""
    scan_id: str = ""
    est_tokens: int = 0
    est_cost_usd: float = 0.0


_call_scope: ContextVar[CallScope | None] = ContextVar("argus_llm_call_scope", default=None)


def set_call_scope(scope: CallScope) -> Token[CallScope | None]:
    """Bind the current call scope; returns a token for :func:`reset_call_scope`."""
    return _call_scope.set(scope)


def reset_call_scope(token: Token[CallScope | None]) -> None:
    """Restore the previous call scope (call from a ``finally`` block)."""
    _call_scope.reset(token)


class ProviderRun:
    """Handle yielded by :func:`provider_guard` to report actual provider usage."""

    def __init__(self) -> None:
        self.usage: AgentUsage | None = None

    def record_usage(self, usage: AgentUsage) -> None:
        """Record provider-metadata usage; settled into the ledger on exit."""
        self.usage = usage


@asynccontextmanager
async def provider_guard(provider: str):
    """Guard a single provider call with a pool slot and a budget reservation.

    Yields a :class:`ProviderRun`; the caller SHOULD invoke ``record_usage`` with
    provider-metadata usage once the response is available. Budget settlement
    follows the ledger's ``budgeted`` discipline (settle on usage, ``uncertain``
    when started without usage, release when never started).
    """
    run = ProviderRun()
    async with apool_slot("provider", provider):
        scope = _call_scope.get()
        in_scan = scope is not None and bool(scope.scan_id)
        if not (settings.budget_ledger_enabled and in_scan):
            # Ledger disabled or the call is not scan-scoped — nothing to enforce.
            yield run
            return

        ledger = get_scan_ledger(scope.scan_id)
        if ledger is not None and ledger.available:
            budget_scope = BudgetScope(tenant_id=scope.tenant_id, scan_id=scope.scan_id)
            async with ledger.budgeted(
                budget_scope, scope.est_tokens, scope.est_cost_usd
            ) as reservation:
                reservation.mark_started()
                yield run
                if run.usage is not None:
                    reservation.record_usage(run.usage)
            return

        # §8.3 fail-closed: the ledger is enabled for this scan but its store is
        # unavailable (never registered / degraded). A *paid* call must be denied
        # rather than fall back to unbounded spend; zero-cost local engines pass.
        if provider in _PAID_PROVIDERS:
            logger.warning(
                "budget_ledger_unavailable_deny",
                extra={
                    "event": "budget_ledger_unavailable_deny",
                    "provider": provider,
                    "scan_id": scope.scan_id,
                },
            )
            raise BudgetDeniedError(
                f"budget ledger unavailable for scan {scope.scan_id} — denying paid {provider} call"
            )
        yield run


__all__ = [
    "CallScope",
    "ProviderRun",
    "provider_guard",
    "reset_call_scope",
    "set_call_scope",
]
