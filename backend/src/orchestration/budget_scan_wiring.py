"""Scan-scoped budget-ledger wiring (platform-hardening A, §8.3).

Bridges the durable :class:`~src.orchestration.budget_ledger_pg.PostgresBudgetStore`
to the per-scan registry consumed by the LLM facade. Called by the scan state
machine (only when ``BUDGET_LEDGER_ENABLED``) so that ``reserve → call → settle``
is enforced against a shared Postgres store — the single budget authority.

Isolated in its own module so the Postgres/session dependency is not dragged
into the dependency-light :mod:`budget_scan_registry` that the facade imports.
"""

from __future__ import annotations

import logging

from src.db.session import async_session_factory
from src.orchestration.budget_ledger import BudgetLedger, BudgetScope
from src.orchestration.budget_ledger_pg import PostgresBudgetStore
from src.orchestration.budget_scan_registry import register_scan_ledger

logger = logging.getLogger(__name__)


async def register_scan_budget_ledger(
    *,
    scan_id: str,
    tenant_id: str,
    max_cost_usd: float,
    max_total_tokens: int,
) -> BudgetLedger:
    """Register an authoritative Postgres-backed ledger for ``scan_id``.

    Sets the scan-scope caps then registers the ledger so the facade can
    reserve/settle against it. Returns the ledger (mainly for tests).
    """
    store = PostgresBudgetStore(async_session_factory)
    scope_key = BudgetScope(scan_id=scan_id).keys()[0]
    await store.set_limits(scope_key, max_tokens=max_total_tokens, max_cost_usd=max_cost_usd)
    ledger = BudgetLedger(store)
    register_scan_ledger(scan_id, ledger)
    logger.info(
        "scan_budget_ledger_registered",
        extra={
            "event": "scan_budget_ledger_registered",
            "scan_id": scan_id,
            "tenant_id": tenant_id,
            "max_cost_usd": max_cost_usd,
            "max_total_tokens": max_total_tokens,
        },
    )
    return ledger


__all__ = ["register_scan_budget_ledger"]
