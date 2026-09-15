"""Per-scan budget-ledger registry (platform-hardening A, §8.3).

Mirrors :func:`src.orchestration.cost_aware_reasoning.get_cost_tracker`: the scan
runner registers an authoritative :class:`~src.orchestration.budget_ledger.BudgetLedger`
for a scan, and the LLM facade looks it up on the hot path to apply
``reserve → call → settle`` around each provider call.

Kept deliberately dependency-light (a process-local dict) so importing it never
drags the Postgres store into offline call paths. When no ledger is registered
for a scan the facade simply skips budgeting — identical to the pre-feature
behaviour — so the feature is safe to leave wired while ``BUDGET_LEDGER_ENABLED``
is off.
"""

from __future__ import annotations

from src.orchestration.budget_ledger import BudgetLedger

_scan_ledgers: dict[str, BudgetLedger] = {}


def register_scan_ledger(scan_id: str, ledger: BudgetLedger) -> None:
    """Register the authoritative budget ledger for ``scan_id``."""
    if scan_id:
        _scan_ledgers[scan_id] = ledger


def unregister_scan_ledger(scan_id: str) -> None:
    """Drop the ledger for a completed scan."""
    _scan_ledgers.pop(scan_id, None)


def get_scan_ledger(scan_id: str) -> BudgetLedger | None:
    """Look up the budget ledger for ``scan_id`` (``None`` when unregistered)."""
    if not scan_id:
        return None
    return _scan_ledgers.get(scan_id)


__all__ = [
    "get_scan_ledger",
    "register_scan_ledger",
    "unregister_scan_ledger",
]
