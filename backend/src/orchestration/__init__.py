"""Orchestration — scan state machine, phase execution."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from src.orchestration.phases import ExploitationSubPhase, PhaseDefinition, ScanPhase

if TYPE_CHECKING:
    from src.orchestration.state_machine import (
        ExploitationApprovalRequiredError,
        LabLeaseRequiredError,
        run_scan_state_machine,
    )

__all__ = [
    "ExploitationApprovalRequiredError",
    "ExploitationSubPhase",
    "LabLeaseRequiredError",
    "PhaseDefinition",
    "ScanPhase",
    "run_scan_state_machine",
]

_LAZY_STATE_MACHINE_EXPORTS = frozenset(
    {
        "ExploitationApprovalRequiredError",
        "LabLeaseRequiredError",
        "run_scan_state_machine",
    }
)


def __getattr__(name: str) -> Any:
    """Lazily resolve ``state_machine`` exports (PEP 562).

    Importing ``state_machine`` at package-import time creates a circular
    import: ``state_machine`` → ``handlers`` → ``va_active_scan_phase`` →
    ``mcp_runner`` → ``src.sandbox.execution_lease_gate`` →
    ``src.orchestration.execution_mode_context``. That last hop re-enters this
    package's ``__init__`` while ``execution_lease_gate`` is still initialising,
    raising ``ImportError``. Deferring the ``state_machine`` import until first
    attribute access breaks the cycle while keeping the public API stable.
    """
    if name in _LAZY_STATE_MACHINE_EXPORTS:
        from src.orchestration import state_machine

        return getattr(state_machine, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
