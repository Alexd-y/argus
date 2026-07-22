"""Cleanup registration and execution for executed scenarios (P4-SCENARIO-004).

A scenario may create server-side artefacts (test accounts, uploaded files,
draft orders). Every such artefact MUST be removed after the scenario runs —
regardless of the verdict (CONFIRMED / REJECTED / PARTIAL) or an execution
error. This module owns that teardown.

Cleanup steps are declared in :attr:`~src.playbooks.schema.Playbook.cleanup`
and *registered* at runtime by ``register_cleanup`` steps (which record their
target id in the :class:`~src.playbooks.actions.ActionContext` variable store).
:class:`CleanupRunner` executes the registered cleanup steps through the same
declarative action interpreter used for the main flow (SI-4: argv/declarative
only, no shell). If nothing was explicitly registered, every declared cleanup
step is attempted as a fail-safe — teardown should never be silently skipped.

The runner is *best-effort and total*: a failure in one cleanup step does not
abort the rest; all failures are collected and surfaced as a single
``CLEANUP_FAILED`` outcome with a concrete reason for auditors.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from src.playbooks.actions import ActionContext, RegisterCleanupAction, execute_step
from src.playbooks.lifecycle import ScenarioStatus
from src.playbooks.schema import Playbook, PlaybookStep

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CleanupOutcome:
    """Immutable result of running a scenario's cleanup steps.

    ``status`` is always one of :attr:`ScenarioStatus.CLEANUP_COMPLETE` or
    :attr:`ScenarioStatus.CLEANUP_FAILED`. ``reason`` is populated (non-empty)
    whenever the status is ``CLEANUP_FAILED`` so the lifecycle state machine's
    reason-required contract is satisfied.
    """

    status: ScenarioStatus
    reason: str | None
    executed_step_ids: tuple[str, ...] = field(default_factory=tuple)
    failed_step_ids: tuple[str, ...] = field(default_factory=tuple)

    @property
    def succeeded(self) -> bool:
        return self.status is ScenarioStatus.CLEANUP_COMPLETE


class CleanupRunner:
    """Execute a playbook's declared cleanup steps against an action context."""

    def _resolve_steps(self, playbook: Playbook, ctx: ActionContext) -> list[PlaybookStep]:
        """Return the ordered cleanup steps to execute.

        Preference order:

        1. Steps whose id was registered via a ``register_cleanup`` action
           (recorded in the variable store), preserving declaration order.
        2. If none were registered, *all* declared cleanup steps (fail-safe so
           teardown is never silently skipped even when a scenario aborted
           before reaching its ``register_cleanup`` steps).
        """
        registered = ctx.variables.get(RegisterCleanupAction._VAR_KEY)
        if isinstance(registered, list) and registered:
            ordered: list[PlaybookStep] = []
            seen: set[str] = set()
            for step in playbook.cleanup:
                if step.id in registered and step.id not in seen:
                    ordered.append(step)
                    seen.add(step.id)
            return ordered
        return list(playbook.cleanup)

    def run(self, playbook: Playbook, ctx: ActionContext) -> CleanupOutcome:
        """Execute the resolved cleanup steps; never raises for step failures."""
        steps = self._resolve_steps(playbook, ctx)
        if not steps:
            return CleanupOutcome(status=ScenarioStatus.CLEANUP_COMPLETE, reason=None)

        executed: list[str] = []
        failed: list[str] = []
        for step in steps:
            try:
                result = execute_step(step, ctx)
            except Exception as exc:  # noqa: BLE001 — teardown is total, never re-raises
                failed.append(step.id)
                _logger.warning(
                    "playbook.cleanup.step_failed",
                    extra={
                        "playbook_id": playbook.playbook_id,
                        "step_id": step.id,
                        "error_class": type(exc).__name__,
                    },
                )
                continue
            executed.append(step.id)
            if not result.ok:
                failed.append(step.id)
                _logger.warning(
                    "playbook.cleanup.step_not_ok",
                    extra={"playbook_id": playbook.playbook_id, "step_id": step.id},
                )

        if failed:
            return CleanupOutcome(
                status=ScenarioStatus.CLEANUP_FAILED,
                reason=f"cleanup failed for step(s): {', '.join(sorted(set(failed)))}",
                executed_step_ids=tuple(executed),
                failed_step_ids=tuple(dict.fromkeys(failed)),
            )
        return CleanupOutcome(
            status=ScenarioStatus.CLEANUP_COMPLETE,
            reason=None,
            executed_step_ids=tuple(executed),
        )


__all__ = [
    "CleanupOutcome",
    "CleanupRunner",
]
