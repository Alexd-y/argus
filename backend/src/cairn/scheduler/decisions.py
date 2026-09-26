"""Task-selection decision logic (upstream D-03 / D-05 / D-06).

Pure functions over a snapshot of project state so they are unit-testable without a
database. The tick (``tasks.py``) builds the snapshot from the graph and acts on the
returned decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from src.cairn.schemas import BOOTSTRAP_DESCRIPTION, GOAL_REF, ORIGIN_REF


@dataclass(slots=True)
class IntentSnapshot:
    ref: str
    worker: str | None
    is_bootstrap: bool
    created_at: datetime


@dataclass(slots=True)
class ReasonCheckpoint:
    fact_count: int
    hint_count: int
    open_intent_count: int


@dataclass(slots=True)
class ProjectDispatchState:
    status: str
    fact_refs: list[str]
    open_intents: list[IntentSnapshot]
    bootstrap_enabled: bool
    reason_worker: str | None
    hint_count: int
    running_task_count: int
    max_project_workers: int
    checkpoint: ReasonCheckpoint | None = None
    fact_count: int = 0


@dataclass(slots=True)
class TaskDecision:
    kind: str  # "bootstrap" | "reason" | "explore" | "noop"
    trigger: str | None = None
    intent_ref: str | None = None
    reason: str | None = None


def is_initial_project(state: ProjectDispatchState) -> bool:
    """Graph is exactly {origin, goal} with no intents (or only a bootstrap one)."""
    if set(state.fact_refs) != {ORIGIN_REF, GOAL_REF}:
        return False
    non_bootstrap = [i for i in state.open_intents if not i.is_bootstrap]
    return not non_bootstrap


def reason_trigger(state: ProjectDispatchState) -> str | None:
    """Return the reason trigger name if reasoning should run, else None (D-05)."""
    checkpoint = state.checkpoint
    if checkpoint is None:
        # No checkpoint yet — the tick initialises one; only fire on the initial
        # project (handled in select_task_for_project).
        return None
    if state.fact_count > checkpoint.fact_count:
        return "facts_grew"
    if state.hint_count > checkpoint.hint_count:
        return "hints_grew"
    open_count = len([i for i in state.open_intents if not i.is_bootstrap])
    if checkpoint.open_intent_count > 0 and open_count == 0:
        return "intents_drained"
    return None


def select_task_for_project(
    state: ProjectDispatchState, *, worker_supports_bootstrap: bool
) -> TaskDecision:
    """Decide the next task for a project (upstream ``_try_dispatch_project``)."""
    if state.running_task_count >= state.max_project_workers:
        return TaskDecision(kind="noop", reason="max_project_workers")
    if state.status != "active":
        return TaskDecision(kind="noop", reason="not_active")

    if is_initial_project(state):
        if state.reason_worker is not None:
            return TaskDecision(kind="noop", reason="reason_lease_held")
        has_bootstrap_intent = any(i.is_bootstrap for i in state.open_intents)
        if state.bootstrap_enabled and (has_bootstrap_intent or worker_supports_bootstrap):
            # skip if the bootstrap intent is already claimed
            claimed = any(i.is_bootstrap and i.worker is not None for i in state.open_intents)
            if claimed:
                return TaskDecision(kind="noop", reason="bootstrap_running")
            return TaskDecision(kind="bootstrap", trigger="initial")
        return TaskDecision(kind="reason", trigger="initial")

    if state.reason_worker is None:
        trigger = reason_trigger(state)
        if trigger is not None:
            return TaskDecision(kind="reason", trigger=trigger)

    unclaimed = [i for i in state.open_intents if not i.is_bootstrap and i.worker is None]
    if unclaimed:
        newest = max(unclaimed, key=lambda i: i.created_at)
        return TaskDecision(kind="explore", intent_ref=newest.ref)

    return TaskDecision(kind="noop", reason="nothing_to_do")


# Special description marker for the dispatcher-created bootstrap intent.
BOOTSTRAP_INTENT_DESCRIPTION = BOOTSTRAP_DESCRIPTION


__all__ = [
    "BOOTSTRAP_INTENT_DESCRIPTION",
    "IntentSnapshot",
    "ProjectDispatchState",
    "ReasonCheckpoint",
    "TaskDecision",
    "is_initial_project",
    "reason_trigger",
    "select_task_for_project",
]
