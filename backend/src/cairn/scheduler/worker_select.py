"""Worker selection + backoff (upstream D-09 / D-10).

``choose_worker`` sorts candidates by ``(priority, running_count, random)`` exactly
as upstream. ``select_workers`` applies the pre-sort filters — task-type support,
per-worker ``max_running``, and the two backoff windows — and records why each
rejected worker was skipped (for the dedup-logged no-op path, D-26).
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime

from src.cairn.workers.base import CairnWorkerConfig

UNHEALTHY_RETRY_AFTER_SECONDS = 5
REJECTED_RETRY_AFTER_SECONDS = 5


@dataclass(slots=True)
class WorkerSelection:
    """Result of filtering + sorting worker candidates for one (project, task)."""

    chosen: list[CairnWorkerConfig] = field(default_factory=list)
    blocked_busy: list[str] = field(default_factory=list)
    blocked_unhealthy: list[str] = field(default_factory=list)
    blocked_rejected: list[str] = field(default_factory=list)
    blocked_task_type: list[str] = field(default_factory=list)


def choose_worker(
    candidates: list[CairnWorkerConfig], running_counts: dict[str, int]
) -> list[CairnWorkerConfig]:
    """Stable-ish preference order: lower priority first, then fewer running, then random."""
    return sorted(
        candidates,
        key=lambda worker: (
            worker.priority,
            running_counts.get(worker.name, 0),
            random.random(),  # noqa: S311  # nosec B311 - tie-break only, not security-sensitive
        ),
    )


def select_workers(
    candidates: list[CairnWorkerConfig],
    *,
    task_type: str,
    project_id: str,
    running_counts: dict[str, int],
    unhealthy_until: dict[str, datetime],
    rejected_until: dict[tuple[str, str, str], datetime],
    now: datetime,
) -> WorkerSelection:
    """Filter candidates for a (project, task_type) and return the sorted choice."""
    selection = WorkerSelection()
    eligible: list[CairnWorkerConfig] = []
    for worker in candidates:
        if task_type not in worker.task_types:
            selection.blocked_task_type.append(worker.name)
            continue
        if running_counts.get(worker.name, 0) >= worker.max_running:
            selection.blocked_busy.append(worker.name)
            continue
        unhealthy_ts = unhealthy_until.get(worker.name)
        if unhealthy_ts is not None and unhealthy_ts > now:
            selection.blocked_unhealthy.append(worker.name)
            continue
        rejected_ts = rejected_until.get((project_id, task_type, worker.name))
        if rejected_ts is not None and rejected_ts > now:
            selection.blocked_rejected.append(worker.name)
            continue
        eligible.append(worker)
    selection.chosen = choose_worker(eligible, running_counts)
    return selection


__all__ = [
    "REJECTED_RETRY_AFTER_SECONDS",
    "UNHEALTHY_RETRY_AFTER_SECONDS",
    "WorkerSelection",
    "choose_worker",
    "select_workers",
]
