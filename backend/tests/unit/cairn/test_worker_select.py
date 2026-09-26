"""Phase 8 — worker selection + backoff (D-09/D-10)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from src.cairn.scheduler.worker_select import choose_worker, select_workers
from src.cairn.workers.base import CairnWorkerConfig


def _w(name: str, priority: int = 100, max_running: int = 2, task_types=("reason", "explore")):
    return CairnWorkerConfig(
        name=name,
        type_name="wrb",
        priority=priority,
        max_running=max_running,
        task_types=tuple(task_types),
    )


def test_choose_worker_orders_by_priority_then_running() -> None:
    a = _w("a", priority=50)
    b = _w("b", priority=10)
    c = _w("c", priority=10)
    ordered = choose_worker([a, b, c], running_counts={"b": 1, "c": 0})
    # priority 10 first; within that, fewer running first → c before b
    assert ordered[0].name == "c"
    assert ordered[-1].name == "a"


def test_select_filters_task_type() -> None:
    now = datetime.now(UTC)
    sel = select_workers(
        [_w("a", task_types=("reason",))],
        task_type="explore",
        project_id="p1",
        running_counts={},
        unhealthy_until={},
        rejected_until={},
        now=now,
    )
    assert sel.chosen == []
    assert sel.blocked_task_type == ["a"]


def test_select_filters_busy() -> None:
    now = datetime.now(UTC)
    sel = select_workers(
        [_w("a", max_running=1)],
        task_type="reason",
        project_id="p1",
        running_counts={"a": 1},
        unhealthy_until={},
        rejected_until={},
        now=now,
    )
    assert sel.chosen == []
    assert sel.blocked_busy == ["a"]


def test_select_filters_unhealthy_and_rejected() -> None:
    now = datetime.now(UTC)
    future = now + timedelta(seconds=5)
    sel = select_workers(
        [_w("a"), _w("b")],
        task_type="reason",
        project_id="p1",
        running_counts={},
        unhealthy_until={"a": future},
        rejected_until={("p1", "reason", "b"): future},
        now=now,
    )
    assert sel.chosen == []
    assert sel.blocked_unhealthy == ["a"]
    assert sel.blocked_rejected == ["b"]


def test_select_allows_after_backoff_expires() -> None:
    now = datetime.now(UTC)
    past = now - timedelta(seconds=1)
    sel = select_workers(
        [_w("a")],
        task_type="reason",
        project_id="p1",
        running_counts={},
        unhealthy_until={"a": past},
        rejected_until={},
        now=now,
    )
    assert [w.name for w in sel.chosen] == ["a"]
