"""Regression tests for SubAgentSpawner accounting/session hygiene (3.4)."""

from __future__ import annotations

import pytest
from src.orchestration.sub_agent_spawner import SubAgentSpawner, SubAgentTask


def test_session_released_on_success():
    spawner = SubAgentSpawner()
    task = SubAgentTask(task_description="ok")
    result = spawner.spawn(task, executor=lambda _desc: {"result": "ok", "tokens_used": 100})
    assert result.error == ""
    assert task.session_id not in spawner._active_sessions
    assert spawner.reserved_tokens == 0
    assert spawner.total_tokens_used == 100


def test_session_released_on_exception():
    """Original bug: an executor exception left the session registered."""
    spawner = SubAgentSpawner()
    task = SubAgentTask(task_description="boom")

    def _boom(_desc: str):
        raise RuntimeError("kaboom")

    result = spawner.spawn(task, executor=_boom)
    assert "kaboom" in result.error
    assert result.output == {}
    # Session and reservation must be released even though the executor raised.
    assert task.session_id not in spawner._active_sessions
    assert spawner.reserved_tokens == 0


async def test_async_session_released_on_exception():
    spawner = SubAgentSpawner()
    task = SubAgentTask(task_description="boom")

    async def _boom(_desc: str):
        raise RuntimeError("async-kaboom")

    result = await spawner.aspawn(task, executor=_boom)
    assert "async-kaboom" in result.error
    assert task.session_id not in spawner._active_sessions
    assert spawner.reserved_tokens == 0


def test_reservation_prevents_over_commit():
    # Budget only fits one 50k task; a second must be rejected while the first
    # holds its reservation. We simulate concurrency by reserving before settle.
    spawner = SubAgentSpawner(max_total_tokens=60000)
    t1 = SubAgentTask(task_description="a", token_budget=50000)
    assert spawner.can_spawn(t1) is True
    reserved = spawner._reserve(t1)
    assert reserved == 50000
    t2 = SubAgentTask(task_description="b", token_budget=50000)
    # With 50k reserved and 60k cap, the remaining budget is exhausted.
    assert spawner.can_spawn(t2) is False
    spawner._settle(t1, reserved, {"tokens_used": 10000})
    assert spawner.total_tokens_used == 10000
    assert spawner.reserved_tokens == 0
    # After settle, budget frees up again.
    assert spawner.can_spawn(t2) is True


def test_per_task_budget_overage_flagged():
    spawner = SubAgentSpawner()
    task = SubAgentTask(task_description="greedy", token_budget=100)
    result = spawner.spawn(task, executor=lambda _desc: {"result": "x", "tokens_used": 500})
    assert "budget_exceeded" in result.error
    # Actual usage is still booked (we cannot un-spend real tokens).
    assert spawner.total_tokens_used == 500


def test_missing_tokens_used_books_nothing():
    spawner = SubAgentSpawner()
    task = SubAgentTask(task_description="silent")
    result = spawner.spawn(task, executor=lambda _desc: {"result": "no usage field"})
    assert result.error == ""
    assert spawner.total_tokens_used == 0


def test_depth_limit_rejected():
    spawner = SubAgentSpawner(max_depth=2)
    assert spawner.can_spawn(SubAgentTask(task_description="x", depth=2)) is False


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
