"""Sub-agent spawner — recursive agent spawning with depth and budget limits.

Ось D п.5 из Развитие2.md: recursive sub-agent spawning with cycle detection.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_TOKENS = 50000


@dataclass
class SubAgentTask:
    task_description: str
    parent_id: str = ""
    depth: int = 0
    max_depth: int = DEFAULT_MAX_DEPTH
    token_budget: int = DEFAULT_MAX_TOKENS
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


@dataclass
class SubAgentResult:
    task_id: str
    session_id: str
    depth: int
    output: dict[str, Any] = field(default_factory=dict)
    sub_results: list[SubAgentResult] = field(default_factory=list)
    tokens_used: int = 0
    error: str = ""


class SubAgentSpawner:
    """Process-local recursive sub-agent spawner with depth and budget limits.

    NOTE: this is an in-memory helper for a single orchestration call. It is NOT
    the authoritative distributed budget/lease store — cross-worker budgeting is
    owned by the durable budget ledger. Token accounting here uses a
    reserve→settle discipline so concurrent spawns inside one process cannot
    collectively over-commit ``max_total_tokens``.
    """

    def __init__(self, max_depth: int = DEFAULT_MAX_DEPTH, max_total_tokens: int = 200000) -> None:
        self._max_depth = max_depth
        self._max_total_tokens = max_total_tokens
        self._total_tokens_used = 0
        self._reserved_tokens = 0
        self._active_sessions: set[str] = set()
        self._spawn_count = 0

    def can_spawn(self, task: SubAgentTask) -> bool:
        if task.depth >= self._max_depth:
            return False
        if task.session_id in self._active_sessions and task.depth > 0:
            return False
        # Reserve-aware: settled usage plus already-reserved budget plus this
        # task's budget must fit under the cap. This closes the
        # "checked-before, incremented-after" race where several spawns each
        # passed a stale ``total_tokens_used`` check and collectively overran.
        return (
            self._total_tokens_used + self._reserved_tokens + task.token_budget
            <= self._max_total_tokens
        )

    def _reserve(self, task: SubAgentTask) -> int:
        """Register the session and reserve this task's token budget."""
        self._active_sessions.add(task.session_id)
        self._spawn_count += 1
        remaining = self._max_total_tokens - self._total_tokens_used - self._reserved_tokens
        reserved = max(0, min(task.token_budget, remaining))
        self._reserved_tokens += reserved
        return reserved

    def _settle(self, task: SubAgentTask, reserved: int, output: dict[str, Any]) -> str:
        """Release the reservation, book actual usage, return any budget error.

        Always releases the reservation and the session (call from ``finally``).
        Actual ``tokens_used`` reported by the executor is booked as settled
        usage; a task that overshoots its own ``token_budget`` is flagged.
        """
        self._reserved_tokens = max(0, self._reserved_tokens - reserved)
        self._active_sessions.discard(task.session_id)
        error = ""
        if isinstance(output, dict) and "tokens_used" in output:
            try:
                used = int(output.get("tokens_used") or 0)
            except (TypeError, ValueError):
                used = 0
            if used > 0:
                self._total_tokens_used += used
                if used > task.token_budget:
                    error = f"budget_exceeded: used {used} > budget {task.token_budget}"
        return error

    def spawn(self, task: SubAgentTask, executor: Any = None) -> SubAgentResult:
        if not self.can_spawn(task):
            return SubAgentResult(
                task_id=uuid.uuid4().hex[:12],
                session_id=task.session_id,
                depth=task.depth,
                error="spawn_rejected: depth or budget limit",
            )
        task_id = uuid.uuid4().hex[:12]
        reserved = self._reserve(task)
        output: dict[str, Any] = {}
        exec_error = ""

        try:
            if executor is not None:
                result = executor(task.task_description)
                output = result if isinstance(result, dict) else {"result": str(result)}
        except Exception as exc:
            logger.warning("Sub-agent execution failed: %s", exc)
            exec_error = str(exc)
        finally:
            budget_error = self._settle(task, reserved, output)

        error = exec_error or budget_error
        return SubAgentResult(
            task_id=task_id, session_id=task.session_id,
            depth=task.depth,
            output={} if exec_error else output,
            error=error,
        )

    async def aspawn(self, task: SubAgentTask, executor: Callable | None = None) -> SubAgentResult:
        """Async spawn — supports async executor callables."""
        if not self.can_spawn(task):
            return SubAgentResult(
                task_id=uuid.uuid4().hex[:12],
                session_id=task.session_id,
                depth=task.depth,
                error="spawn_rejected: depth or budget limit",
            )
        task_id = uuid.uuid4().hex[:12]
        reserved = self._reserve(task)
        output: dict[str, Any] = {}
        exec_error = ""

        try:
            if executor is not None:
                result = executor(task.task_description)
                if asyncio.iscoroutine(result):
                    result = await result
                output = result if isinstance(result, dict) else {"result": str(result)}
        except Exception as exc:
            logger.warning("Sub-agent async execution failed: %s", exc)
            exec_error = str(exc)
        finally:
            budget_error = self._settle(task, reserved, output)

        error = exec_error or budget_error
        return SubAgentResult(
            task_id=task_id, session_id=task.session_id,
            depth=task.depth,
            output={} if exec_error else output,
            error=error,
        )

    @property
    def total_tokens_used(self) -> int:
        return self._total_tokens_used

    @property
    def reserved_tokens(self) -> int:
        return self._reserved_tokens

    @property
    def spawn_count(self) -> int:
        return self._spawn_count


__all__ = [
    "SubAgentSpawner",
    "SubAgentTask",
    "SubAgentResult",
]
