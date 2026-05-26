"""Sub-agent spawner — recursive agent spawning with depth and budget limits.

Ось D п.5 из Развитие2.md: recursive sub-agent spawning with cycle detection.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

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
    sub_results: list["SubAgentResult"] = field(default_factory=list)
    tokens_used: int = 0
    error: str = ""


class SubAgentSpawner:
    def __init__(self, max_depth: int = DEFAULT_MAX_DEPTH, max_total_tokens: int = 200000) -> None:
        self._max_depth = max_depth
        self._max_total_tokens = max_total_tokens
        self._total_tokens_used = 0
        self._active_sessions: set[str] = set()
        self._spawn_count = 0

    def can_spawn(self, task: SubAgentTask) -> bool:
        if task.depth >= self._max_depth:
            return False
        if task.session_id in self._active_sessions and task.depth > 0:
            return False
        if self._total_tokens_used >= self._max_total_tokens:
            return False
        return True

    def spawn(self, task: SubAgentTask, executor: Any = None) -> SubAgentResult:
        if not self.can_spawn(task):
            return SubAgentResult(
                task_id=uuid.uuid4().hex[:12],
                session_id=task.session_id,
                depth=task.depth,
                error="spawn_rejected: depth or budget limit",
            )
        self._active_sessions.add(task.session_id)
        self._spawn_count += 1
        task_id = uuid.uuid4().hex[:12]
        output = {}
        sub_results: list[SubAgentResult] = []

        if executor is not None:
            try:
                result = executor(task.task_description)
                output = result if isinstance(result, dict) else {"result": str(result)}
            except Exception as exc:
                logger.warning("Sub-agent execution failed: %s", exc)
                return SubAgentResult(
                    task_id=task_id, session_id=task.session_id,
                    depth=task.depth, error=str(exc),
                )
        self._active_sessions.discard(task.session_id)
        return SubAgentResult(
            task_id=task_id, session_id=task.session_id,
            depth=task.depth, output=output, sub_results=sub_results,
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
        self._active_sessions.add(task.session_id)
        self._spawn_count += 1
        task_id = uuid.uuid4().hex[:12]
        output = {}
        sub_results: list[SubAgentResult] = []

        if executor is not None:
            try:
                result = executor(task.task_description)
                if asyncio.iscoroutine(result):
                    result = await result
                output = result if isinstance(result, dict) else {"result": str(result)}
            except Exception as exc:
                logger.warning("Sub-agent async execution failed: %s", exc)
                return SubAgentResult(
                    task_id=task_id, session_id=task.session_id,
                    depth=task.depth, error=str(exc),
                )
        self._active_sessions.discard(task.session_id)
        return SubAgentResult(
            task_id=task_id, session_id=task.session_id,
            depth=task.depth, output=output, sub_results=sub_results,
        )

    @property
    def total_tokens_used(self) -> int:
        return self._total_tokens_used

    @property
    def spawn_count(self) -> int:
        return self._spawn_count


__all__ = [
    "SubAgentSpawner",
    "SubAgentTask",
    "SubAgentResult",
]