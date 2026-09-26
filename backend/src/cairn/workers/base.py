"""Worker driver contract (async port of upstream ``workers/base.py``).

A driver turns a rendered prompt into a task execution and its response text. Two
families exist:

* **In-process** (``WrbAgentDriver``): runs a ``ReActAgent`` and returns the answer
  text directly (``DriverResult.text``); ``session`` is the ReAct trace id.
* **CLI** (claude/codex/pi, opt-in): build an ``argv`` (``DriverResult.argv``) that
  the execution backend runs in the sandbox; response text is parsed from stdout.

Upstream ``--dangerously-*`` flags are NOT ported (hard rule #1). CLI drivers are
gated to ``lab_unrestricted`` + ``cairn_cli_drivers_enabled`` by the registry.
"""

from __future__ import annotations

import abc
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from src.cairn.workers.health import HealthResult


@dataclass(slots=True)
class CairnWorkerConfig:
    """Lightweight worker config (full DB-backed config arrives in Phase 10)."""

    name: str
    type_name: str
    env: dict[str, str] = field(default_factory=dict)
    model: str | None = None
    max_running: int = 1
    priority: int = 100
    task_types: tuple[str, ...] = ("bootstrap", "reason", "explore")


@dataclass(slots=True)
class CairnTaskContext:
    """Per-task context handed to a driver's execute/conclude."""

    tenant_id: str
    project_id: str
    task_type: str
    execution_mode: str = "production"
    scan_id: str | None = None
    intent_id: str | None = None
    max_iterations: int = 10
    confidence_threshold: float = 0.85
    # Injected dependencies (WRB driver): an async llm caller and a tool executor.
    llm_caller: Any = None
    tool_executor: Any = None
    worker: CairnWorkerConfig | None = None


@dataclass(slots=True)
class DriverResult:
    """Outcome of a driver execute/conclude call.

    ``argv`` is set by CLI drivers (run by the execution backend); ``text`` is set
    by in-process drivers (already the model's answer). ``session`` carries the
    driver's session/trace id for the conclude fallback in the same session.
    """

    argv: list[str] | None = None
    session: str | None = None
    text: str | None = None
    # ReAct trace (WRB driver) so the task run can persist it and restore for conclude.
    trace: list[dict[str, Any]] | None = None
    evidence_backed: bool = False


class CairnWorkerDriver(abc.ABC):
    """Abstract async worker driver."""

    type_name: str

    def supports_conclude(self) -> bool:
        return True

    def local_binary(self) -> str | None:
        return None

    async def prepare_session(self) -> str | None:
        return None

    @abc.abstractmethod
    async def check_health(self, worker: CairnWorkerConfig, *, timeout: float) -> HealthResult:
        raise NotImplementedError

    def describe_health(self, _worker: CairnWorkerConfig) -> str:
        return "in-process API ping"

    @abc.abstractmethod
    async def execute(
        self, ctx: CairnTaskContext, prompt: str, session: str | None
    ) -> DriverResult:
        raise NotImplementedError

    @abc.abstractmethod
    async def conclude(self, ctx: CairnTaskContext, prompt: str, session: str) -> DriverResult:
        raise NotImplementedError

    def extract_session(self, session: str | None, _stdout: str, _stderr: str) -> str | None:
        return session

    def extract_response_text(self, stdout: str, _stderr: str) -> str:
        return stdout


class SeedSessionDriver(CairnWorkerDriver):
    """Driver whose session id is a client-generated UUID (claude-style)."""

    async def prepare_session(self) -> str | None:
        return str(uuid.uuid4())


class RegexSessionDriver(CairnWorkerDriver):
    """Driver that recovers a session id from stderr (codex-style)."""

    session_pattern = re.compile(r"session id:\s*([0-9a-fA-F-]+)")

    def extract_session(self, session: str | None, _stdout: str, stderr: str) -> str | None:
        if session:
            return session
        match = self.session_pattern.search(stderr)
        return match.group(1) if match else None


__all__ = [
    "CairnTaskContext",
    "CairnWorkerConfig",
    "CairnWorkerDriver",
    "DriverResult",
    "RegexSessionDriver",
    "SeedSessionDriver",
]
