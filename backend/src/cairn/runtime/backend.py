"""Execution backend Protocol (upstream D-17).

A single Protocol lets the dispatcher treat the hardened sandbox container and the
opt-in local process backend interchangeably. Implementations:

* :class:`~src.cairn.runtime.sandbox_backend.SandboxExecutionBackend` — the default;
  one hardened long-lived container per project via the existing
  ``DockerLifecycleSandboxAdapter`` (read-only, cap_drop ALL, no host network).
* :class:`~src.cairn.runtime.local_backend.LocalExecutionBackend` — opt-in, only
  under ``lab_unrestricted`` + ``cairn_local_execution_enabled``; runs host
  processes WITHOUT a sandbox.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(slots=True)
class ProcessResult:
    """Outcome of a single process execution."""

    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    cancelled: bool = False
    cancel_reason: str | None = None


@runtime_checkable
class CairnExecProcess(Protocol):
    """A single, cancellable process run inside a backend."""

    async def start(self) -> None: ...

    async def communicate(self, timeout: float | None) -> ProcessResult: ...

    async def kill(self) -> None: ...

    async def cancel(self, reason: str) -> None: ...


@runtime_checkable
class CairnExecutionBackend(Protocol):
    """Backend that owns one workspace per project and runs processes in it."""

    def workspace_name(self, project_id: str) -> str: ...

    async def ensure_running(self, project_id: str) -> str: ...

    async def build_exec_process(
        self,
        workspace: str,
        env: dict[str, str],
        command: list[str],
        timeout_seconds: float | None = None,
        kill_after_seconds: float = 5.0,
    ) -> CairnExecProcess: ...

    async def write_text_file(self, workspace: str, path: str, content: str) -> None: ...

    async def needs_completed_cleanup(self, project_id: str) -> bool: ...

    async def needs_stopped_cleanup(self, project_id: str) -> bool: ...

    async def cleanup_completed(self, project_id: str) -> bool: ...

    async def cleanup_stopped(self, project_id: str) -> bool: ...

    async def close(self) -> None: ...


def assert_safe_workspace_path(path: str) -> str:
    """Reject absolute paths and ``..`` traversal for in-workspace writes.

    Ported from the upstream ``ContainerManager._text_file_archive`` guard: the
    path must be relative and must not escape the workspace via ``.``/``..``.
    """
    normalized = path.strip()
    if not normalized:
        raise ValueError("empty path")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        raise ValueError(f"absolute path not allowed: {path!r}")
    parts = normalized.replace("\\", "/").split("/")
    if any(part in (".", "..") for part in parts):
        raise ValueError(f"path traversal not allowed: {path!r}")
    return normalized


__all__ = [
    "CairnExecProcess",
    "CairnExecutionBackend",
    "ProcessResult",
    "assert_safe_workspace_path",
]
