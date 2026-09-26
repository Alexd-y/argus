"""LocalExecutionBackend (port of upstream D-16) — opt-in, lab-only.

WARNING (mirrors upstream): local mode runs the agent's processes with the current
user's privileges and WITHOUT a sandbox. It is only constructible under
``execution_mode == "lab_unrestricted"`` AND ``settings.cairn_local_execution_enabled``;
any other case raises ``RuntimeError`` at construction (fail-closed).
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from src.cairn.runtime.backend import (
    CairnExecProcess,
    ProcessResult,
    assert_safe_workspace_path,
)
from src.core.config import settings


class _LocalProcess:
    """A single local subprocess with timeout + cancellation."""

    def __init__(
        self, cwd: Path, env: dict[str, str], command: list[str], kill_after: float
    ) -> None:
        self._cwd = cwd
        self._env = env
        self._command = command
        self._kill_after = kill_after
        self._proc: asyncio.subprocess.Process | None = None
        self._cancelled = False
        self._cancel_reason: str | None = None

    async def start(self) -> None:
        if self._cancelled:
            return
        self._proc = await asyncio.create_subprocess_exec(
            *self._command,
            cwd=str(self._cwd),
            env=self._env or None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def communicate(self, timeout: float | None) -> ProcessResult:
        if self._cancelled or self._proc is None:
            return ProcessResult(
                returncode=-1,
                stdout="",
                stderr="",
                cancelled=True,
                cancel_reason=self._cancel_reason,
            )
        try:
            stdout, stderr = await asyncio.wait_for(self._proc.communicate(), timeout=timeout)
        except TimeoutError:
            await self.kill()
            return ProcessResult(returncode=-1, stdout="", stderr="", timed_out=True)
        return ProcessResult(
            returncode=self._proc.returncode if self._proc.returncode is not None else -1,
            stdout=(stdout or b"").decode("utf-8", "replace"),
            stderr=(stderr or b"").decode("utf-8", "replace"),
        )

    async def kill(self) -> None:
        if self._proc is None or self._proc.returncode is not None:
            return
        self._proc.terminate()
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=self._kill_after)
        except TimeoutError:
            self._proc.kill()

    async def cancel(self, reason: str) -> None:
        self._cancelled = True
        self._cancel_reason = reason
        await self.kill()


class LocalExecutionBackend:
    """Runs processes as host subprocesses in a per-project workspace dir."""

    def __init__(self, *, execution_mode: str, workspace_root: Path | str | None = None) -> None:
        if execution_mode != "lab_unrestricted" or not getattr(
            settings, "cairn_local_execution_enabled", False
        ):
            raise RuntimeError(
                "LocalExecutionBackend requires execution_mode=lab_unrestricted and "
                "cairn_local_execution_enabled=true (fail-closed)"
            )
        self._root = Path(workspace_root or Path.home() / ".cache" / "cairn-local")
        self._root.mkdir(parents=True, exist_ok=True)

    def workspace_name(self, project_id: str) -> str:
        return f"cairn-{project_id}"

    def _workspace_dir(self, project_id: str) -> Path:
        return self._root / self.workspace_name(project_id)

    async def ensure_running(self, project_id: str) -> str:
        workspace = self._workspace_dir(project_id)
        workspace.mkdir(parents=True, exist_ok=True)
        return self.workspace_name(project_id)

    async def build_exec_process(
        self,
        workspace: str,
        env: dict[str, str],
        command: list[str],
        timeout_seconds: float | None = None,  # noqa: ARG002 - honored by communicate()
        kill_after_seconds: float = 5.0,
    ) -> CairnExecProcess:
        cwd = self._root / workspace
        cwd.mkdir(parents=True, exist_ok=True)
        return _LocalProcess(cwd, env, command, kill_after_seconds)

    async def write_text_file(self, workspace: str, path: str, content: str) -> None:
        safe = assert_safe_workspace_path(path)
        target = self._root / workspace / safe
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    async def needs_completed_cleanup(self, project_id: str) -> bool:
        return self._workspace_dir(project_id).exists()

    async def needs_stopped_cleanup(self, project_id: str) -> bool:
        return self._workspace_dir(project_id).exists()

    async def cleanup_completed(self, project_id: str) -> bool:
        return self._cleanup(project_id)

    async def cleanup_stopped(self, project_id: str) -> bool:
        return self._cleanup(project_id)

    def _cleanup(self, project_id: str) -> bool:
        workspace = self._workspace_dir(project_id)
        if workspace.exists():
            shutil.rmtree(workspace, ignore_errors=True)
            return True
        return False

    async def close(self) -> None:
        return None


__all__ = ["LocalExecutionBackend"]
