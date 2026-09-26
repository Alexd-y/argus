"""SandboxExecutionBackend — hardened container backend (port of upstream D-15).

One long-lived, hardened container per project via the existing
``DockerLifecycleSandboxAdapter`` (read-only rootfs, cap_drop ALL,
no-new-privileges, mem/cpu/pids limits, tmpfs workspace, dedicated network — NOT
``host``). We do not write a new Docker client; the adapter owns all container ops.

``write_text_file`` uses a base64 pipe through ``exec`` (the adapter exposes no
put_archive), with the target path validated to stay inside ``/workspace``.
"""

from __future__ import annotations

import asyncio
import base64

from src.cairn.runtime.backend import (
    CairnExecProcess,
    ProcessResult,
    assert_safe_workspace_path,
)
from src.sandbox.docker_sandbox_adapter import (
    DockerLifecycleSandboxAdapter,
    build_docker_lifecycle_adapter,
)

_WORKSPACE = "/workspace"


class _SandboxProcess:
    """Deferred ``exec`` in the project container, shaped as an ExecProcess."""

    def __init__(
        self, adapter: DockerLifecycleSandboxAdapter, container_id: str, argv: list[str]
    ) -> None:
        self._adapter = adapter
        self._container_id = container_id
        self._argv = argv
        self._cancelled = False
        self._cancel_reason: str | None = None

    async def start(self) -> None:
        return None

    async def communicate(self, timeout: float | None) -> ProcessResult:
        if self._cancelled:
            return ProcessResult(
                returncode=-1,
                stdout="",
                stderr="",
                cancelled=True,
                cancel_reason=self._cancel_reason,
            )
        try:
            coro = self._adapter.exec(self._container_id, self._argv)
            result = await (asyncio.wait_for(coro, timeout=timeout) if timeout else coro)
        except TimeoutError:
            return ProcessResult(returncode=-1, stdout="", stderr="", timed_out=True)
        return ProcessResult(
            returncode=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    async def kill(self) -> None:
        # A docker exec cannot be signalled individually here; container teardown
        # (cleanup_*) is the kill path. Best-effort no-op.
        return None

    async def cancel(self, reason: str) -> None:
        self._cancelled = True
        self._cancel_reason = reason


class SandboxExecutionBackend:
    """Per-project hardened container backend."""

    def __init__(
        self,
        *,
        tenant_id: str,
        adapter: DockerLifecycleSandboxAdapter | None = None,
        network: str | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        # Dedicated network (or the adapter default) — never host networking.
        self._adapter = adapter or build_docker_lifecycle_adapter(network=network)
        self._containers: dict[str, str] = {}
        self._lock = asyncio.Lock()

    def _owner_labels(self, project_id: str) -> dict[str, str]:
        return {"argus.cairn.project": project_id, "argus.tenant": self._tenant_id}

    def workspace_name(self, project_id: str) -> str:
        return f"cairn-{project_id}"

    async def ensure_running(self, project_id: str) -> str:
        async with self._lock:
            if project_id not in self._containers:
                owned = await self._adapter.list_owned(self._owner_labels(project_id))
                if owned:
                    container_id = owned[0][0]
                else:
                    container_id = await self._adapter.create(
                        project_id, self._owner_labels(project_id)
                    )
                self._containers[project_id] = container_id
            return self.workspace_name(project_id)

    async def build_exec_process(
        self,
        workspace: str,  # noqa: ARG002 - container id resolved via ensure_running mapping
        env: dict[str, str],
        command: list[str],
        timeout_seconds: float | None = None,  # noqa: ARG002 - honored by communicate()
        kill_after_seconds: float = 5.0,  # noqa: ARG002 - container teardown is the kill path
    ) -> CairnExecProcess:
        container_id = self._require_container(workspace)
        argv = command
        if env:
            # Prefix env assignments via ``env`` so the adapter argv stays a list.
            argv = ["env", *[f"{k}={v}" for k, v in env.items()], *command]
        return _SandboxProcess(self._adapter, container_id, argv)

    async def write_text_file(self, workspace: str, path: str, content: str) -> None:
        container_id = self._require_container(workspace)
        safe = assert_safe_workspace_path(path)
        target = f"{_WORKSPACE}/{safe}"
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        directory = target.rsplit("/", 1)[0]
        script = f"mkdir -p '{directory}' && printf '%s' '{encoded}' | base64 -d > '{target}'"
        result = await self._adapter.exec(container_id, ["sh", "-c", script])
        if result.exit_code != 0:
            raise RuntimeError(f"write_text_file failed: {result.stderr[:200]}")

    def _require_container(self, workspace: str) -> str:
        # workspace_name is cairn-<project_id>; map back to the running container.
        project_id = workspace.removeprefix("cairn-")
        container_id = self._containers.get(project_id)
        if not container_id:
            raise RuntimeError(f"container for project {project_id!r} is not running")
        return container_id

    async def needs_completed_cleanup(self, project_id: str) -> bool:
        return bool(await self._adapter.list_owned(self._owner_labels(project_id)))

    async def needs_stopped_cleanup(self, project_id: str) -> bool:
        return bool(await self._adapter.list_owned(self._owner_labels(project_id)))

    async def cleanup_completed(self, project_id: str) -> bool:
        return await self._teardown(project_id)

    async def cleanup_stopped(self, project_id: str) -> bool:
        return await self._teardown(project_id)

    async def _teardown(self, project_id: str) -> bool:
        owned = await self._adapter.list_owned(self._owner_labels(project_id))
        for container_id, _ts in owned:
            await self._adapter.destroy(container_id)
        self._containers.pop(project_id, None)
        return bool(owned)

    async def close(self) -> None:
        return None


__all__ = ["SandboxExecutionBackend"]
