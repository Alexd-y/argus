"""Phase 7 — execution backends + environment brief."""

from __future__ import annotations

import sys

import pytest
from src.cairn.environment_brief import build_environment_brief
from src.cairn.runtime.backend import ProcessResult, assert_safe_workspace_path
from src.cairn.runtime.local_backend import LocalExecutionBackend
from src.cairn.runtime.sandbox_backend import SandboxExecutionBackend
from src.policy.scope import ScopeEngine, ScopeKind, ScopeRule

# --- path guard --------------------------------------------------------------


@pytest.mark.parametrize("bad", ["/etc/passwd", "../../etc/passwd", "a/../b", "C:/win"])
def test_unsafe_paths_rejected(bad: str) -> None:
    with pytest.raises(ValueError):
        assert_safe_workspace_path(bad)


def test_safe_path_accepted() -> None:
    assert assert_safe_workspace_path("notes/graph.yaml") == "notes/graph.yaml"


# --- environment brief -------------------------------------------------------


def test_environment_brief_contains_scope_mode_tools() -> None:
    scope = ScopeEngine([ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com")])
    brief = build_environment_brief(
        execution_mode="production", scope_engine=scope, allowed_tools=["nuclei", "ffuf"]
    ).render()
    assert "Execution mode: production" in brief
    assert "example.com" in brief
    assert "nuclei" in brief
    assert "tmux" in brief
    assert "Never act outside the allowed scope" in brief


# --- local backend gating ----------------------------------------------------


def test_local_backend_blocked_in_production() -> None:
    with pytest.raises(RuntimeError, match="lab_unrestricted"):
        LocalExecutionBackend(execution_mode="production")


async def test_local_backend_runs_and_writes(tmp_path, monkeypatch) -> None:
    from src.core.config import settings

    monkeypatch.setattr(settings, "cairn_local_execution_enabled", True, raising=False)
    backend = LocalExecutionBackend(execution_mode="lab_unrestricted", workspace_root=tmp_path)
    workspace = await backend.ensure_running("proj1")
    await backend.write_text_file(workspace, "notes/x.txt", "hi")
    assert (tmp_path / workspace / "notes" / "x.txt").read_text() == "hi"

    proc = await backend.build_exec_process(workspace, {}, [sys.executable, "-c", "print('hello')"])
    await proc.start()
    result = await proc.communicate(timeout=30)
    assert isinstance(result, ProcessResult)
    assert result.returncode == 0
    assert "hello" in result.stdout
    assert await backend.cleanup_completed("proj1") is True


# --- sandbox backend with a fake adapter -------------------------------------


class _FakeExecResult:
    def __init__(self, exit_code=0, stdout="", stderr="") -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class _FakeAdapter:
    def __init__(self) -> None:
        self.created: list[str] = []
        self.execs: list[list[str]] = []
        self.destroyed: list[str] = []
        self._owned: list[tuple[str, float]] = []

    async def list_owned(self, owner_labels):  # noqa: ARG002
        return list(self._owned)

    async def create(self, task_id, owner_labels):  # noqa: ARG002
        cid = f"c-{task_id}"
        self.created.append(cid)
        self._owned = [(cid, 0.0)]
        return cid

    async def exec(self, container_id, argv):  # noqa: ARG002
        self.execs.append(argv)
        return _FakeExecResult(exit_code=0, stdout="ok")

    async def destroy(self, container_id):
        self.destroyed.append(container_id)
        self._owned = []


async def test_sandbox_backend_ensure_running_is_idempotent() -> None:
    adapter = _FakeAdapter()
    backend = SandboxExecutionBackend(tenant_id="t1", adapter=adapter)
    w1 = await backend.ensure_running("p1")
    w2 = await backend.ensure_running("p1")
    assert w1 == w2 == "cairn-p1"  # ensure_running returns the workspace name
    assert adapter.created == ["c-p1"]  # container created only once


async def test_sandbox_backend_write_text_file_uses_base64_pipe() -> None:
    adapter = _FakeAdapter()
    backend = SandboxExecutionBackend(tenant_id="t1", adapter=adapter)
    ws = await backend.ensure_running("p1")
    await backend.write_text_file(ws, "notes/g.yaml", "content")
    assert any("base64 -d" in " ".join(argv) for argv in adapter.execs)


async def test_sandbox_backend_rejects_traversal_write() -> None:
    adapter = _FakeAdapter()
    backend = SandboxExecutionBackend(tenant_id="t1", adapter=adapter)
    ws = await backend.ensure_running("p1")
    with pytest.raises(ValueError):
        await backend.write_text_file(ws, "../escape", "x")


async def test_sandbox_backend_exec_and_teardown() -> None:
    adapter = _FakeAdapter()
    backend = SandboxExecutionBackend(tenant_id="t1", adapter=adapter)
    ws = await backend.ensure_running("p1")
    proc = await backend.build_exec_process(ws, {}, ["nuclei", "-u", "x"])
    await proc.start()
    result = await proc.communicate(timeout=None)
    assert result.returncode == 0 and result.stdout == "ok"
    assert await backend.cleanup_stopped("p1") is True
    assert adapter.destroyed == ["c-p1"]
