"""Offline tests for :class:`DockerLifecycleSandboxAdapter` (§8.2).

Uses a fake Docker client (no daemon) to verify the hardened create flags,
create-failure fail-closed behaviour, exec demux handling, artifact extraction,
owner-scoped listing, and end-to-end integration through the lifecycle wrapper.
Real Docker behaviour is covered under ``requires_docker``.
"""

from __future__ import annotations

import io
import tarfile

import pytest
from src.orchestration.sandbox_lifecycle import SandboxCreateError, SandboxStatus, run_in_sandbox
from src.sandbox.docker_sandbox_adapter import DockerLifecycleSandboxAdapter


class _FakeExecResult:
    def __init__(self, exit_code, output):
        self.exit_code = exit_code
        self.output = output


class _FakeContainer:
    def __init__(self, cid, *, created="2026-01-01T00:00:00.000000000Z", archive=None):
        self.id = cid
        self.attrs = {"Created": created}
        self._archive = archive
        self.stopped = False
        self.removed = False

    def exec_run(self, argv, demux=True):
        return _FakeExecResult(0, (b"stdout-" + argv[0].encode(), b""))

    def get_archive(self, path):
        if self._archive is None:
            raise RuntimeError(f"no such path: {path}")
        return iter([self._archive]), {"name": "artifacts"}

    def stop(self, timeout=10):
        self.stopped = True

    def remove(self, force=True):
        self.removed = True


class _FakeContainers:
    def __init__(self, *, run_error=False, archive=None, owned=None):
        self.run_error = run_error
        self.archive = archive
        self._by_id: dict[str, _FakeContainer] = {}
        self.run_kwargs: dict | None = None
        self.list_filters: dict | None = None
        self._owned = owned or []

    def run(self, image, **kwargs):
        if self.run_error:
            raise RuntimeError("docker daemon unreachable")
        self.run_kwargs = {"image": image, **kwargs}
        container = _FakeContainer("c-real-123", archive=self.archive)
        self._by_id[container.id] = container
        return container

    def get(self, cid):
        return self._by_id.get(cid) or _FakeContainer(cid, archive=self.archive)

    def list(self, all, filters):  # noqa: A002 — mirror docker-py signature
        self.list_filters = filters
        return list(self._owned)


class _FakeClient:
    def __init__(self, **kwargs):
        self.containers = _FakeContainers(**kwargs)


def _tar_bytes(name: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=name)
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


_LABELS = {"argus.owner": "argus", "argus.tenant": "t1"}


async def test_create_returns_real_id_with_hardening_flags():
    client = _FakeClient()
    adapter = DockerLifecycleSandboxAdapter(client=client, image="argus-sandbox")
    cid = await adapter.create("task-abc", _LABELS)
    assert cid == "c-real-123"
    kw = client.containers.run_kwargs
    assert kw["image"] == "argus-sandbox"
    assert kw["read_only"] is True
    assert kw["cap_drop"] == ["ALL"]
    assert kw["security_opt"] == ["no-new-privileges"]
    assert kw["user"] == "1000:1000"
    assert kw["detach"] is True
    assert "/workspace" in kw["tmpfs"]
    assert kw["labels"]["argus.task"] == "task-abc"
    assert kw["labels"]["argus.owner"] == "argus"


async def test_create_failure_raises_sandbox_create_error():
    adapter = DockerLifecycleSandboxAdapter(client=_FakeClient(run_error=True))
    with pytest.raises(SandboxCreateError):
        await adapter.create("task-abc", _LABELS)


async def test_exec_returns_exit_code_and_streams():
    adapter = DockerLifecycleSandboxAdapter(client=_FakeClient())
    cid = await adapter.create("t", _LABELS)
    result = await adapter.exec(cid, ["echo", "hi"])
    assert result.exit_code == 0
    assert result.stdout == "stdout-echo"
    assert result.stderr == ""


async def test_collect_artifacts_absent_dir_returns_empty():
    adapter = DockerLifecycleSandboxAdapter(client=_FakeClient(archive=None))
    cid = await adapter.create("t", _LABELS)
    assert await adapter.collect_artifacts(cid, "s1/exploit/t") == []


async def test_collect_artifacts_returns_keys_for_files():
    archive = _tar_bytes("artifacts/poc.json", b"{}")
    adapter = DockerLifecycleSandboxAdapter(client=_FakeClient(archive=archive))
    cid = await adapter.create("t", _LABELS)
    keys = await adapter.collect_artifacts(cid, "s1/exploit/t")
    assert keys == ["s1/exploit/t/poc.json"]


async def test_destroy_stops_and_removes():
    client = _FakeClient()
    adapter = DockerLifecycleSandboxAdapter(client=client)
    cid = await adapter.create("t", _LABELS)
    await adapter.destroy(cid)
    container = client.containers._by_id[cid]
    assert container.stopped is True
    assert container.removed is True


async def test_list_owned_filters_by_label_and_reports_age():
    owned = [_FakeContainer("old", created="2000-01-01T00:00:00.000000Z")]
    adapter = DockerLifecycleSandboxAdapter(client=_FakeClient(owned=owned))
    result = await adapter.list_owned(_LABELS)
    assert len(result) == 1
    cid, age = result[0]
    assert cid == "old"
    assert age > 0  # far in the past → large positive age


async def test_lifecycle_wrapper_runs_and_cleans_up():
    archive = _tar_bytes("artifacts/out.json", b"[]")
    adapter = DockerLifecycleSandboxAdapter(client=_FakeClient(archive=archive))
    result = await run_in_sandbox(adapter, "task-xyz", ["id"], owner_labels=_LABELS)
    assert result.status == SandboxStatus.SUCCEEDED
    assert result.exit_code == 0
    assert result.artifacts == ["task-xyz/out.json"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
