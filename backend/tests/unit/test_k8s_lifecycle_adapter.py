"""Offline tests for :class:`K8sLifecycleSandboxAdapter` (§8.2 K8s variant).

No Kubernetes cluster or SDK is required — a fake ``CoreV1Api`` and a fake exec
function are injected. The real cluster path is exercised under ``requires_kind``
in ``tests/integration/k8s/test_k8s_lifecycle_adapter.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from src.orchestration.sandbox_lifecycle import (
    SandboxCreateError,
    SandboxStatus,
    run_in_sandbox,
)
from src.sandbox.k8s_lifecycle_adapter import (
    K8sLifecycleSandboxAdapter,
    _age_seconds,
    _parse_exec_returncode,
    _sanitise_name,
    build_k8s_lifecycle_adapter,
)

_LABELS = {"argus.owner": "exploitation", "argus.tenant": "t1"}


class _FakeStatus:
    def __init__(self, phase: str) -> None:
        self.phase = phase


class _FakePod:
    def __init__(self, phase: str = "Running") -> None:
        self.status = _FakeStatus(phase)


class _FakeMeta:
    def __init__(self, name: str, ts: datetime | None) -> None:
        self.name = name
        self.creation_timestamp = ts


class _FakeListItem:
    def __init__(self, name: str, ts: datetime | None) -> None:
        self.metadata = _FakeMeta(name, ts)


class _FakeList:
    def __init__(self, items: list[_FakeListItem]) -> None:
        self.items = items


class _FakeCoreV1:
    def __init__(self, *, create_error: bool = False, phase: str = "Running", owned=None) -> None:
        self.created: list[dict] = []
        self.deleted: list[str] = []
        self._create_error = create_error
        self._phase = phase
        self._owned = owned or []

    def create_namespaced_pod(self, namespace, body):
        if self._create_error:
            raise RuntimeError("apiserver unreachable")
        self.created.append(body)

    def read_namespaced_pod(self, name, namespace):
        return _FakePod(self._phase)

    def delete_namespaced_pod(self, name, namespace, grace_period_seconds=0):
        self.deleted.append(name)

    def list_namespaced_pod(self, namespace, label_selector):
        return _FakeList(self._owned)


def _tool_exec_fn(_core, _pod, _ns, argv, _container):
    # Distinguish the collect_artifacts `find` probe from a real tool run.
    if argv and argv[0] == "find":
        return (
            0,
            "/workspace/artifacts/report.json\n/workspace/artifacts/nuclei.log\n",
            "",
        )
    return (0, "tool-ran", "")


def _make(core: _FakeCoreV1, **kw) -> K8sLifecycleSandboxAdapter:
    return K8sLifecycleSandboxAdapter(core_v1=core, exec_fn=_tool_exec_fn, **kw)


# --- helpers ---------------------------------------------------------------


def test_sanitise_name_is_dns1123_safe():
    name = _sanitise_name("Exploit_NUCLEI/#42")
    assert name.startswith("argus-sbx-")
    assert all(c.islower() or c.isdigit() or c == "-" for c in name)


def test_parse_exec_returncode_success_and_failure():
    assert _parse_exec_returncode('{"status": "Success"}') == 0
    assert _parse_exec_returncode("") == 0
    failure = '{"status":"Failure","details":{"causes":[{"reason":"ExitCode","message":"7"}]}}'
    assert _parse_exec_returncode(failure) == 7


def test_age_seconds_from_datetime():
    now = datetime.now(UTC)
    assert _age_seconds(now - timedelta(seconds=120), now) == pytest.approx(120, abs=2)
    assert _age_seconds(None, now) == 0.0


# --- lifecycle -------------------------------------------------------------


async def test_create_returns_pod_name_and_hardened_manifest():
    core = _FakeCoreV1()
    adapter = _make(core)
    name = await adapter.create("exploit-nuclei-abc", _LABELS)

    assert name.startswith("argus-sbx-")
    assert len(core.created) == 1
    spec = core.created[0]["spec"]
    assert spec["restartPolicy"] == "Never"
    assert spec["automountServiceAccountToken"] is False
    assert spec["securityContext"]["runAsNonRoot"] is True
    assert spec["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    csec = spec["containers"][0]["securityContext"]
    assert csec["allowPrivilegeEscalation"] is False
    assert csec["readOnlyRootFilesystem"] is True
    assert csec["privileged"] is False
    assert csec["capabilities"]["drop"] == ["ALL"]
    # No dangerous volumes.
    serialised = repr(core.created[0]).lower()
    assert "hostpath" not in serialised
    assert "docker.sock" not in serialised


async def test_create_failure_raises_and_attempts_cleanup():
    core = _FakeCoreV1(create_error=True)
    adapter = _make(core)
    with pytest.raises(SandboxCreateError):
        await adapter.create("t", _LABELS)


async def test_create_terminal_phase_raises():
    core = _FakeCoreV1(phase="Failed")
    adapter = _make(core, ready_timeout_seconds=1.0)
    with pytest.raises(SandboxCreateError):
        await adapter.create("t", _LABELS)


async def test_exec_maps_injected_result():
    core = _FakeCoreV1()
    adapter = _make(core)
    result = await adapter.exec("pod-1", ["nuclei", "-u", "http://t"])
    assert result.exit_code == 0
    assert result.stdout == "tool-ran"


async def test_collect_artifacts_parses_find_output():
    core = _FakeCoreV1()
    adapter = _make(core)
    keys = await adapter.collect_artifacts("pod-1", "exploitation/task")
    assert keys == ["exploitation/task/report.json", "exploitation/task/nuclei.log"]


async def test_collect_artifacts_empty_when_find_fails():
    core = _FakeCoreV1()
    adapter = K8sLifecycleSandboxAdapter(core_v1=core, exec_fn=lambda *_a: (1, "", "no such dir"))
    assert await adapter.collect_artifacts("pod-1", "p") == []


async def test_destroy_deletes_pod():
    core = _FakeCoreV1()
    adapter = _make(core)
    await adapter.destroy("pod-xyz")
    assert "pod-xyz" in core.deleted


async def test_list_owned_returns_name_and_age():
    now = datetime.now(UTC)
    owned = [
        _FakeListItem("argus-sbx-a", now - timedelta(seconds=30)),
        _FakeListItem("argus-sbx-b", now - timedelta(seconds=900)),
    ]
    core = _FakeCoreV1(owned=owned)
    adapter = _make(core)
    result = await adapter.list_owned(_LABELS)
    names = {n for n, _ in result}
    assert names == {"argus-sbx-a", "argus-sbx-b"}
    ages = dict(result)
    assert ages["argus-sbx-b"] > ages["argus-sbx-a"]


async def test_run_in_sandbox_success_end_to_end():
    core = _FakeCoreV1()
    adapter = _make(core)
    result = await run_in_sandbox(adapter, "task-xyz", ["id"], owner_labels=_LABELS)
    assert result.status == SandboxStatus.SUCCEEDED
    assert result.exit_code == 0
    assert result.stdout == "tool-ran"
    # Pod was torn down after the run.
    assert len(core.deleted) == 1


def test_build_factory_returns_adapter():
    assert isinstance(
        build_k8s_lifecycle_adapter(core_v1=_FakeCoreV1()), K8sLifecycleSandboxAdapter
    )


def test_empty_namespace_rejected():
    with pytest.raises(ValueError, match="namespace"):
        K8sLifecycleSandboxAdapter(namespace="", core_v1=_FakeCoreV1())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
