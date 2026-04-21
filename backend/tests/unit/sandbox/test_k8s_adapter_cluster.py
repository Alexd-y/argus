"""Cluster-mode unit tests for :class:`KubernetesSandboxAdapter`.

The real ``kubernetes`` Python SDK is *not* required: each test injects a
hand-written fake ``kubernetes.client`` / ``kubernetes.config`` /
``kubernetes.watch`` module into ``sys.modules`` and then exercises the
adapter's CLUSTER-mode code paths through the public :meth:`run` /
:meth:`build_*` API.

This complements :mod:`tests.unit.sandbox.test_k8s_adapter`, which focuses on
DRY_RUN behaviour and pure-helper invariants. Together they push
``src.sandbox.k8s_adapter`` past the 90 %-coverage threshold without ever
touching a live cluster.
"""

from __future__ import annotations

import asyncio
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest

from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel, TargetKind, TargetSpec, ToolJob
from src.sandbox.adapter_base import (
    NetworkPolicyRef,
    ParseStrategy,
    ToolCategory,
    ToolDescriptor,
)
from src.sandbox.k8s_adapter import (
    FAILURE_REASONS,
    KubernetesSandboxAdapter,
    SandboxClusterError,
    SandboxConfigError,
    SandboxRunMode,
)


# ---------------------------------------------------------------------------
# Minimal in-process fake of the kubernetes Python SDK.
# ---------------------------------------------------------------------------


class _FakeApiException(Exception):
    """Mirror ``kubernetes.client.exceptions.ApiException``.

    The real ``kubernetes.client.exceptions.ApiException`` carries an HTTP
    ``body`` (and headers) that are echoed by ``str(exc)``. We mirror that
    surface so MED-2 tests can prove the closed-taxonomy never leaks the
    body / status / reason into ``SandboxRunResult.failure_reason``.
    """

    def __init__(
        self, *, status: int, reason: str = "fake", body: str | None = None
    ) -> None:
        rendered = f"ApiException(status={status}, reason={reason!r}"
        if body is not None:
            rendered += f", body={body!r}"
        rendered += ")"
        super().__init__(rendered)
        self.status = status
        self.reason = reason
        self.body = body


class _FakeConfigException(Exception):
    """Mirror ``kubernetes.config.ConfigException``."""


class _FakeContainerStatus:
    def __init__(self, exit_code: int, *, terminated_reason: str | None = None) -> None:
        terminated_attrs: dict[str, Any] = {"exit_code": exit_code}
        if terminated_reason is not None:
            terminated_attrs["reason"] = terminated_reason
        terminated = type("T", (), terminated_attrs)
        state = type("S", (), {"terminated": terminated})
        self.state = state


class _FakePodStatus:
    def __init__(
        self, exit_code: int | None, *, terminated_reason: str | None = None
    ) -> None:
        if exit_code is None and terminated_reason is None:
            self.container_statuses: list[_FakeContainerStatus] = []
        else:
            self.container_statuses = [
                _FakeContainerStatus(
                    exit_code if exit_code is not None else 0,
                    terminated_reason=terminated_reason,
                )
            ]


class _FakePodMetadata:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakePod:
    def __init__(
        self,
        name: str,
        exit_code: int | None,
        *,
        terminated_reason: str | None = None,
    ) -> None:
        self.metadata = _FakePodMetadata(name)
        self.status = _FakePodStatus(exit_code, terminated_reason=terminated_reason)


class _FakePodList:
    def __init__(self, items: list[_FakePod]) -> None:
        self.items = items


class _FakeJobStatus:
    def __init__(
        self,
        *,
        succeeded: int | None = None,
        failed: int | None = None,
        conditions: list[Any] | None = None,
    ) -> None:
        self.succeeded = succeeded
        self.failed = failed
        self.conditions = conditions


class _FakeJob:
    def __init__(self, status: _FakeJobStatus) -> None:
        self.status = status


class _FakeBatchV1Api:
    """Stub of ``kubernetes.client.BatchV1Api``.

    ``_status_sequence`` is consumed FIFO by ``read_namespaced_job_status`` so
    a test can pin the polling loop to "still running … then succeeded" or
    "still running … then failed" sequences.
    """

    create_calls: list[dict[str, Any]] = []
    create_should_raise: _FakeApiException | None = None
    status_sequence: list[_FakeJob] = []
    status_should_raise: _FakeApiException | None = None

    @classmethod
    def reset(cls) -> None:
        cls.create_calls = []
        cls.create_should_raise = None
        cls.status_sequence = []
        cls.status_should_raise = None

    def create_namespaced_job(
        self, *, namespace: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        if self.create_should_raise is not None:
            raise self.create_should_raise
        self.create_calls.append({"namespace": namespace, "body": body})
        return body

    def read_namespaced_job_status(self, *, name: str, namespace: str) -> _FakeJob:
        del name, namespace  # retained for API symmetry
        if self.status_should_raise is not None:
            raise self.status_should_raise
        if not self.status_sequence:
            return _FakeJob(_FakeJobStatus())
        if len(self.status_sequence) > 1:
            return self.status_sequence.pop(0)
        return self.status_sequence[0]


class _FakeNetworkingV1Api:
    """Stub of ``kubernetes.client.NetworkingV1Api``."""

    delete_calls: list[dict[str, Any]] = []
    create_calls: list[dict[str, Any]] = []
    delete_status: int | None = None
    create_should_raise: _FakeApiException | None = None

    @classmethod
    def reset(cls) -> None:
        cls.delete_calls = []
        cls.create_calls = []
        cls.delete_status = None
        cls.create_should_raise = None

    def delete_namespaced_network_policy(
        self, *, name: str, namespace: str, grace_period_seconds: int
    ) -> None:
        self.delete_calls.append(
            {"name": name, "namespace": namespace, "grace": grace_period_seconds}
        )
        if self.delete_status is not None:
            raise _FakeApiException(status=self.delete_status)

    def create_namespaced_network_policy(
        self, *, namespace: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        if self.create_should_raise is not None:
            raise self.create_should_raise
        self.create_calls.append({"namespace": namespace, "body": body})
        return body


class _FakeCoreV1Api:
    """Stub of ``kubernetes.client.CoreV1Api``."""

    pods: list[_FakePod] = []
    pod_list_should_raise: Exception | None = None
    log_should_raise: Exception | None = None
    log_text: str = ""

    @classmethod
    def reset(cls) -> None:
        cls.pods = []
        cls.pod_list_should_raise = None
        cls.log_should_raise = None
        cls.log_text = ""

    def list_namespaced_pod(
        self, *, namespace: str, label_selector: str
    ) -> _FakePodList:
        del namespace, label_selector
        if self.pod_list_should_raise is not None:
            raise self.pod_list_should_raise
        return _FakePodList(list(self.pods))

    def read_namespaced_pod_log(
        self,
        *,
        name: str,
        namespace: str,
        limit_bytes: int,
        tail_lines: int,
    ) -> str:
        del name, namespace, limit_bytes, tail_lines
        if self.log_should_raise is not None:
            raise self.log_should_raise
        return self.log_text


def _make_fake_kubernetes(
    *,
    raise_on_load_kube_config: bool = False,
    raise_on_incluster_config: bool = False,
) -> dict[str, ModuleType]:
    """Build the trio of fake kubernetes modules.

    Returns a dict the test can directly stash into ``sys.modules`` so the
    adapter's lazy ``importlib.import_module`` calls succeed.
    """
    client_mod = ModuleType("kubernetes.client")
    client_mod.BatchV1Api = _FakeBatchV1Api  # type: ignore[attr-defined]
    client_mod.NetworkingV1Api = _FakeNetworkingV1Api  # type: ignore[attr-defined]
    client_mod.CoreV1Api = _FakeCoreV1Api  # type: ignore[attr-defined]
    exceptions_mod = ModuleType("kubernetes.client.exceptions")
    exceptions_mod.ApiException = _FakeApiException  # type: ignore[attr-defined]
    client_mod.exceptions = exceptions_mod  # type: ignore[attr-defined]

    config_mod = ModuleType("kubernetes.config")
    config_mod.ConfigException = _FakeConfigException  # type: ignore[attr-defined]

    def _load_kube_config(*_args: Any, **_kwargs: Any) -> None:
        if raise_on_load_kube_config:
            raise RuntimeError("forced load_kube_config failure")

    def _load_incluster_config(*_args: Any, **_kwargs: Any) -> None:
        if raise_on_incluster_config:
            raise _FakeConfigException("forced incluster failure")

    config_mod.load_kube_config = _load_kube_config  # type: ignore[attr-defined]
    config_mod.load_incluster_config = _load_incluster_config  # type: ignore[attr-defined]

    watch_mod = ModuleType("kubernetes.watch")

    return {"client": client_mod, "config": config_mod, "watch": watch_mod}


@pytest.fixture()
def fake_kube_modules() -> Iterator[dict[str, ModuleType]]:
    """Inject a fake kubernetes SDK into ``sys.modules`` for the test's lifetime."""
    _FakeBatchV1Api.reset()
    _FakeNetworkingV1Api.reset()
    _FakeCoreV1Api.reset()
    modules = _make_fake_kubernetes()
    saved = {
        "kubernetes": sys.modules.pop("kubernetes", None),
        "kubernetes.client": sys.modules.pop("kubernetes.client", None),
        "kubernetes.config": sys.modules.pop("kubernetes.config", None),
        "kubernetes.watch": sys.modules.pop("kubernetes.watch", None),
    }
    sys.modules["kubernetes.client"] = modules["client"]
    sys.modules["kubernetes.config"] = modules["config"]
    sys.modules["kubernetes.watch"] = modules["watch"]
    try:
        yield modules
    finally:
        for name in (
            "kubernetes",
            "kubernetes.client",
            "kubernetes.config",
            "kubernetes.watch",
        ):
            sys.modules.pop(name, None)
            if saved.get(name) is not None:
                sys.modules[name] = saved[name]  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class _FakeRegistry:
    def __init__(self, descriptors: list[ToolDescriptor]) -> None:
        self._by_id: dict[str, ToolDescriptor] = {d.tool_id: d for d in descriptors}

    def get(self, tool_id: str) -> ToolDescriptor | None:
        return self._by_id.get(tool_id)


@pytest.fixture()
def passive_descriptor() -> ToolDescriptor:
    return ToolDescriptor(
        tool_id="crt_sh",
        category=ToolCategory.RECON,
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.PASSIVE,
        requires_approval=False,
        network_policy=NetworkPolicyRef(
            name="recon-passive",
            egress_allowlist=["0.0.0.0/0"],
            dns_resolvers=["1.1.1.1"],
        ),
        seccomp_profile="profiles/recon-default.json",
        default_timeout_s=60,
        cpu_limit="500m",
        memory_limit="256Mi",
        pids_limit=256,
        image="argus/crt_sh:1.0",
        command_template=["crt_sh", "{domain}"],
        parse_strategy=ParseStrategy.JSON_LINES,
        evidence_artifacts=["crt.json"],
        cwe_hints=[],
        owasp_wstg=[],
    )


@pytest.fixture()
def passive_job() -> ToolJob:
    return ToolJob(
        id=UUID("00000000-0000-0000-0000-000000000010"),
        tenant_id=uuid4(),
        scan_id=UUID("11111111-2222-3333-4444-555555555555"),
        tool_id="crt_sh",
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.PASSIVE,
        target=TargetSpec(kind=TargetKind.DOMAIN, domain="example.com"),
        parameters={"domain": "example.com"},
        outputs_dir="/out",
        timeout_s=15,
        correlation_id="argus-cluster-test",
    )


@pytest.fixture()
def cluster_adapter(
    tmp_path: Path, passive_descriptor: ToolDescriptor
) -> KubernetesSandboxAdapter:
    """CLUSTER-mode adapter with a tiny default deadline so polls stay quick."""
    registry = _FakeRegistry([passive_descriptor])
    return KubernetesSandboxAdapter(
        registry,  # type: ignore[arg-type]
        mode=SandboxRunMode.CLUSTER,
        namespace="argus-sandbox",
        dry_run_artifact_dir=tmp_path,
        default_pod_timeout_s=2,
    )


# ---------------------------------------------------------------------------
# Constructor / property surface
# ---------------------------------------------------------------------------


def test_invalid_mode_type_raises(
    tmp_path: Path, passive_descriptor: ToolDescriptor
) -> None:
    registry = _FakeRegistry([passive_descriptor])
    with pytest.raises(SandboxConfigError, match="mode must be"):
        KubernetesSandboxAdapter(
            registry,  # type: ignore[arg-type]
            mode="dry_run",  # type: ignore[arg-type]
            dry_run_artifact_dir=tmp_path,
        )


def test_property_accessors_reflect_init(
    cluster_adapter: KubernetesSandboxAdapter,
) -> None:
    assert cluster_adapter.mode is SandboxRunMode.CLUSTER
    assert cluster_adapter.namespace == "argus-sandbox"
    assert cluster_adapter.default_pod_timeout_s == 2


# ---------------------------------------------------------------------------
# Pure helpers — fill the remaining branches.
# ---------------------------------------------------------------------------


def test_derive_target_cidr_returns_none_for_non_ip_targets(
    cluster_adapter: KubernetesSandboxAdapter, passive_job: ToolJob
) -> None:
    cidr = cluster_adapter._derive_target_cidr(passive_job)  # type: ignore[attr-defined]
    assert cidr is None


def test_derive_target_cidr_handles_ipv6(
    cluster_adapter: KubernetesSandboxAdapter,
) -> None:
    job = ToolJob(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        tool_id="crt_sh",
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.PASSIVE,
        target=TargetSpec(kind=TargetKind.IP, ip="2001:db8::1"),
        parameters={"domain": "example.com"},
        outputs_dir="/out",
        timeout_s=10,
        correlation_id="argus-cluster-ipv6",
    )
    assert cluster_adapter._derive_target_cidr(job) == "2001:db8::1/128"  # type: ignore[attr-defined]


def test_derive_target_cidr_uses_cidr_target_verbatim(
    cluster_adapter: KubernetesSandboxAdapter,
) -> None:
    job = ToolJob(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        tool_id="crt_sh",
        phase=ScanPhase.RECON,
        risk_level=RiskLevel.PASSIVE,
        target=TargetSpec(kind=TargetKind.CIDR, cidr="10.0.0.0/8"),
        parameters={"domain": "example.com"},
        outputs_dir="/out",
        timeout_s=10,
        correlation_id="argus-cluster-cidr",
    )
    assert cluster_adapter._derive_target_cidr(job) == "10.0.0.0/8"  # type: ignore[attr-defined]


def test_assert_no_dangerous_volumes_rejects_hostpath(
    cluster_adapter: KubernetesSandboxAdapter,
) -> None:
    bad = {
        "spec": {
            "template": {
                "spec": {
                    "volumes": [{"name": "host", "hostPath": {"path": "/etc"}}],
                    "containers": [],
                }
            }
        }
    }
    with pytest.raises(SandboxConfigError, match="hostPath"):
        cluster_adapter._assert_no_dangerous_volumes(bad)  # type: ignore[attr-defined]


def test_assert_no_dangerous_volumes_rejects_docker_sock_mount(
    cluster_adapter: KubernetesSandboxAdapter,
) -> None:
    bad = {
        "spec": {
            "template": {
                "spec": {
                    "volumes": [],
                    "containers": [
                        {
                            "volumeMounts": [
                                {"name": "x", "mountPath": "/var/run/docker.sock"}
                            ]
                        }
                    ],
                }
            }
        }
    }
    with pytest.raises(SandboxConfigError, match="docker.sock"):
        cluster_adapter._assert_no_dangerous_volumes(bad)  # type: ignore[attr-defined]


def test_collected_artifact_paths_returns_descriptor_evidence(
    cluster_adapter: KubernetesSandboxAdapter, passive_job: ToolJob
) -> None:
    paths = cluster_adapter._collected_artifact_paths(passive_job)  # type: ignore[attr-defined]
    assert paths == ["crt.json"]


def test_collected_artifact_paths_returns_empty_for_unknown_tool(
    tmp_path: Path,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
) -> None:
    registry = _FakeRegistry([passive_descriptor])
    adapter = KubernetesSandboxAdapter(
        registry,  # type: ignore[arg-type]
        mode=SandboxRunMode.CLUSTER,
        dry_run_artifact_dir=tmp_path,
    )
    other_job = passive_job.model_copy(update={"tool_id": "ghost_tool"})
    # adapter._collected_artifact_paths reads via registry.get(); fake returns None.
    paths = adapter._collected_artifact_paths(other_job)  # type: ignore[attr-defined]
    assert paths == []


# ---------------------------------------------------------------------------
# _kube() — lazy SDK loading + kubeconfig path resolution
# ---------------------------------------------------------------------------


def test_kube_loads_explicit_kubeconfig_path(
    tmp_path: Path,
    passive_descriptor: ToolDescriptor,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    registry = _FakeRegistry([passive_descriptor])
    adapter = KubernetesSandboxAdapter(
        registry,  # type: ignore[arg-type]
        mode=SandboxRunMode.CLUSTER,
        dry_run_artifact_dir=tmp_path,
        kube_config_path=tmp_path / "kubeconfig.yaml",
    )
    modules = adapter._kube()  # type: ignore[attr-defined]
    assert modules["client"] is fake_kube_modules["client"]
    # Second call must hit the cached path (line coverage for the early-return).
    modules2 = adapter._kube()  # type: ignore[attr-defined]
    assert modules2 is modules


def test_kube_falls_back_to_default_kubeconfig_when_incluster_fails(
    tmp_path: Path,
    passive_descriptor: ToolDescriptor,
) -> None:
    """If load_incluster_config raises ConfigException, fall back to load_kube_config."""
    registry = _FakeRegistry([passive_descriptor])
    fake_modules = _make_fake_kubernetes(raise_on_incluster_config=True)
    saved = {
        name: sys.modules.pop(name, None)
        for name in (
            "kubernetes",
            "kubernetes.client",
            "kubernetes.config",
            "kubernetes.watch",
        )
    }
    sys.modules["kubernetes.client"] = fake_modules["client"]
    sys.modules["kubernetes.config"] = fake_modules["config"]
    sys.modules["kubernetes.watch"] = fake_modules["watch"]
    try:
        adapter = KubernetesSandboxAdapter(
            registry,  # type: ignore[arg-type]
            mode=SandboxRunMode.CLUSTER,
            dry_run_artifact_dir=tmp_path,
        )
        modules = adapter._kube()  # type: ignore[attr-defined]
        assert modules["config"] is fake_modules["config"]
    finally:
        for name in (
            "kubernetes",
            "kubernetes.client",
            "kubernetes.config",
            "kubernetes.watch",
        ):
            sys.modules.pop(name, None)
            if saved.get(name) is not None:
                sys.modules[name] = saved[name]  # type: ignore[assignment]


def test_kube_wraps_config_load_error_uniformly(
    tmp_path: Path,
    passive_descriptor: ToolDescriptor,
) -> None:
    """A non-ConfigException kubeconfig failure becomes SandboxClusterError."""
    registry = _FakeRegistry([passive_descriptor])
    fake_modules = _make_fake_kubernetes(raise_on_load_kube_config=True)
    saved = {
        name: sys.modules.pop(name, None)
        for name in (
            "kubernetes",
            "kubernetes.client",
            "kubernetes.config",
            "kubernetes.watch",
        )
    }
    sys.modules["kubernetes.client"] = fake_modules["client"]
    sys.modules["kubernetes.config"] = fake_modules["config"]
    sys.modules["kubernetes.watch"] = fake_modules["watch"]
    try:
        adapter = KubernetesSandboxAdapter(
            registry,  # type: ignore[arg-type]
            mode=SandboxRunMode.CLUSTER,
            dry_run_artifact_dir=tmp_path,
            kube_config_path=tmp_path / "kubeconfig.yaml",
        )
        with pytest.raises(SandboxClusterError, match="failed to load kubeconfig"):
            adapter._kube()  # type: ignore[attr-defined]
    finally:
        for name in (
            "kubernetes",
            "kubernetes.client",
            "kubernetes.config",
            "kubernetes.watch",
        ):
            sys.modules.pop(name, None)
            if saved.get(name) is not None:
                sys.modules[name] = saved[name]  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# CLUSTER-mode end-to-end happy path
# ---------------------------------------------------------------------------


def _patch_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip ``time.sleep`` inside the polling loop so tests stay fast."""
    monkeypatch.setattr("src.sandbox.k8s_adapter.time.sleep", lambda _seconds: None)


def test_run_in_cluster_succeeds_returns_zero_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    _patch_sleep(monkeypatch)
    _FakeBatchV1Api.status_sequence = [
        _FakeJob(_FakeJobStatus()),
        _FakeJob(_FakeJobStatus(succeeded=1)),
    ]
    _FakeCoreV1Api.pods = [_FakePod("crtpod", exit_code=0)]
    _FakeCoreV1Api.log_text = "hello world"

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))
    assert result.completed is True
    assert result.exit_code == 0
    assert result.failure_reason is None
    assert result.artifacts == ["crt.json"]
    assert "hello world" in result.logs_excerpt
    assert _FakeNetworkingV1Api.create_calls, "NetworkPolicy was not applied"
    assert _FakeBatchV1Api.create_calls, "Job was not applied"


def test_run_in_cluster_failed_job_returns_exit_code_and_reason(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    _patch_sleep(monkeypatch)
    failure_condition = type("C", (), {"reason": "BackoffLimitExceeded"})()
    _FakeBatchV1Api.status_sequence = [
        _FakeJob(_FakeJobStatus(failed=1, conditions=[failure_condition]))
    ]
    _FakeCoreV1Api.pods = [_FakePod("crtpod", exit_code=137)]
    _FakeCoreV1Api.log_text = "killed"

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))
    assert result.completed is False
    assert result.exit_code == 137
    # MED-2: closed taxonomy — BackoffLimitExceeded normalises to job_failed.
    assert result.failure_reason == "job_failed"
    assert result.failure_reason in FAILURE_REASONS
    assert "killed" in result.logs_excerpt


def test_run_in_cluster_failed_job_uses_default_reason_without_conditions(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    _patch_sleep(monkeypatch)
    _FakeBatchV1Api.status_sequence = [_FakeJob(_FakeJobStatus(failed=1))]
    _FakeCoreV1Api.pods = []

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))
    assert result.completed is False
    # MED-2: closed taxonomy default for "failed Job, no conditions" is job_failed.
    assert result.failure_reason == "job_failed"
    assert result.failure_reason in FAILURE_REASONS
    # No pods → exit_code lookup returns None.
    assert result.exit_code is None
    assert result.logs_excerpt == ""


def test_run_in_cluster_timeout_returns_timeout_reason(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    _patch_sleep(monkeypatch)
    # Simulate "running forever" by always returning an empty status.
    _FakeBatchV1Api.status_sequence = [_FakeJob(_FakeJobStatus())]
    _FakeCoreV1Api.pods = [_FakePod("crtpod", exit_code=None)]
    _FakeCoreV1Api.log_text = "still running"

    # Fast-forward time.monotonic so the polling loop trips its deadline
    # immediately on the second call.
    real_monotonic = time.monotonic
    counter = {"calls": 0}

    def _fake_monotonic() -> float:
        counter["calls"] += 1
        # First call sets the start; subsequent calls jump well past the deadline.
        if counter["calls"] <= 1:
            return real_monotonic()
        return real_monotonic() + 1_000.0

    monkeypatch.setattr("src.sandbox.k8s_adapter.time.monotonic", _fake_monotonic)

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))
    # MED-2: closed taxonomy — wall-clock timeout is "cluster_timeout".
    assert result.failure_reason == "cluster_timeout"
    assert result.failure_reason in FAILURE_REASONS
    assert result.completed is False
    assert result.exit_code is None
    assert "still running" in result.logs_excerpt


def test_run_in_cluster_wraps_apply_networkpolicy_failure(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    _patch_sleep(monkeypatch)
    _FakeNetworkingV1Api.create_should_raise = _FakeApiException(
        status=500, reason="api down"
    )

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))
    assert result.completed is False
    # MED-2: closed taxonomy — NP apply failure maps to cluster_apply_failed.
    assert result.failure_reason == "cluster_apply_failed"
    assert result.failure_reason in FAILURE_REASONS


def test_run_in_cluster_wraps_apply_job_failure(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    _patch_sleep(monkeypatch)
    _FakeBatchV1Api.create_should_raise = _FakeApiException(
        status=409, reason="already exists"
    )

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))
    assert result.completed is False
    # MED-2: closed taxonomy — Job apply failure maps to cluster_apply_failed.
    assert result.failure_reason == "cluster_apply_failed"
    assert result.failure_reason in FAILURE_REASONS


def test_run_in_cluster_wraps_status_read_failure(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    _patch_sleep(monkeypatch)
    _FakeBatchV1Api.status_should_raise = _FakeApiException(
        status=503, reason="apiserver unavailable"
    )

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))
    assert result.completed is False
    # MED-2: closed taxonomy — status read failure → cluster_status_unavailable.
    assert result.failure_reason == "cluster_status_unavailable"
    assert result.failure_reason in FAILURE_REASONS


def test_apply_networkpolicy_swallows_404_on_stale_delete(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    _patch_sleep(monkeypatch)
    _FakeBatchV1Api.status_sequence = [_FakeJob(_FakeJobStatus(succeeded=1))]
    _FakeCoreV1Api.pods = [_FakePod("crtpod", exit_code=0)]
    _FakeNetworkingV1Api.delete_status = 404  # stale → must be swallowed

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))
    assert result.completed is True
    assert _FakeNetworkingV1Api.delete_calls
    assert _FakeNetworkingV1Api.create_calls


def test_apply_networkpolicy_propagates_non_404_delete_error(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    _patch_sleep(monkeypatch)
    _FakeNetworkingV1Api.delete_status = 500

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))
    assert result.completed is False
    # MED-2: closed taxonomy — stale-NP delete failure → cluster_apply_failed.
    assert result.failure_reason == "cluster_apply_failed"
    assert result.failure_reason in FAILURE_REASONS


def test_run_in_cluster_truncates_long_pod_logs(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    _patch_sleep(monkeypatch)
    _FakeBatchV1Api.status_sequence = [_FakeJob(_FakeJobStatus(succeeded=1))]
    _FakeCoreV1Api.pods = [_FakePod("crtpod", exit_code=0)]
    _FakeCoreV1Api.log_text = "x" * 50_000  # well over the 10 KB cap

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))
    assert result.completed is True
    # logs_excerpt is capped at 10 KB.
    assert len(result.logs_excerpt.encode("utf-8")) <= 10_240


def test_read_pod_logs_returns_empty_when_pod_lookup_fails(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    _patch_sleep(monkeypatch)
    _FakeBatchV1Api.status_sequence = [_FakeJob(_FakeJobStatus(succeeded=1))]
    _FakeCoreV1Api.pod_list_should_raise = RuntimeError("kubelet hiccup")

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))
    assert result.completed is True
    assert result.logs_excerpt == ""


def test_read_pod_logs_returns_empty_when_log_read_fails(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    _patch_sleep(monkeypatch)
    _FakeBatchV1Api.status_sequence = [_FakeJob(_FakeJobStatus(succeeded=1))]
    _FakeCoreV1Api.pods = [_FakePod("crtpod", exit_code=0)]
    _FakeCoreV1Api.log_should_raise = RuntimeError("logs gone")

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))
    assert result.completed is True
    assert result.logs_excerpt == ""


def test_exit_code_returns_none_when_pod_lookup_fails(
    cluster_adapter: KubernetesSandboxAdapter,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    """`_exit_code_from_pod` must swallow exceptions and return None."""
    api = fake_kube_modules["client"].CoreV1Api()  # type: ignore[attr-defined]
    _FakeCoreV1Api.pod_list_should_raise = RuntimeError("fail")
    code = cluster_adapter._exit_code_from_pod(api, "missing")  # type: ignore[attr-defined]
    assert code is None


def test_exit_code_returns_none_when_no_terminated_state(
    cluster_adapter: KubernetesSandboxAdapter,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    """If no container has terminated yet, `_exit_code_from_pod` returns None."""
    api = fake_kube_modules["client"].CoreV1Api()  # type: ignore[attr-defined]
    _FakeCoreV1Api.pods = [_FakePod("crtpod", exit_code=None)]
    code = cluster_adapter._exit_code_from_pod(api, "crtpod")  # type: ignore[attr-defined]
    assert code is None


def test_run_in_cluster_logs_include_apply_args(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    """Smoke: the cluster path actually pushes the rendered manifests verbatim."""
    _patch_sleep(monkeypatch)
    _FakeBatchV1Api.status_sequence = [_FakeJob(_FakeJobStatus(succeeded=1))]
    _FakeCoreV1Api.pods = [_FakePod("crtpod", exit_code=0)]
    _FakeCoreV1Api.log_text = "ok"

    asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))

    assert _FakeNetworkingV1Api.create_calls
    body = _FakeNetworkingV1Api.create_calls[-1]["body"]
    assert body["kind"] == "NetworkPolicy"
    assert body["spec"]["ingress"] == []
    job_body = _FakeBatchV1Api.create_calls[-1]["body"]
    assert job_body["kind"] == "Job"
    assert job_body["spec"]["backoffLimit"] == 0


def test_cluster_run_sdk_unavailable_maps_to_closed_taxonomy(
    tmp_path: Path,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
) -> None:
    """If the SDK cannot be loaded, ``failure_reason`` stays in the closed
    taxonomy. The verbose install hint lives in the chained exception /
    structured logs — never in the user-facing field.
    """
    registry = _FakeRegistry([passive_descriptor])
    adapter = KubernetesSandboxAdapter(
        registry,  # type: ignore[arg-type]
        mode=SandboxRunMode.CLUSTER,
        dry_run_artifact_dir=tmp_path,
    )

    def _explode(name: str, *_args: Any, **_kwargs: Any) -> Any:
        raise ImportError(name)

    with patch("src.sandbox.k8s_adapter.importlib.import_module", side_effect=_explode):
        result = asyncio.run(adapter.run(passive_job, passive_descriptor))
    assert result.completed is False
    # MED-2: closed taxonomy — SDK-missing collapses to cluster_apply_failed
    # so the API surface never echoes free-form module names / install hints.
    assert result.failure_reason == "cluster_apply_failed"
    assert result.failure_reason in FAILURE_REASONS


# ---------------------------------------------------------------------------
# MED-1: NetworkPolicy cleanup on partial Job-create failure
# ---------------------------------------------------------------------------


def test_run_in_cluster_cleans_up_networkpolicy_when_job_apply_fails(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    """MED-1: if Job-create fails after NetworkPolicy was applied, the orphan
    NetworkPolicy MUST be torn down before re-raising. Otherwise we leak
    cluster-scoped policies that have no TTL.
    """
    _patch_sleep(monkeypatch)
    _FakeBatchV1Api.create_should_raise = _FakeApiException(status=500, body="boom")

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))

    assert result.completed is False
    assert result.failure_reason == "cluster_apply_failed"
    assert result.failure_reason in FAILURE_REASONS

    # Two delete calls are expected:
    #   1. Initial stale-NP cleanup at the head of _apply_networkpolicy.
    #   2. MED-1 cleanup after Job-apply failed.
    delete_calls = _FakeNetworkingV1Api.delete_calls
    assert len(delete_calls) == 2, (
        f"expected initial-cleanup + MED-1 cleanup deletes, got {delete_calls!r}"
    )
    # The cleanup MUST target exactly the NP that was applied — not a guess
    # / not the wrong namespace. Compare to the NP name we just created.
    create_calls = _FakeNetworkingV1Api.create_calls
    assert create_calls, "NetworkPolicy must have been applied before cleanup"
    applied_name = create_calls[-1]["body"]["metadata"]["name"]
    cleanup_call = delete_calls[-1]
    assert cleanup_call["name"] == applied_name
    assert cleanup_call["namespace"] == "argus-sandbox"
    # MED-1: cleanup must use grace_period_seconds=0 to evict immediately.
    assert cleanup_call["grace"] == 0


def test_run_in_cluster_cleans_up_networkpolicy_when_status_read_fails(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    """MED-1: NP cleanup must also fire when Job-create succeeds but the
    subsequent status-read loop raises (e.g. API server flake)."""
    _patch_sleep(monkeypatch)
    _FakeBatchV1Api.status_should_raise = _FakeApiException(
        status=500, body="status-503"
    )

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))

    assert result.completed is False
    assert result.failure_reason == "cluster_status_unavailable"
    assert result.failure_reason in FAILURE_REASONS
    # Initial stale-NP delete + MED-1 cleanup delete = 2.
    assert len(_FakeNetworkingV1Api.delete_calls) == 2


def test_run_in_cluster_cleanup_failure_does_not_mask_original_error(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """MED-1: if the cleanup _delete_networkpolicy itself fails, we MUST still
    surface the *original* failure reason to the caller — never the
    cleanup-side noise. The cleanup error stays inside structured logs."""
    _patch_sleep(monkeypatch)
    _FakeBatchV1Api.create_should_raise = _FakeApiException(status=500, body="job-boom")

    # Initial stale-NP delete returns OK (delete_status=None), then NP create
    # succeeds, then Job create raises, then cleanup delete must run — and we
    # want THAT cleanup to also fail.
    original_delete = _FakeNetworkingV1Api.delete_namespaced_network_policy

    call_state = {"count": 0}

    def _flaky_delete(self: Any, **kwargs: Any) -> None:
        call_state["count"] += 1
        if call_state["count"] >= 2:
            # Cleanup attempt: fail with non-404.
            _FakeNetworkingV1Api.delete_calls.append(
                {
                    "name": kwargs["name"],
                    "namespace": kwargs["namespace"],
                    "grace": kwargs["grace_period_seconds"],
                }
            )
            raise _FakeApiException(status=500, body="cleanup-boom")
        return original_delete(self, **kwargs)

    monkeypatch.setattr(
        _FakeNetworkingV1Api,
        "delete_namespaced_network_policy",
        _flaky_delete,
        raising=True,
    )

    with caplog.at_level("WARNING", logger="src.sandbox.k8s_adapter"):
        result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))

    # Original failure reason wins — cleanup noise is invisible to callers.
    assert result.failure_reason == "cluster_apply_failed"
    assert result.failure_reason in FAILURE_REASONS

    # Cleanup failure is logged structurally — never as the failure_reason.
    cleanup_logs = [
        rec
        for rec in caplog.records
        if "networkpolicy" in rec.getMessage().lower()
        and "cleanup" in rec.getMessage().lower()
    ]
    assert cleanup_logs, "MED-1 cleanup failure must be logged for SRE visibility"


# ---------------------------------------------------------------------------
# MED-2: closed taxonomy — failure_reason values are bounded and sanitised
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("k8s_reason", "expected_failure_reason"),
    [
        ("OOMKilled", "oom_killed"),
        ("Evicted", "oom_killed"),
        ("ImagePullBackOff", "image_pull_failed"),
        ("ErrImagePull", "image_pull_failed"),
        ("InvalidImageName", "image_pull_failed"),
        ("DeadlineExceeded", "cluster_timeout"),
        ("BackoffLimitExceeded", "job_failed"),
        ("Error", "job_failed"),
        ("ContainerCannotRun", "job_failed"),
    ],
)
def test_run_in_cluster_normalises_pod_termination_reason(
    k8s_reason: str,
    expected_failure_reason: str,
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    """MED-2: every raw K8s vocabulary token coming from pod terminated.reason
    must be projected into the closed taxonomy before reaching callers."""
    _patch_sleep(monkeypatch)
    _FakeBatchV1Api.status_sequence = [
        _FakeJob(_FakeJobStatus(failed=1)),
    ]
    _FakeCoreV1Api.pods = [
        _FakePod("crtpod", exit_code=137, terminated_reason=k8s_reason),
    ]
    _FakeCoreV1Api.log_text = "stderr-tail"

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))

    assert result.completed is False
    assert result.failure_reason == expected_failure_reason
    assert result.failure_reason in FAILURE_REASONS


@pytest.mark.parametrize(
    "scenario_failure_reason",
    sorted(FAILURE_REASONS),
)
def test_failure_reasons_taxonomy_is_alphanumeric_lowercase(
    scenario_failure_reason: str,
) -> None:
    """MED-2: the closed taxonomy is intentionally alphanumeric+underscore so
    callers (UI, search, SIEM) can pattern-match on it without quoting."""
    assert scenario_failure_reason
    assert scenario_failure_reason.replace("_", "").isalnum()
    assert scenario_failure_reason == scenario_failure_reason.lower()


def test_failure_reason_never_contains_apiexception_bytes(
    monkeypatch: pytest.MonkeyPatch,
    cluster_adapter: KubernetesSandboxAdapter,
    passive_descriptor: ToolDescriptor,
    passive_job: ToolJob,
    fake_kube_modules: dict[str, ModuleType],
) -> None:
    """MED-2: even when the underlying ApiException carries an HTTP body /
    status / headers, the user-facing failure_reason MUST be a bare taxonomy
    token — not a serialised exception."""
    _patch_sleep(monkeypatch)
    _FakeNetworkingV1Api.create_should_raise = _FakeApiException(
        status=409,
        body='{"kind":"Status","reason":"AlreadyExists","message":"super secret"}',
    )

    result = asyncio.run(cluster_adapter.run(passive_job, passive_descriptor))

    assert result.failure_reason is not None
    # Must be exactly one of the closed taxonomy values.
    assert result.failure_reason in FAILURE_REASONS
    # Defence-in-depth: no JSON braces / status codes / secrets bleed through.
    assert "{" not in result.failure_reason
    assert "409" not in result.failure_reason
    assert "secret" not in result.failure_reason.lower()
    assert "kind" not in result.failure_reason.lower()
