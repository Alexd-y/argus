"""Real hardened Kubernetes adapter for the sandbox lifecycle wrapper (§8.2).

The Kubernetes counterpart of
:class:`src.sandbox.docker_sandbox_adapter.DockerLifecycleSandboxAdapter`. It
backs :func:`src.orchestration.sandbox_lifecycle.run_in_sandbox` with a
short-lived, hardened Pod so the verifiable ``create → exec → collect → destroy``
lifecycle runs real tools on a cluster (ECS-less / K8s deployments).

Naming: the ARGUS catalog already ships a ``KubernetesSandboxAdapter`` in
:mod:`src.sandbox.k8s_adapter` implementing a *different* contract
(``run(tool_job, descriptor) -> SandboxRunResult`` over a Job + NetworkPolicy).
To avoid an ambiguous name clash this lifecycle adapter is named
``K8sLifecycleSandboxAdapter`` (mirroring the Docker lifecycle adapter).

Hardening mirrors the existing K8s manifest invariants (Backlog §5/§18) and the
Docker lifecycle adapter: non-root UID, read-only root filesystem,
``allowPrivilegeEscalation=False``, ``capabilities.drop=["ALL"]``,
``seccompProfile=RuntimeDefault``, ``automountServiceAccountToken=False``,
``restartPolicy=Never``, a bounded ``activeDeadlineSeconds``, CPU/memory limits,
and memory-backed ``/workspace`` + ``/tmp`` ``emptyDir`` volumes. There are NO
``hostPath`` volumes and NO docker.sock mount. A create failure raises
:class:`SandboxCreateError` — never a pseudo-ID — so a dependent finding can
never mistake "no isolation" for a successful isolated run.

All blocking Kubernetes SDK calls are offloaded with ``asyncio.to_thread`` so the
event loop is never blocked. Ownership is tracked by Pod *labels* only, so
``list_owned`` (and orchestrated orphan cleanup) can never touch a Pod we did not
create. The ``kubernetes`` SDK is imported lazily so this module is safe to
import (and unit-test with injected fakes) where the SDK is absent.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from src.orchestration.observability import SANDBOX_FAILURES, metric_labels
from src.orchestration.sandbox_lifecycle import ExecResult, SandboxCreateError

logger = logging.getLogger(__name__)

_DEFAULT_NAMESPACE = "argus-sandbox"
_DEFAULT_IMAGE = "argus-sandbox"
_DEFAULT_CONTAINER = "sandbox"
_DEFAULT_CPU_LIMIT = "1"
_DEFAULT_MEM_LIMIT = "512Mi"
_DEFAULT_WORKSPACE_SIZE = "2Gi"
_DEFAULT_TMP_SIZE = "256Mi"
_DEFAULT_KEEPALIVE_SECONDS = 3600
_DEFAULT_READY_TIMEOUT_SECONDS = 60.0
_DNS1123_SANITISE = re.compile(r"[^a-z0-9-]+")

# k8s exec multiplexed channel used for the command exit status payload.
_K8S_ERROR_CHANNEL = 3


def _sanitise_name(task_id: str) -> str:
    """Build a DNS-1123-safe Pod name from an arbitrary task id."""
    base = _DNS1123_SANITISE.sub("-", task_id.lower()).strip("-") or "task"
    return f"argus-sbx-{base[:40]}-{uuid.uuid4().hex[:6]}"


def _age_seconds(created: Any, now: datetime) -> float:
    """Best-effort age of a Pod from its ``creation_timestamp`` (tz-aware datetime)."""
    if created is None:
        return 0.0
    if isinstance(created, str):
        text = created.replace("Z", "+00:00")
        try:
            created = datetime.fromisoformat(text)
        except ValueError:
            return 0.0
    if not isinstance(created, datetime):
        return 0.0
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    return max(0.0, (now - created).total_seconds())


def _parse_exec_returncode(error_payload: str) -> int:
    """Map a k8s exec ERROR_CHANNEL status payload to a process exit code.

    Kubernetes returns ``{"status": "Success"}`` for exit 0, otherwise a
    ``Failure`` status whose ``details.causes`` carries the numeric exit code.
    An unparseable/empty payload is treated as success (channel not emitted).
    """
    if not error_payload:
        return 0
    try:
        status = json.loads(error_payload)
    except (json.JSONDecodeError, TypeError):
        return 0
    if status.get("status") == "Success":
        return 0
    for cause in (status.get("details") or {}).get("causes") or []:
        if cause.get("reason") == "ExitCode":
            try:
                return int(cause.get("message", 1))
            except (TypeError, ValueError):
                return 1
    return 1


def _default_exec_fn(
    core_v1: Any, pod_name: str, namespace: str, argv: list[str], container: str
) -> tuple[int, str, str]:
    """Run ``argv`` in a Pod via the k8s streaming exec API (real-cluster path).

    Imported lazily so the module stays importable without the SDK. Exercised
    under ``requires_kind``; unit tests inject a fake ``exec_fn`` instead.
    """
    from kubernetes.stream import stream  # local: optional SDK, cluster-only path

    resp = stream(
        core_v1.connect_get_namespaced_pod_exec,
        pod_name,
        namespace,
        command=argv,
        container=container,
        stderr=True,
        stdin=False,
        stdout=True,
        tty=False,
        _preload_content=False,
    )
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    while resp.is_open():
        resp.update(timeout=1)
        if resp.peek_stdout():
            stdout_chunks.append(resp.read_stdout())
        if resp.peek_stderr():
            stderr_chunks.append(resp.read_stderr())
    error_payload = resp.read_channel(_K8S_ERROR_CHANNEL)
    resp.close()
    return (
        _parse_exec_returncode(error_payload),
        "".join(stdout_chunks),
        "".join(stderr_chunks),
    )


class K8sLifecycleSandboxAdapter:
    """Hardened Kubernetes backing for :func:`run_in_sandbox` (§8.2).

    ``core_v1`` and ``exec_fn`` may be injected (tests / a pre-authenticated
    cluster handle); otherwise the SDK is loaded lazily on first use so the
    module imports cleanly where ``kubernetes`` is unavailable.
    """

    def __init__(
        self,
        *,
        namespace: str = _DEFAULT_NAMESPACE,
        image: str = _DEFAULT_IMAGE,
        container_name: str = _DEFAULT_CONTAINER,
        core_v1: Any | None = None,
        exec_fn: Any | None = None,
        cpu_limit: str = _DEFAULT_CPU_LIMIT,
        mem_limit: str = _DEFAULT_MEM_LIMIT,
        workspace_size: str = _DEFAULT_WORKSPACE_SIZE,
        tmp_size: str = _DEFAULT_TMP_SIZE,
        keepalive_seconds: int = _DEFAULT_KEEPALIVE_SECONDS,
        ready_timeout_seconds: float = _DEFAULT_READY_TIMEOUT_SECONDS,
        run_as_uid: int = 1000,
        artifact_dir: str = "/workspace/artifacts",
    ) -> None:
        if not namespace:
            raise ValueError("namespace must be non-empty")
        self._namespace = namespace
        self._image = image
        self._container = container_name
        self._core_v1 = core_v1
        self._exec_fn = exec_fn or _default_exec_fn
        self._cpu_limit = cpu_limit
        self._mem_limit = mem_limit
        self._workspace_size = workspace_size
        self._tmp_size = tmp_size
        self._keepalive_seconds = keepalive_seconds
        self._ready_timeout_seconds = ready_timeout_seconds
        self._run_as_uid = run_as_uid
        self._artifact_dir = artifact_dir.rstrip("/")

    def _get_core_v1(self) -> Any:
        if self._core_v1 is not None:
            return self._core_v1
        try:
            from kubernetes import client, config  # local: optional SDK
        except ImportError as exc:  # pragma: no cover — SDK-absent guard
            raise SandboxCreateError(
                "kubernetes SDK not installed — cannot create sandbox pod"
            ) from exc
        try:
            config.load_incluster_config()
        except Exception:  # noqa: BLE001 — fall back to a local kubeconfig
            config.load_kube_config()
        self._core_v1 = client.CoreV1Api()
        return self._core_v1

    def _pod_manifest(self, pod_name: str, task_id: str, owner_labels: dict[str, str]) -> dict:
        """Build a hardened, kept-alive Pod manifest (no hostPath / no docker.sock)."""
        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": pod_name,
                "namespace": self._namespace,
                "labels": {**owner_labels, "argus.task": task_id},
            },
            "spec": {
                "restartPolicy": "Never",
                "automountServiceAccountToken": False,
                "activeDeadlineSeconds": self._keepalive_seconds + 60,
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": self._run_as_uid,
                    "runAsGroup": self._run_as_uid,
                    "fsGroup": self._run_as_uid,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [
                    {
                        "name": self._container,
                        "image": self._image,
                        # Keep the Pod alive so we can exec into it; a bare sleep
                        # needs nothing writable (compatible with a read-only
                        # rootfs). Real tool output goes to the /workspace tmpfs.
                        "command": ["sleep", str(self._keepalive_seconds)],
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "privileged": False,
                            "runAsNonRoot": True,
                            "runAsUser": self._run_as_uid,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "resources": {
                            "limits": {
                                "cpu": self._cpu_limit,
                                "memory": self._mem_limit,
                            },
                            "requests": {"cpu": "100m", "memory": "128Mi"},
                        },
                        "volumeMounts": [
                            {"name": "workspace", "mountPath": "/workspace"},
                            {"name": "tmp", "mountPath": "/tmp"},
                        ],
                    }
                ],
                "volumes": [
                    {
                        "name": "workspace",
                        "emptyDir": {
                            "medium": "Memory",
                            "sizeLimit": self._workspace_size,
                        },
                    },
                    {
                        "name": "tmp",
                        "emptyDir": {"medium": "Memory", "sizeLimit": self._tmp_size},
                    },
                ],
            },
        }

    async def create(self, task_id: str, owner_labels: dict[str, str]) -> str:
        """Create a hardened, kept-alive Pod and wait until it is Running.

        Returns the real Pod name; raises :class:`SandboxCreateError` on any
        failure (never a pseudo-ID).
        """
        pod_name = _sanitise_name(task_id)
        manifest = self._pod_manifest(pod_name, task_id, owner_labels)

        def _create() -> None:
            core = self._get_core_v1()
            core.create_namespaced_pod(namespace=self._namespace, body=manifest)

        try:
            await asyncio.to_thread(_create)
            await self._wait_running(pod_name)
        except SandboxCreateError:
            await self._safe_delete(pod_name)
            raise
        except Exception as exc:
            SANDBOX_FAILURES.labels(**metric_labels(reason="create_failed")).inc()
            logger.warning(
                "k8s_sandbox_create_failed",
                extra={"event": "k8s_sandbox_create_failed", "error": str(exc)},
            )
            await self._safe_delete(pod_name)
            raise SandboxCreateError(f"k8s sandbox create failed: {exc}") from exc
        return pod_name

    async def _wait_running(self, pod_name: str) -> None:
        """Poll the Pod until it reaches ``Running`` or the ready deadline lapses."""

        def _phase() -> str:
            core = self._get_core_v1()
            pod = core.read_namespaced_pod(name=pod_name, namespace=self._namespace)
            status = getattr(pod, "status", None)
            return str(getattr(status, "phase", "") or "")

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._ready_timeout_seconds
        while True:
            phase = await asyncio.to_thread(_phase)
            if phase == "Running":
                return
            if phase in ("Failed", "Succeeded"):
                raise SandboxCreateError(f"pod {pod_name} entered terminal phase {phase!r}")
            if loop.time() >= deadline:
                raise SandboxCreateError(
                    f"pod {pod_name} not Running within {self._ready_timeout_seconds}s (phase={phase!r})"
                )
            await asyncio.sleep(0.5)

    async def exec(self, container_id: str, argv: list[str]) -> ExecResult:
        """Run ``argv`` inside the Pod and capture exit code + stdout/stderr."""

        def _exec() -> tuple[int, str, str]:
            core = self._get_core_v1()
            return self._exec_fn(core, container_id, self._namespace, argv, self._container)

        exit_code, stdout, stderr = await asyncio.to_thread(_exec)
        return ExecResult(exit_code=int(exit_code), stdout=stdout or "", stderr=stderr or "")

    async def collect_artifacts(self, container_id: str, prefix: str) -> list[str]:
        """Enumerate files under the artifact dir and return their keys.

        Best-effort: exec ``find`` inside the Pod. Returns ``[]`` when the
        directory is absent/empty. Upload to MinIO/S3 is delegated to the caller
        (this adapter stays storage-free so it is safe to unit-test offline).
        """

        def _list() -> list[str]:
            core = self._get_core_v1()
            argv = ["find", self._artifact_dir, "-type", "f"]
            exit_code, stdout, _stderr = self._exec_fn(
                core, container_id, self._namespace, argv, self._container
            )
            if exit_code != 0 or not stdout:
                return []
            keys: list[str] = []
            for line in stdout.splitlines():
                name = line.strip().rsplit("/", 1)[-1]
                if name:
                    keys.append(f"{prefix}/{name}")
            return keys

        return await asyncio.to_thread(_list)

    async def destroy(self, container_id: str) -> None:
        """Delete the Pod (best-effort, never raises)."""
        await self._safe_delete(container_id)

    async def _safe_delete(self, pod_name: str) -> None:
        def _delete() -> None:
            core = self._get_core_v1()
            with contextlib.suppress(Exception):
                core.delete_namespaced_pod(
                    name=pod_name,
                    namespace=self._namespace,
                    grace_period_seconds=0,
                )

        with contextlib.suppress(Exception):
            await asyncio.to_thread(_delete)

    async def list_owned(self, owner_labels: dict[str, str]) -> list[tuple[str, float]]:
        """Return ``(pod_name, age_seconds)`` for OUR labelled Pods only."""

        def _list() -> list[tuple[str, float]]:
            core = self._get_core_v1()
            selector = ",".join(f"{k}={v}" for k, v in owner_labels.items())
            resp = core.list_namespaced_pod(namespace=self._namespace, label_selector=selector)
            now = datetime.now(UTC)
            owned: list[tuple[str, float]] = []
            for pod in getattr(resp, "items", []) or []:
                meta = getattr(pod, "metadata", None)
                name = getattr(meta, "name", None)
                if not name:
                    continue
                owned.append(
                    (
                        str(name),
                        _age_seconds(getattr(meta, "creation_timestamp", None), now),
                    )
                )
            return owned

        return await asyncio.to_thread(_list)


def build_k8s_lifecycle_adapter(**overrides: Any) -> K8sLifecycleSandboxAdapter:
    """Construct a :class:`K8sLifecycleSandboxAdapter` with catalog defaults."""
    return K8sLifecycleSandboxAdapter(**overrides)


__all__ = [
    "K8sLifecycleSandboxAdapter",
    "build_k8s_lifecycle_adapter",
]
