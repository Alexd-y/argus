"""Real hardened Docker adapter for the sandbox lifecycle wrapper (§8.2).

Backs :func:`src.orchestration.sandbox_lifecycle.run_in_sandbox` with an actual
Docker daemon so the verifiable ``create → exec → collect → destroy`` lifecycle
runs real tools. It implements the structural
:class:`~src.orchestration.sandbox_lifecycle.SandboxAdapter` protocol
(``create`` / ``exec`` / ``collect_artifacts`` / ``destroy`` / ``list_owned``).

Naming: the ARGUS catalog already ships a ``DockerSandboxAdapter`` in
:mod:`src.sandbox.docker_adapter` implementing a *different* contract
(``run(tool_job, descriptor) -> SandboxRunResult``). To avoid an ambiguous name
clash this lifecycle adapter is named ``DockerLifecycleSandboxAdapter``.

Hardening mirrors the existing sandbox stack (and the ``EphemeralWorkerPool``
fix): non-root UID, read-only rootfs, ``--cap-drop ALL``, ``no-new-privileges``,
memory/CPU/pids caps, and a memory-backed ``/workspace`` tmpfs. A create failure
raises :class:`SandboxCreateError` — never a pseudo-ID — so a dependent finding
can never mistake "no isolation" for a successful isolated run.

All blocking Docker SDK calls are offloaded with ``asyncio.to_thread`` so the
event loop is never blocked. Ownership is tracked by container *labels* only, so
``list_owned`` (and orchestrated orphan cleanup) can never touch a container we
did not create.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import tarfile
import tempfile
import time
from datetime import datetime

from src.orchestration.observability import SANDBOX_FAILURES, metric_labels
from src.orchestration.sandbox_lifecycle import ExecResult, SandboxCreateError

try:  # docker SDK is an optional dependency (absent in offline/dev installs).
    import docker
except ImportError:  # pragma: no cover — exercised only where docker is absent
    docker = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_DEFAULT_IMAGE = "argus-sandbox"
_DEFAULT_USER = "1000:1000"
_DEFAULT_MEM_LIMIT = "512m"
_DEFAULT_NANO_CPUS = 1_000_000_000  # 1.0 CPU
_DEFAULT_PIDS_LIMIT = 256
_DEFAULT_WORKSPACE_SIZE = "2g"
_DEFAULT_KEEPALIVE_SECONDS = 3600
_ARTIFACT_DIR = "/workspace/artifacts/"


def _age_seconds(created: str | None, now: float) -> float:
    """Best-effort age of a container from its RFC3339 ``Created`` timestamp."""
    if not created:
        return 0.0
    text = created.strip()
    # Docker emits nanosecond precision + trailing 'Z'; trim to microseconds.
    if text.endswith("Z"):
        text = text[:-1]
    if "." in text:
        head, frac = text.split(".", 1)
        text = f"{head}.{frac[:6]}"
    try:
        created_at = datetime.fromisoformat(text)
    except ValueError:
        return 0.0
    return max(0.0, now - created_at.timestamp())


class DockerLifecycleSandboxAdapter:
    """Hardened Docker backing for :func:`run_in_sandbox` (§8.2).

    ``client`` may be injected (tests / a pre-authenticated daemon handle);
    otherwise it is built lazily via ``docker.from_env()`` on first use so the
    module imports cleanly where the Docker SDK is unavailable.
    """

    def __init__(
        self,
        *,
        image: str = _DEFAULT_IMAGE,
        client: object | None = None,
        user: str = _DEFAULT_USER,
        mem_limit: str = _DEFAULT_MEM_LIMIT,
        nano_cpus: int = _DEFAULT_NANO_CPUS,
        pids_limit: int = _DEFAULT_PIDS_LIMIT,
        workspace_size: str = _DEFAULT_WORKSPACE_SIZE,
        keepalive_seconds: int = _DEFAULT_KEEPALIVE_SECONDS,
        network: str | None = None,
        artifact_dir: str = _ARTIFACT_DIR,
    ) -> None:
        self._image = image
        self._client = client
        self._user = user
        self._mem_limit = mem_limit
        self._nano_cpus = nano_cpus
        self._pids_limit = pids_limit
        self._workspace_size = workspace_size
        self._keepalive_seconds = keepalive_seconds
        self._network = network
        self._artifact_dir = artifact_dir

    def _get_client(self) -> object:
        if self._client is not None:
            return self._client
        if docker is None:
            raise SandboxCreateError("docker SDK not installed — cannot create sandbox")
        self._client = docker.from_env()
        return self._client

    async def create(self, task_id: str, owner_labels: dict[str, str]) -> str:
        """Create a hardened, kept-alive container; return its real ID.

        Raises :class:`SandboxCreateError` on any failure (never a pseudo-ID).
        """

        def _run() -> str:
            client = self._get_client()
            container = client.containers.run(  # type: ignore[attr-defined]
                self._image,
                detach=True,
                labels={**owner_labels, "argus.task": task_id},
                # Keep the container alive so we can exec into it; a bare sleep
                # needs nothing writable, so it is compatible with a read-only
                # rootfs. Real tool output goes to the /workspace tmpfs.
                entrypoint=["sleep", str(self._keepalive_seconds)],
                user=self._user,
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                mem_limit=self._mem_limit,
                nano_cpus=self._nano_cpus,
                pids_limit=self._pids_limit,
                tmpfs={"/workspace": f"size={self._workspace_size}", "/tmp": "size=256m"},
                network=self._network or None,
            )
            return str(container.id)

        try:
            return await asyncio.to_thread(_run)
        except SandboxCreateError:
            raise
        except Exception as exc:  # noqa: BLE001 — every create failure fails closed
            SANDBOX_FAILURES.labels(**metric_labels(reason="create_failed")).inc()
            logger.warning(
                "docker_sandbox_create_failed",
                extra={"event": "docker_sandbox_create_failed", "error": str(exc)},
            )
            raise SandboxCreateError(f"docker sandbox create failed: {exc}") from exc

    async def exec(self, container_id: str, argv: list[str]) -> ExecResult:
        """Run ``argv`` in the container and capture exit code + stdout/stderr."""

        def _exec() -> ExecResult:
            client = self._get_client()
            container = client.containers.get(container_id)  # type: ignore[attr-defined]
            result = container.exec_run(argv, demux=True)
            exit_code = getattr(result, "exit_code", None)
            output = getattr(result, "output", None)
            if exit_code is None and isinstance(result, tuple):  # tuple-shaped double
                exit_code, output = result
            stdout_b, stderr_b = output if isinstance(output, tuple) else (output, None)
            return ExecResult(
                exit_code=int(exit_code or 0),
                stdout=(stdout_b or b"").decode("utf-8", errors="replace"),
                stderr=(stderr_b or b"").decode("utf-8", errors="replace"),
            )

        return await asyncio.to_thread(_exec)

    async def collect_artifacts(self, container_id: str, prefix: str) -> list[str]:
        """Pull files from ``/workspace/artifacts/`` and return their keys.

        Returns ``[]`` when the artifact directory is absent. Upload to
        MinIO/S3 is delegated to the caller (this adapter stays storage-free so
        it is safe to import and unit-test offline).
        """

        def _collect() -> list[str]:
            client = self._get_client()
            container = client.containers.get(container_id)  # type: ignore[attr-defined]
            try:
                bits, _stat = container.get_archive(self._artifact_dir)
            except Exception:  # noqa: BLE001 — absent artifact dir is not an error
                return []
            keys: list[str] = []
            with tempfile.TemporaryDirectory(prefix="argus_sbx_art_") as tmp:
                tar_path = os.path.join(tmp, "artifacts.tar")
                with open(tar_path, "wb") as fh:
                    for chunk in bits:
                        fh.write(chunk)
                with tarfile.open(tar_path) as tar:
                    for member in tar.getmembers():
                        if member.isfile():
                            keys.append(f"{prefix}/{os.path.basename(member.name)}")
            return keys

        return await asyncio.to_thread(_collect)

    async def destroy(self, container_id: str) -> None:
        """Stop and force-remove the container (best-effort, never raises)."""

        def _destroy() -> None:
            client = self._get_client()
            try:
                container = client.containers.get(container_id)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001 — already gone
                return
            with contextlib.suppress(Exception):
                container.stop(timeout=10)
            with contextlib.suppress(Exception):
                container.remove(force=True)

        await asyncio.to_thread(_destroy)

    async def list_owned(self, owner_labels: dict[str, str]) -> list[tuple[str, float]]:
        """Return ``(container_id, age_seconds)`` for OUR labelled containers only."""

        def _list() -> list[tuple[str, float]]:
            client = self._get_client()
            filters = {"label": [f"{k}={v}" for k, v in owner_labels.items()]}
            containers = client.containers.list(all=True, filters=filters)  # type: ignore[attr-defined]
            now = time.time()
            owned: list[tuple[str, float]] = []
            for container in containers:
                attrs = getattr(container, "attrs", {}) or {}
                owned.append((str(container.id), _age_seconds(attrs.get("Created"), now)))
            return owned

        return await asyncio.to_thread(_list)


def build_docker_lifecycle_adapter(**overrides: object) -> DockerLifecycleSandboxAdapter:
    """Construct a :class:`DockerLifecycleSandboxAdapter` with catalog defaults."""
    return DockerLifecycleSandboxAdapter(**overrides)  # type: ignore[arg-type]


__all__ = [
    "DockerLifecycleSandboxAdapter",
    "build_docker_lifecycle_adapter",
]
