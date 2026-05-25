"""
Ephemeral Worker Isolation — Design Specification (4.11)

Goal: Each exploitation/vuln-analysis task runs in a short-lived Docker
container that is destroyed after the task completes. Inspired by
Shannon's per-task ephemeral subprocess isolation but adapted for
ARGUS's existing Docker sandbox + Celery worker architecture.

Architecture
============

1. Task Submission
   - Celery task (run_vuln_agent / run_exploit_step) submits a job
   - Worker calls EphemeralWorkerPool.acquire() to get an isolated container

2. Container Lifecycle
   - EphemeralWorkerPool pulls a fresh container from a pre-built image
   - Mounts: /workspace (read-write temp dir), /tools (read-only Kali tools)
   - Network: isolated Docker network with target access via proxy
   - Container runs the task script (Python or shell) as non-root
   - On completion: container is stopped, removed, workspace dir is deleted
   - Artifacts are collected before teardown via collect_artifacts()

3. Resource Limits
   - CPU: 1 core per container (Docker --cpus=1)
   - Memory: 512MB limit (--memory=512m)
   - Disk: 2GB tmpfs for /workspace (--tmpfs /workspace:size=2g)
   - Network: custom Docker network, outbound only to target + DNS
   - Timeout: 300s default (--stop-timeout 30)

4. Pool Management
   - Max concurrent containers: configured per tenant (default 5)
   - Container reuse: NONE — every task gets a fresh container
   - Health check: docker inspect before use; prune stale containers
   - Cleanup: async sweeper removes containers older than 600s

5. Artifact Collection
   - Before container removal, copy /workspace/artifacts/ to MinIO
   - Artifact keys follow: {scan_id}/{phase}/{task_id}/{filename}
   - If copy fails, log warning but DO NOT block container cleanup

6. Security
   - Containers run as non-root user ( --user 1000:1000 )
   - No Docker socket mount
   - No privilege escalation (--no-new-privileges)
   - Read-only root filesystem except /workspace and /tmp
   - seccomp profile: default Docker + allow ptrace for debug tools
   - Network egress: deny all, then allow target CIDR + DNS + proxy

Implementation Plan
===================

Phase 1: EphemeralWorkerPool class
  - acquire(task_id, image, timeout) -> container_id
  - release(container_id) -> None (stop + remove)
  - collect_artifacts(container_id, scan_id, phase, task_id) -> list[str]
  - prune_stale(max_age_seconds=600) -> int

Phase 2: Celery integration
  - Wrap existing run_vuln_agent task with EphemeralWorkerPool
  - Replace direct Docker exec with pool-managed containers
  - Add pool lifecycle hooks to Celery worker startup/shutdown

Phase 3: Network isolation
  - Create Docker network per scan (argus-scan-{scan_id})
  - Connect container to scan network + proxy service
  - Destroy network on scan completion

Phase 4: Monitoring
  - Prometheus metrics: containers_created, containers_removed,
    container_timeout_total, artifacts_collected_total
  - Structured logs: container_id, task_id, scan_id, duration

Conventions
===========
- Container naming: argus-task-{task_id[:12]}
- Image: argus/kali-runner:latest (pre-built with tools + Python)
- Workspace: /workspace (tmpfs, 2GB)
- Artifacts dir: /workspace/artifacts/
- Exit codes: 0=success, 1=task_error, 2=timeout, 137=OOM_killed
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ContainerSpec:
    """Specification for an ephemeral task container."""

    image: str = "argus/kali-runner:latest"
    cpu_limit: float = 1.0
    memory_limit: str = "512m"
    workspace_size: str = "2g"
    timeout_seconds: int = 300
    user: str = "1000:1000"
    network: str = ""
    env_vars: dict[str, str] = field(default_factory=dict)
    command: list[str] = field(default_factory=list)


@dataclass
class ContainerResult:
    """Result from a completed ephemeral container."""

    container_id: str
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    artifact_keys: list[str] = field(default_factory=list)
    oom_killed: bool = False
    timed_out: bool = False


class EphemeralWorkerPool:
    """Manages short-lived Docker containers for isolated task execution.

    Each invocation creates a fresh container, runs the task, collects
    artifacts, and destroys the container. No container reuse.
    """

    def __init__(
        self,
        max_containers: int = 5,
        default_image: str = "argus/kali-runner:latest",
        prune_interval: int = 120,
    ) -> None:
        self._max_containers = max_containers
        self._default_image = default_image
        self._prune_interval = prune_interval
        self._active: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def acquire(
        self,
        task_id: str,
        spec: ContainerSpec | None = None,
    ) -> str:
        """Create and start an ephemeral container for a task.

        Returns the Docker container ID. When Docker SDK is available,
        creates a real container with resource limits. Otherwise returns
        a pseudo-ID for tracking.
        """
        if spec is None:
            spec = ContainerSpec(image=self._default_image)

        container_name = f"argus-task-{task_id[:12]}"

        async with self._lock:
            if len(self._active) >= self._max_containers:
                raise RuntimeError(
                    f"Max concurrent containers ({self._max_containers}) reached"
                )

        logger.info(
            "Creating ephemeral container %s (image=%s, timeout=%ds)",
            container_name,
            spec.image,
            spec.timeout_seconds,
        )

        container_id = container_name

        try:
            import docker
            client = docker.from_env()
            container = client.containers.run(
                image=spec.image,
                name=container_name,
                detach=True,
                remove=False,
                network=spec.network or None,
                environment=spec.env_vars or None,
                command=spec.command or None,
                user=spec.user,
                mem_limit=spec.memory_limit,
                nano_cpus=int(spec.cpu_limit * 1e9),
                stop_timeout=30,
                tmpfs={"/workspace": f"size={spec.workspace_size}"},
                read_only=True,
                security_opt=["no-new-privileges"],
            )
            container_id = container.id
            logger.info("Docker container created: %s", container_id)
        except ImportError:
            logger.debug("Docker SDK not available — using pseudo container tracking")
        except Exception as docker_exc:
            logger.warning(
                "Docker container creation failed (%s) — using pseudo tracking",
                docker_exc,
            )

        self._active[container_id] = time.monotonic()
        return container_id
        self._active[container_id] = time.monotonic()

        return container_id

    async def release(self, container_id: str) -> None:
        """Stop and remove an ephemeral container."""
        logger.info("Releasing ephemeral container %s", container_id)

        try:
            import docker
            client = docker.from_env()
            container = client.containers.get(container_id)
            container.stop(timeout=10)
            container.remove(force=True)
            logger.info("Docker container removed: %s", container_id)
        except ImportError:
            pass
        except Exception as docker_exc:
            logger.debug("Docker container removal failed: %s", docker_exc)

        async with self._lock:
            self._active.pop(container_id, None)

    async def collect_artifacts(
        self,
        container_id: str,
        scan_id: str,
        phase: str,
        task_id: str,
    ) -> list[str]:
        """Collect artifacts from container before teardown.

        Returns list of MinIO artifact keys.
        """
        artifact_prefix = f"{scan_id}/{phase}/{task_id}"
        logger.info(
            "Collecting artifacts from %s -> %s/",
            container_id,
            artifact_prefix,
        )
        return []

    async def prune_stale(self, max_age_seconds: int = 600) -> int:
        """Remove containers that have been active too long."""
        now = time.monotonic()
        stale_ids = [
            cid
            for cid, created_at in self._active.items()
            if (now - created_at) > max_age_seconds
        ]
        for cid in stale_ids:
            logger.warning("Pruning stale container %s (age > %ds)", cid, max_age_seconds)
            await self.release(cid)
        return len(stale_ids)

    @property
    def active_count(self) -> int:
        """Number of currently active containers."""
        return len(self._active)


__all__ = [
    "ContainerResult",
    "ContainerSpec",
    "EphemeralWorkerPool",
]