"""Ephemeral sandbox lifecycle (platform-hardening A, §10).

A verifiable create → hand-off → exec → wait → exit-code → artifact-capture →
cleanup sequence over a pluggable ``SandboxAdapter``. Guarantees:

* cleanup runs on every path — success, exception, timeout, cancellation;
* a create failure raises (no pseudo container-ID, no confirmation status);
* orphan cleanup only removes containers carrying OUR owner labels, checked by
  age — never another owner's containers;
* the event loop is not blocked: adapter methods are async (a real Docker adapter
  runs blocking SDK calls in a bounded thread executor).

The real hardened Docker/K8s adapter reuses the existing sandbox stack and is
exercised under ``requires_docker``; ``MockSandboxAdapter`` covers the lifecycle
logic offline.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol


class SandboxStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    CREATE_FAILED = "create_failed"


class SandboxCreateError(RuntimeError):
    """Raised when an isolated sandbox container cannot be created."""


@dataclass
class ExecResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""


@dataclass
class SandboxRunResult:
    status: SandboxStatus
    container_id: str = ""
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    artifacts: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def is_success(self) -> bool:
        return self.status == SandboxStatus.SUCCEEDED and self.exit_code == 0


class SandboxAdapter(Protocol):
    async def create(self, task_id: str, owner_labels: dict[str, str]) -> str: ...
    async def exec(self, container_id: str, argv: list[str]) -> ExecResult: ...
    async def collect_artifacts(self, container_id: str, prefix: str) -> list[str]: ...
    async def destroy(self, container_id: str) -> None: ...
    async def list_owned(self, owner_labels: dict[str, str]) -> list[tuple[str, float]]: ...


async def run_in_sandbox(
    adapter: SandboxAdapter,
    task_id: str,
    argv: list[str],
    *,
    owner_labels: dict[str, str],
    artifact_prefix: str = "",
    timeout_seconds: float = 300.0,
) -> SandboxRunResult:
    """Run ``argv`` in a fresh sandbox with guaranteed cleanup on every path."""
    try:
        container_id = await adapter.create(task_id, owner_labels)
    except Exception as exc:  # noqa: BLE001 — create failure must NOT masquerade as success
        return SandboxRunResult(status=SandboxStatus.CREATE_FAILED, error=str(exc))

    result = SandboxRunResult(status=SandboxStatus.FAILED, container_id=container_id)
    try:
        exec_result = await asyncio.wait_for(
            adapter.exec(container_id, argv), timeout=timeout_seconds
        )
        result.exit_code = exec_result.exit_code
        result.stdout = exec_result.stdout
        result.stderr = exec_result.stderr
        # Collect artifacts AFTER execution completes, before teardown.
        result.artifacts = await adapter.collect_artifacts(
            container_id, artifact_prefix or task_id
        )
        result.status = (
            SandboxStatus.SUCCEEDED if exec_result.exit_code == 0 else SandboxStatus.FAILED
        )
    except TimeoutError:
        result.status = SandboxStatus.TIMEOUT
        result.error = f"exec exceeded {timeout_seconds}s"
    except asyncio.CancelledError:
        result.status = SandboxStatus.CANCELLED
        await _safe_destroy(adapter, container_id)
        raise
    except Exception as exc:  # noqa: BLE001
        result.status = SandboxStatus.FAILED
        result.error = str(exc)
    finally:
        if result.status != SandboxStatus.CANCELLED:
            await _safe_destroy(adapter, container_id)
    return result


async def cleanup_orphans(
    adapter: SandboxAdapter,
    owner_labels: dict[str, str],
    max_age_seconds: float = 600.0,
) -> int:
    """Destroy OUR orphaned containers older than ``max_age_seconds``.

    ``list_owned`` must return only containers carrying ``owner_labels`` — we
    never destroy containers we do not own.
    """
    owned = await adapter.list_owned(owner_labels)
    removed = 0
    for container_id, age_seconds in owned:
        if age_seconds >= max_age_seconds:
            await _safe_destroy(adapter, container_id)
            removed += 1
    return removed


async def _safe_destroy(adapter: SandboxAdapter, container_id: str) -> None:
    # Teardown is best-effort but must never raise.
    with contextlib.suppress(Exception):
        await adapter.destroy(container_id)


__all__ = [
    "ExecResult",
    "SandboxAdapter",
    "SandboxCreateError",
    "SandboxRunResult",
    "SandboxStatus",
    "cleanup_orphans",
    "run_in_sandbox",
]
