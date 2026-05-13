"""Sandbox environment provisioning — containers and VMs.

Provides disposable, isolated environments for validation runs.
Container mode uses docker exec; VM mode uses Firecracker microVMs.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class EnvironmentError(Exception):
    """Failed to provision or manage environment."""


@dataclass
class EnvironmentSnapshot:
    id: str
    environment_id: str
    snapshot_path: str
    metadata: dict[str, Any]


async def provision_container(
    image: str = "argus-sandbox",
    network_policy: str = "deny_all",
    memory_limit_mb: int = 512,
    cpu_limit: float = 1.0,
) -> dict[str, Any]:
    """Provision a disposable Docker container for validation.

    Args:
        image: Container image to use.
        network_policy: 'deny_all' or 'allowlist'.
        memory_limit_mb: Memory cap.
        cpu_limit: CPU cap.

    Returns:
        {"id": container_id, "type": "container", "status": "ready", ...}
    """
    container_id = f"argus-validation-{uuid.uuid4().hex[:12]}"
    cmd = [
        "docker", "run", "-d", "--rm",
        "--name", container_id,
        "--memory", f"{memory_limit_mb}m",
        "--cpus", str(cpu_limit),
        "--network", "none" if network_policy == "deny_all" else "bridge",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        image,
        "sleep", "3600",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        if proc.returncode != 0:
            raise EnvironmentError(
                f"Container creation failed: {(stderr or b'').decode()[:500]}"
            )
        cid = (stdout or b"").decode().strip()[:64]
        return {
            "id": cid or container_id,
            "name": container_id,
            "type": "container",
            "status": "ready",
            "network_policy": network_policy,
        }
    except asyncio.TimeoutError:
        raise EnvironmentError("Container creation timed out")


async def teardown_container(container_id: str) -> None:
    """Stop and remove a validation container."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.communicate(), timeout=10)
    except Exception as exc:
        logger.warning("container_teardown_error", extra={
            "container_id": container_id,
            "error": str(exc),
        })


async def create_snapshot(container_id: str, snapshot_name: str = "") -> EnvironmentSnapshot:
    """Create a filesystem snapshot of validation environment before execution."""
    snap_name = snapshot_name or f"snap-{uuid.uuid4().hex[:8]}"
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "commit", container_id, snap_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        if proc.returncode != 0:
            raise EnvironmentError(f"Snapshot failed: {(stderr or b'').decode()[:500]}")
        image_id = (stdout or b"").decode().strip()
        return EnvironmentSnapshot(
            id=snap_name,
            environment_id=container_id,
            snapshot_path=image_id,
            metadata={"type": "docker_commit"},
        )
    except Exception as exc:
        logger.warning("snapshot_failed", extra={"container_id": container_id, "error": str(exc)})
        return EnvironmentSnapshot(
            id=snap_name, environment_id=container_id, snapshot_path="", metadata={}
        )


async def rollback_to_snapshot(container_id: str, snapshot: EnvironmentSnapshot) -> bool:
    """Rollback container to a previous snapshot (re-create from image)."""
    if not snapshot.snapshot_path:
        return False
    try:
        await teardown_container(container_id)
        proc = await asyncio.create_subprocess_exec(
            "docker", "run", "-d", "--rm",
            "--name", container_id,
            "--network", "none",
            "--cap-drop", "ALL",
            snapshot.snapshot_path,
            "sleep", "3600",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=30)
        return proc.returncode == 0
    except Exception:
        return False


async def get_file_diff(
    container_id: str, path: str = "/tmp"
) -> dict[str, Any]:
    """Get file listing diff before/after validation run (snapshot based)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", container_id, "find", path,
            "-type", "f", "-printf", r"%p\t%s\n",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        files = {}
        for line in (stdout or b"").decode().splitlines():
            if "\t" in line:
                p, s = line.rsplit("\t", 1)
                files[p] = int(s)
        return {"path": path, "file_count": len(files), "files": files}
    except Exception as exc:
        return {"path": path, "error": str(exc)}
