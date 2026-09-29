"""Read bounded bytes from files inside the sandbox container (docker exec)."""

from __future__ import annotations

import logging

from src.core.config import settings
from src.sandbox.docker_gateway import DockerGatewayError, exec_in_sync_bytes

logger = logging.getLogger(__name__)


def read_sandbox_file_capped(remote_path: str, *, max_bytes: int) -> bytes:
    """``head -c`` inside sandbox; empty if disabled, bad path, or error.

    F-H01 Stage 3: routed through the single Docker gateway (binary capture).
    """
    rp = (remote_path or "").strip()
    if not rp or not rp.startswith("/"):
        return b""
    if not settings.sandbox_enabled:
        return b""
    cap = max(0, min(int(max_bytes), 50 * 1024 * 1024))
    if cap == 0:
        return b""
    name = (settings.sandbox_container_name or "").strip()
    if not name:
        return b""
    try:
        rc, stdout, _stderr = exec_in_sync_bytes(
            name,
            ["head", "-c", str(cap), rp],
            timeout=120,
        )
    except DockerGatewayError as e:
        logger.warning(
            "sandbox_file_read_failed",
            extra={"event": "sandbox_file_read_failed", "error_type": type(e).__name__},
        )
        return b""
    if rc != 0:
        return b""
    return stdout or b""
