"""Read bounded bytes from files inside the sandbox container (docker exec)."""

from __future__ import annotations

import logging
import subprocess

from src.core.config import settings

logger = logging.getLogger(__name__)


def read_sandbox_file_capped(remote_path: str, *, max_bytes: int) -> bytes:
    """``head -c`` inside sandbox; empty if disabled, bad path, or error."""
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
        proc = subprocess.run(
            ["docker", "exec", name, "head", "-c", str(cap), rp],
            capture_output=True,
            timeout=120,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.warning(
            "sandbox_file_read_failed",
            extra={"event": "sandbox_file_read_failed", "error_type": type(e).__name__},
        )
        return b""
    if proc.returncode != 0:
        return b""
    return proc.stdout or b""
