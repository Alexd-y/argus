"""KAL-007 — shared sandbox argv wrapping and simple subprocess execution.

Used by KAL MCP executor, generic ``execute_command``, VA active-scan docker prefix,
and recon adapters (e.g. searchsploit) so docker/exec and uncapped ``subprocess.run``
paths stay in one place.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from datetime import UTC, datetime
from typing import Any

from src.core.config import settings

logger = logging.getLogger(__name__)

# Raw artifact logical keys (align with kal_searchsploit_intel / RawPhaseSink usage)
SEARCHSPLOIT_INTEL_RAW_ARTIFACT_KEY = "searchsploit_intel_raw"

_TOOL_AVAILABILITY_CACHE: dict[str, bool] = {}

_AVAILABILITY_CHECK_TIMEOUT = 5.0


def clear_tool_availability_cache() -> None:
    """Reset the per-scan availability cache (call at scan start/end)."""
    _TOOL_AVAILABILITY_CACHE.clear()


def check_tool_available(
    tool_binary: str,
    *,
    use_sandbox: bool = True,
) -> bool:
    """Check if *tool_binary* is reachable in the sandbox container (or locally).

    Results are cached for the lifetime of the scan to avoid repeated ``which`` calls.
    """
    cache_key = f"{'sandbox' if (use_sandbox and settings.sandbox_enabled) else 'local'}:{tool_binary}"
    cached = _TOOL_AVAILABILITY_CACHE.get(cache_key)
    if cached is not None:
        return cached

    available = False
    if use_sandbox and settings.sandbox_enabled:
        try:
            proc = subprocess.run(
                ["docker", "exec", settings.sandbox_container_name, "which", tool_binary],
                capture_output=True,
                text=True,
                timeout=_AVAILABILITY_CHECK_TIMEOUT,
                shell=False,
            )
            available = proc.returncode == 0 and bool(proc.stdout.strip())
        except (subprocess.TimeoutExpired, OSError):
            logger.warning(
                "tool_availability_check_failed",
                extra={
                    "event": "tool_availability_check_failed",
                    "binary": tool_binary,
                    "method": "sandbox",
                },
            )
    else:
        available = shutil.which(tool_binary) is not None

    _TOOL_AVAILABILITY_CACHE[cache_key] = available

    if not available:
        method = "sandbox" if (use_sandbox and settings.sandbox_enabled) else "local"
        logger.warning(
            "tool_not_found",
            extra={
                "event": "tool_not_found",
                "binary": tool_binary,
                "method": method,
            },
        )

    return available


def check_tool_available_with_fallback(
    tool_binary: str,
    *,
    use_sandbox: bool = True,
) -> dict[str, Any]:
    """Check tool availability and return a structured result dict.

    Keys: ``available``, ``binary``, ``checked_at``, ``method``.
    """
    method = "sandbox" if (use_sandbox and settings.sandbox_enabled) else "local"
    available = check_tool_available(tool_binary, use_sandbox=use_sandbox)
    return {
        "available": available,
        "binary": tool_binary,
        "checked_at": datetime.now(UTC).isoformat(),
        "method": method,
    }


def build_sandbox_exec_argv(
    argv: list[str],
    *,
    use_sandbox: bool,
    sandbox_workdir: str | None = None,
) -> list[str]:
    """Prefix *argv* with ``docker exec`` into the configured sandbox when requested."""
    if use_sandbox and settings.sandbox_enabled:
        parts: list[str] = ["docker", "exec"]
        wd = (sandbox_workdir or "").strip()
        if wd:
            parts.extend(["-w", wd])
        parts.append(settings.sandbox_container_name)
        return parts + list(argv)
    return list(argv)


def run_argv_simple_sync(
    run_parts: list[str],
    *,
    timeout_sec: float,
) -> dict[str, Any]:
    """Run *run_parts* with ``subprocess.run`` (uncapped capture). Same shape as ``execute_command`` results."""
    start = time.perf_counter()
    t = float(timeout_sec)
    if t <= 0:
        t = float(max(1, int(getattr(settings, "recon_tools_timeout", 300) or 300)))
    try:
        proc = subprocess.run(
            run_parts,
            capture_output=True,
            text=True,
            timeout=t,
            shell=False,
        )
        elapsed = time.perf_counter() - start
        return {
            "success": proc.returncode == 0,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "return_code": proc.returncode,
            "execution_time": elapsed,
        }
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - start
        logger.warning(
            "sandbox_tool_runner_timeout",
            extra={"event": "sandbox_tool_runner_timeout", "timeout_sec": t},
        )
        return {
            "success": False,
            "stdout": "",
            "stderr": "Command timed out",
            "return_code": -1,
            "execution_time": elapsed,
        }
    except OSError:
        elapsed = time.perf_counter() - start
        logger.exception(
            "sandbox_tool_runner_os_error",
            extra={"event": "sandbox_tool_runner_os_error"},
        )
        return {
            "success": False,
            "stdout": "",
            "stderr": "Execution failed",
            "return_code": -1,
            "execution_time": elapsed,
        }
    except Exception:
        elapsed = time.perf_counter() - start
        logger.exception(
            "sandbox_tool_runner_failed",
            extra={"event": "sandbox_tool_runner_failed"},
        )
        return {
            "success": False,
            "stdout": "",
            "stderr": "Command execution failed",
            "return_code": -1,
            "execution_time": elapsed,
        }
