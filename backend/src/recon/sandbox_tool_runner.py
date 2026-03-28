"""KAL-007 — shared sandbox argv wrapping and simple subprocess execution.

Used by KAL MCP executor, generic ``execute_command``, VA active-scan docker prefix,
and recon adapters (e.g. searchsploit) so docker/exec and uncapped ``subprocess.run``
paths stay in one place.
"""

from __future__ import annotations

import logging
import subprocess
import time
from typing import Any

from src.core.config import settings

logger = logging.getLogger(__name__)

# Raw artifact logical keys (align with kal_searchsploit_intel / RawPhaseSink usage)
SEARCHSPLOIT_INTEL_RAW_ARTIFACT_KEY = "searchsploit_intel_raw"


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
