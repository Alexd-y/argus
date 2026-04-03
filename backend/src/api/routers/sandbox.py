"""Sandbox router — HexStrike v4 constrained execution.

POST /sandbox/python runs arbitrary code via the host interpreter when
``ARGUS_SANDBOX_PYTHON_ENABLED`` is true. This is intended for local/dev
workflows only; regex filtering is a coarse guardrail, not a security
boundary. Do not expose enabled instances to untrusted callers.
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import platform
import re
import shutil
import subprocess
import sys
import time
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from starlette import status

from src.api.schemas import SandboxExecuteRequest, SandboxExecuteResponse, SandboxPythonRequest
from src.cache.tool_cache import (
    cache_key_for_execute,
    get_tool_cache,
    ttl_for_tool,
)
from src.cache.tool_recovery import get_tool_recovery_system
from src.core.config import settings
from src.tools.executor import execute_command_with_recovery
from src.tools.guardrails.command_parser import ALLOWED_TOOLS, extract_tool_name

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sandbox", tags=["sandbox"])

_OUTPUT_MAX_LEN = 32_768

_DANGEROUS_PYTHON_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bgetattr\s*\(", re.I),
    re.compile(r"\bos\.\s*(system|popen|spawn)", re.I),
    re.compile(r"\bos\.system\s*\(", re.I),
    re.compile(r"\bsubprocess\b", re.I),
    re.compile(r"\b__import__\s*\(", re.I),
    re.compile(r"\bimportlib\b", re.I),
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"\bexec\s*\(", re.I),
    re.compile(r"\bcompile\s*\(", re.I),
    re.compile(r"\bopen\s*\(", re.I),
    re.compile(r"\bsocket\b", re.I),
    re.compile(r"\bpty\b", re.I),
    re.compile(r"`", re.M),  # backticks in code often abuse subprocess
)


def _truncate(text: str, max_len: int = _OUTPUT_MAX_LEN) -> tuple[str, bool]:
    if len(text) <= max_len:
        return text, False
    return text[:max_len] + "\n… [truncated]", True


def _python_code_blocked(code: str) -> str | None:
    for pat in _DANGEROUS_PYTHON_PATTERNS:
        if pat.search(code):
            return pat.pattern
    return None


def _parse_ps_docker_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    parts = line.split(None, 2)
    if len(parts) < 2:
        return None
    try:
        pid = int(parts[0])
    except ValueError:
        return None
    comm = parts[1]
    args = parts[2] if len(parts) > 2 else comm
    return {"pid": pid, "comm": comm, "command": args}


def _list_processes_impl() -> dict[str, Any]:
    """List processes from sandbox container (docker) or host OS."""
    container = (settings.sandbox_container_name or "").strip() or "argus-sandbox"
    if settings.sandbox_enabled and shutil.which("docker"):
        try:
            proc = subprocess.run(
                ["docker", "exec", container, "ps", "-eo", "pid=,comm=,args="],
                capture_output=True,
                text=True,
                timeout=20,
                shell=False,
            )
            if proc.returncode != 0:
                logger.warning(
                    "sandbox_ps_docker_failed",
                    extra={"event": "argus.sandbox.ps_docker_failed", "returncode": proc.returncode},
                )
                return {
                    "success": False,
                    "source": "docker",
                    "processes": [],
                    "detail": "Could not list processes in sandbox container",
                }
            processes = []
            for line in (proc.stdout or "").splitlines():
                row = _parse_ps_docker_line(line)
                if row:
                    processes.append(row)
            return {"success": True, "source": "docker", "processes": processes, "detail": None}
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "source": "docker",
                "processes": [],
                "detail": "Process listing timed out",
            }
        except OSError:
            logger.exception(
                "sandbox_ps_docker_os_error",
                extra={"event": "argus.sandbox.ps_docker_os_error"},
            )
            return {
                "success": False,
                "source": "docker",
                "processes": [],
                "detail": "Process listing failed",
            }

    try:
        if platform.system() == "Windows":
            proc = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=20,
                shell=False,
            )
            if proc.returncode != 0:
                return {
                    "success": False,
                    "source": "host",
                    "processes": [],
                    "detail": "Host process listing failed",
                }
            processes: list[dict[str, Any]] = []
            reader = csv.reader(io.StringIO(proc.stdout or ""))
            for row in reader:
                if len(row) < 2:
                    continue
                name = row[0]
                try:
                    pid = int(row[1])
                except ValueError:
                    continue
                processes.append({"pid": pid, "comm": name, "command": name})
            return {"success": True, "source": "host", "processes": processes, "detail": None}

        proc = subprocess.run(
            ["ps", "-eo", "pid=,comm=,args="],
            capture_output=True,
            text=True,
            timeout=20,
            shell=False,
        )
        if proc.returncode != 0:
            return {
                "success": False,
                "source": "host",
                "processes": [],
                "detail": "Host process listing failed",
            }
        processes = []
        for line in (proc.stdout or "").splitlines():
            row = _parse_ps_docker_line(line)
            if row:
                processes.append(row)
        return {"success": True, "source": "host", "processes": processes, "detail": None}
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "source": "host",
            "processes": [],
            "detail": "Process listing timed out",
        }
    except OSError:
        logger.exception(
            "sandbox_ps_host_os_error",
            extra={"event": "argus.sandbox.ps_host_os_error"},
        )
        return {
            "success": False,
            "source": "host",
            "processes": [],
            "detail": "Process listing failed",
        }


def _kill_process_impl(pid: int) -> dict[str, Any]:
    container = (settings.sandbox_container_name or "").strip() or "argus-sandbox"
    if settings.sandbox_enabled and shutil.which("docker"):
        try:
            proc = subprocess.run(
                ["docker", "exec", container, "kill", "-9", str(pid)],
                capture_output=True,
                text=True,
                timeout=15,
                shell=False,
            )
            if proc.returncode != 0:
                return {
                    "success": False,
                    "source": "docker",
                    "detail": "Kill signal was not acknowledged",
                }
            return {"success": True, "source": "docker", "detail": None}
        except subprocess.TimeoutExpired:
            return {"success": False, "source": "docker", "detail": "Kill request timed out"}
        except OSError:
            logger.exception(
                "sandbox_kill_docker_os_error",
                extra={"event": "argus.sandbox.kill_docker_os_error"},
            )
            return {"success": False, "source": "docker", "detail": "Kill request failed"}

    try:
        if platform.system() == "Windows":
            proc = subprocess.run(
                ["taskkill", "/PID", str(pid), "/F"],
                capture_output=True,
                text=True,
                timeout=15,
                shell=False,
            )
            if proc.returncode != 0:
                return {
                    "success": False,
                    "source": "host",
                    "detail": "Kill request failed",
                }
            return {"success": True, "source": "host", "detail": None}
        proc = subprocess.run(
            ["kill", "-9", str(pid)],
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
        )
        if proc.returncode != 0:
            return {
                "success": False,
                "source": "host",
                "detail": "Kill request failed",
            }
        return {"success": True, "source": "host", "detail": None}
    except subprocess.TimeoutExpired:
        return {"success": False, "source": "host", "detail": "Kill request timed out"}
    except OSError:
        logger.exception(
            "sandbox_kill_host_os_error",
            extra={"event": "argus.sandbox.kill_host_os_error"},
        )
        return {"success": False, "source": "host", "detail": "Kill request failed"}


@router.post("/execute", response_model=SandboxExecuteResponse)
async def sandbox_execute(body: SandboxExecuteRequest) -> SandboxExecuteResponse:
    """Run allowlisted shell tool command (same guardrails as /tools/execute)."""
    tool = extract_tool_name(body.command)
    if not tool or tool not in ALLOWED_TOOLS:
        out, trunc = _truncate(
            f"Tool not in sandbox whitelist. Allowed: {', '.join(sorted(ALLOWED_TOOLS))}"
        )
        return SandboxExecuteResponse(
            success=False,
            stdout="",
            stderr=out,
            return_code=1,
            execution_time=0.0,
            truncated=trunc,
            from_cache=False,
            recovery_info=None,
        )
    timeout = body.timeout_sec
    if timeout is None:
        timeout = int(settings.recon_tools_timeout or 300)

    cache = get_tool_cache()
    ttl = ttl_for_tool(tool)
    cache_key = cache_key_for_execute(body.command, body.use_sandbox, timeout)
    if ttl > 0 and cache.enabled:
        cached = cache.get(cache_key)
        if cached and cached.get("success") is True:
            stdout, t1 = _truncate(str(cached.get("stdout") or ""))
            stderr, t2 = _truncate(str(cached.get("stderr") or ""))
            rec = get_tool_recovery_system()
            recovery_info = rec.build_recovery_info(
                tool,
                tool,
                [],
                from_cache=True,
            )
            return SandboxExecuteResponse(
                success=True,
                stdout=stdout,
                stderr=stderr,
                return_code=int(cached.get("return_code") or 0),
                execution_time=float(cached.get("execution_time") or 0.0),
                truncated=t1 or t2,
                from_cache=True,
                recovery_info=recovery_info,
            )

    result, recovery_info = execute_command_with_recovery(
        body.command,
        use_cache=False,
        use_sandbox=body.use_sandbox,
        timeout_sec=timeout,
    )
    stdout, t1 = _truncate(str(result.get("stdout") or ""))
    stderr, t2 = _truncate(str(result.get("stderr") or ""))
    success = bool(result.get("success"))
    response = SandboxExecuteResponse(
        success=success,
        stdout=stdout,
        stderr=stderr,
        return_code=int(result.get("return_code") or -1),
        execution_time=float(result.get("execution_time") or 0.0),
        truncated=t1 or t2,
        from_cache=False,
        recovery_info=recovery_info,
    )
    if ttl > 0 and cache.enabled and success:
        cache.set(
            cache_key,
            {
                "success": True,
                "stdout": stdout,
                "stderr": stderr,
                "return_code": response.return_code,
                "execution_time": response.execution_time,
                "truncated": response.truncated,
            },
            ttl,
        )
    return response


@router.get("/processes")
async def sandbox_process_list() -> JSONResponse:
    """List processes in sandbox container (docker) or on the API host."""
    payload = await asyncio.to_thread(_list_processes_impl)
    return JSONResponse(status_code=status.HTTP_200_OK, content=payload)


@router.post("/processes/{pid}/kill")
async def sandbox_kill_process(pid: int) -> JSONResponse:
    """Send SIGKILL to PID in sandbox container or host (best-effort)."""
    if pid < 1:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"success": False, "feature": "sandbox_kill_process", "detail": "Invalid pid"},
        )
    payload = await asyncio.to_thread(_kill_process_impl, pid)
    if not payload.get("success"):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "feature": "sandbox_kill_process",
                "pid": pid,
                "source": payload.get("source"),
                "detail": payload.get("detail") or "Kill failed",
            },
        )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"success": True, "pid": pid, "source": payload.get("source")},
    )


@router.post("/python", response_model=None)
async def sandbox_python(body: SandboxPythonRequest):
    """Run short Python snippet when feature flag is on; blocks common escape patterns."""
    if not settings.argus_sandbox_python_enabled:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "success": False,
                "feature": "sandbox_python",
                "code": "sandbox_python_disabled",
                "detail": "Sandbox Python execution is disabled. Set ARGUS_SANDBOX_PYTHON_ENABLED=true to enable.",
            },
        )
    if _python_code_blocked(body.code):
        msg, trunc = _truncate("Code blocked by sandbox policy")
        return SandboxExecuteResponse(
            success=False,
            stdout="",
            stderr=msg,
            return_code=1,
            execution_time=0.0,
            truncated=trunc,
            from_cache=False,
            recovery_info=None,
        )
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            [sys.executable or "python", "-c", body.code],
            capture_output=True,
            text=True,
            timeout=float(body.timeout_sec),
            shell=False,
        )
        elapsed = time.perf_counter() - start
        stdout, t1 = _truncate(proc.stdout or "")
        stderr, t2 = _truncate(proc.stderr or "")
        return SandboxExecuteResponse(
            success=proc.returncode == 0,
            stdout=stdout,
            stderr=stderr,
            return_code=int(proc.returncode),
            execution_time=elapsed,
            truncated=t1 or t2,
            from_cache=False,
            recovery_info=None,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - start
        return SandboxExecuteResponse(
            success=False,
            stdout="",
            stderr="Execution timed out",
            return_code=-1,
            execution_time=elapsed,
            truncated=False,
            from_cache=False,
            recovery_info=None,
        )
    except Exception:
        logger.exception("sandbox_python_failed", extra={"event": "argus.sandbox_python_failed"})
        elapsed = time.perf_counter() - start
        return SandboxExecuteResponse(
            success=False,
            stdout="",
            stderr="Sandbox execution failed",
            return_code=-1,
            execution_time=elapsed,
            truncated=False,
            from_cache=False,
            recovery_info=None,
        )
