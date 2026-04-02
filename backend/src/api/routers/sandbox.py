"""Sandbox router — HexStrike v4 constrained execution.

POST /sandbox/python runs arbitrary code via the host interpreter when
``ARGUS_SANDBOX_PYTHON_ENABLED`` is true. This is intended for local/dev
workflows only; regex filtering is a coarse guardrail, not a security
boundary. Do not expose enabled instances to untrusted callers.
"""

from __future__ import annotations

import logging
import re
import subprocess
import sys
import time
from typing import Pattern

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from starlette import status

from src.api.schemas import SandboxExecuteRequest, SandboxExecuteResponse, SandboxPythonRequest
from src.cache.tool_cache import (
    cache_key_for_execute,
    get_tool_cache,
    recovery_info_stub,
    ttl_for_tool,
)
from src.core.config import settings
from src.tools.executor import execute_command
from src.tools.guardrails.command_parser import ALLOWED_TOOLS, extract_tool_name

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sandbox", tags=["sandbox"])

_OUTPUT_MAX_LEN = 32_768

_DANGEROUS_PYTHON_PATTERNS: tuple[Pattern[str], ...] = (
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
            return SandboxExecuteResponse(
                success=True,
                stdout=stdout,
                stderr=stderr,
                return_code=int(cached.get("return_code") or 0),
                execution_time=float(cached.get("execution_time") or 0.0),
                truncated=t1 or t2,
                from_cache=True,
                recovery_info=recovery_info_stub(from_cache=True),
            )

    start = time.perf_counter()
    result = execute_command(
        body.command,
        use_cache=False,
        use_sandbox=body.use_sandbox,
        timeout_sec=timeout,
    )
    elapsed = time.perf_counter() - start
    stdout, t1 = _truncate(str(result.get("stdout") or ""))
    stderr, t2 = _truncate(str(result.get("stderr") or ""))
    success = bool(result.get("success"))
    response = SandboxExecuteResponse(
        success=success,
        stdout=stdout,
        stderr=stderr,
        return_code=int(result.get("return_code") or -1),
        execution_time=float(result.get("execution_time") or elapsed),
        truncated=t1 or t2,
        from_cache=False,
        recovery_info=recovery_info_stub(from_cache=False),
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
    """HexStrike v4 MCP — process listing (stub)."""
    return JSONResponse(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        content={
            "success": False,
            "feature": "sandbox_processes",
            "detail": "Sandbox process listing is not implemented.",
        },
    )


@router.post("/processes/{pid}/kill")
async def sandbox_kill_process(pid: int) -> JSONResponse:
    """HexStrike v4 MCP — terminate sandbox worker (stub)."""
    _ = pid
    return JSONResponse(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        content={
            "success": False,
            "feature": "sandbox_kill_process",
            "detail": "Sandbox process termination is not implemented.",
        },
    )


@router.post("/python", response_model=None)
async def sandbox_python(body: SandboxPythonRequest):
    """Run short Python snippet when feature flag is on; blocks common escape patterns."""
    if not settings.argus_sandbox_python_enabled:
        return JSONResponse(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            content={
                "success": False,
                "feature": "sandbox_python",
                "detail": "Sandbox Python execution is disabled (set ARGUS_SANDBOX_PYTHON_ENABLED=true to enable).",
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
        )
