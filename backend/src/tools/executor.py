"""Command executor — subprocess-based execution for allowlisted tools only."""

import logging
import shlex
import time
from typing import Any

from src.core.config import settings
from src.recon.sandbox_tool_runner import build_sandbox_exec_argv, run_argv_simple_sync
from src.tools.guardrails.command_parser import ALLOWED_TOOLS, extract_tool_name

logger = logging.getLogger(__name__)


def execute_command(
    command: str,
    use_cache: bool = True,
    use_sandbox: bool = False,
    timeout_sec: int | None = None,
) -> dict[str, Any]:
    """
    Execute a shell command via subprocess.

    Uses list form (no shell) to reduce injection risk. Parameterized calls only.

    Args:
        command: Full command string (e.g. "nmap -sV 192.168.1.1")
        use_cache: Ignored in MVP; reserved for future caching
        use_sandbox: If True, run via docker exec in sandbox container
        timeout_sec: Subprocess timeout seconds; defaults to ``settings.recon_tools_timeout``.

    Returns:
        Dict with success, stdout, stderr, return_code, execution_time
    """
    _ = use_cache  # Reserved for future use
    start = time.perf_counter()
    try:
        parts = shlex.split(command)
        if not parts:
            return _result(False, "", "Empty command", 1, 0.0)

        tool_name = extract_tool_name(command)
        if not tool_name or tool_name not in ALLOWED_TOOLS:
            return _result(
                False,
                "",
                f"Tool not allowed. Allowed: {', '.join(sorted(ALLOWED_TOOLS))}",
                1,
                0.0,
            )

        run_parts = build_sandbox_exec_argv(parts, use_sandbox=use_sandbox)

        timeout = timeout_sec if timeout_sec is not None else settings.recon_tools_timeout
        if timeout is not None and timeout <= 0:
            timeout = 300

        exec_out = run_argv_simple_sync(run_parts, timeout_sec=float(timeout))
        elapsed = time.perf_counter() - start
        rc = exec_out.get("return_code")
        return _result(
            bool(exec_out.get("success")),
            str(exec_out.get("stdout") or ""),
            str(exec_out.get("stderr") or ""),
            int(rc) if rc is not None else -1,
            elapsed,
        )
    except Exception:
        elapsed = time.perf_counter() - start
        logger.exception("Command execution failed")
        return _result(False, "", "Command execution failed", -1, elapsed)


def _result(success: bool, stdout: str, stderr: str, return_code: int, execution_time: float) -> dict[str, Any]:
    return {
        "success": success,
        "stdout": stdout,
        "stderr": stderr,
        "return_code": return_code,
        "execution_time": execution_time,
    }


def build_nmap_command(target: str, scan_type: str, ports: str, additional_args: str) -> str:
    """Build nmap command from parameters."""
    cmd = ["nmap", scan_type]
    if ports:
        cmd.extend(["-p", ports])
    if additional_args:
        cmd.extend(shlex.split(additional_args))
    cmd.append(target)
    return " ".join(shlex.quote(p) for p in cmd)


def build_nuclei_command(target: str, severity: str, tags: str, template: str, additional_args: str) -> str:
    """Build nuclei command from parameters."""
    cmd = ["nuclei", "-u", target]
    if severity:
        cmd.extend(["-severity", severity])
    if tags:
        cmd.extend(["-tags", tags])
    if template:
        cmd.extend(["-t", template])
    if additional_args:
        cmd.extend(shlex.split(additional_args))
    return " ".join(shlex.quote(p) for p in cmd)


def build_gobuster_command(url: str, mode: str, wordlist: str, additional_args: str) -> str:
    """Build gobuster command from parameters."""
    cmd = ["gobuster", mode, "-u", url, "-w", wordlist]
    if additional_args:
        cmd.extend(shlex.split(additional_args))
    return " ".join(shlex.quote(p) for p in cmd)


def build_nikto_command(target: str, additional_args: str) -> str:
    """Build nikto command from parameters."""
    cmd = ["nikto", "-h", target]
    if additional_args:
        cmd.extend(shlex.split(additional_args))
    return " ".join(shlex.quote(p) for p in cmd)


def build_sqlmap_command(url: str, data: str, additional_args: str) -> str:
    """Build sqlmap command from parameters."""
    cmd = ["sqlmap", "-u", url, "--batch"]
    if data:
        cmd.extend(["--data", data])
    if additional_args:
        cmd.extend(shlex.split(additional_args))
    return " ".join(shlex.quote(p) for p in cmd)


def build_generic_tool_command(tool: str, args: list[str]) -> str:
    """Build generic tool command."""
    cmd = [tool] + args
    return " ".join(shlex.quote(p) for p in cmd)
