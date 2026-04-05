"""Command executor — subprocess-based execution for allowlisted tools only."""

import logging
import shlex
import time
from typing import Any

from src.cache.tool_recovery import (
    MAX_RECOVERY_ATTEMPTS,
    _replace_tool_in_command,
    classify_error,
    get_tool_recovery_system,
    log_recovery_attempt,
)
from src.core.config import settings
from src.recon.sandbox_tool_runner import (
    build_sandbox_exec_argv,
    check_tool_available,
    run_argv_simple_sync,
)
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
        use_cache: Reserved for ToolResultCache integration
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

        if not check_tool_available(tool_name, use_sandbox=use_sandbox):
            logger.warning(
                "tool_not_installed",
                extra={
                    "event": "tool_not_installed",
                    "tool": tool_name,
                    "use_sandbox": use_sandbox,
                },
            )
            return _result(
                False,
                "",
                f"{tool_name} not installed in {'sandbox' if use_sandbox else 'local environment'}",
                127,
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


def execute_command_with_recovery(
    command: str,
    *,
    use_cache: bool = True,
    use_sandbox: bool = False,
    timeout_sec: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Run *command*; on failure, retry with up to ``MAX_RECOVERY_ATTEMPTS`` allowlisted alternatives.

    Single subprocess execution path remains ``execute_command`` per attempt.
    """
    recovery = get_tool_recovery_system()
    original_tool = extract_tool_name(command) or ""
    attempts: list[dict[str, Any]] = []

    def _append_attempt(tool_label: str, res: dict[str, Any]) -> None:
        stderr = str(res.get("stderr") or "")
        rc = int(res.get("return_code") if res.get("return_code") is not None else -1)
        et = classify_error(stderr, rc)
        attempts.append(
            {
                "tool": tool_label,
                "exit_code": rc,
                "error_type": et,
                "duration_sec": float(res.get("execution_time") or 0.0),
            }
        )
        if not res.get("success"):
            log_recovery_attempt(
                original_tool=original_tool,
                attempted_tool=tool_label,
                command_preview=command[:200],
                return_code=rc,
                error_type=et,
                duration_sec=float(res.get("execution_time") or 0.0),
            )

    result = execute_command(
        command,
        use_cache=use_cache,
        use_sandbox=use_sandbox,
        timeout_sec=timeout_sec,
    )
    _append_attempt(original_tool, result)

    if result.get("success") or not original_tool or recovery.is_stateful(original_tool):
        info = recovery.build_recovery_info(original_tool, original_tool, attempts, from_cache=False)
        return result, info

    allowed_alts = [a for a in recovery.get_alternatives(original_tool) if a in ALLOWED_TOOLS][
        :MAX_RECOVERY_ATTEMPTS
    ]
    final_tool = original_tool
    for alt in allowed_alts:
        new_cmd = _replace_tool_in_command(command, original_tool, alt)
        if new_cmd == command:
            continue
        result = execute_command(
            new_cmd,
            use_cache=use_cache,
            use_sandbox=use_sandbox,
            timeout_sec=timeout_sec,
        )
        final_tool = alt
        _append_attempt(alt, result)
        if result.get("success"):
            break

    info = recovery.build_recovery_info(original_tool, final_tool, attempts, from_cache=False)
    return result, info


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
