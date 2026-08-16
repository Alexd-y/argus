"""Command executor — subprocess-based execution for allowlisted tools only."""

import asyncio
import logging
import shlex
import time
from datetime import UTC, datetime
from typing import Any

from src.cache.tool_cache import cache_key_for_execute, get_tool_cache, ttl_for_tool
from src.cache.tool_recovery import (
    MAX_RECOVERY_ATTEMPTS,
    _replace_tool_in_command,
    classify_error,
    get_tool_recovery_system,
    log_recovery_attempt,
)
from src.core.config import settings
from src.nuclei.legacy_inventory import is_profile_compiler_enabled
from src.nuclei.legacy_metrics import increment_legacy_argv
from src.nuclei.profile_compiler import (
    NucleiProfileCompiler,
    default_profile_id_for_mode,
)
from src.recon.sandbox_tool_runner import (
    build_sandbox_exec_argv,
    check_tool_available,
    run_argv_simple_sync,
)
from src.sandbox.execution_lease_gate import assert_execution_allowed
from src.tools.guardrails.command_parser import ALLOWED_TOOLS, extract_tool_name

logger = logging.getLogger(__name__)

_TOOL_RUN_OUTPUT_MAX_CHARS = 50_000

_PHASE_CACHE: dict[str, str] = {}
_NUCLEI_EXECUTOR_CALLER = "tools.executor.build_nuclei_command"


def _current_scan_phase(scan_id: str) -> str:
    return _PHASE_CACHE.get(scan_id, "")


async def _persist_tool_run(
    tenant_id: str,
    scan_id: str,
    tool_name: str,
    run_status: str,
    input_params: dict[str, Any] | None,
    output_raw: str,
    started_at: datetime,
    finished_at: datetime,
) -> None:
    """Best-effort ToolRun persistence — fire-and-forget from sync executor."""
    try:
        from src.db.models import ToolRun
        from src.db.session import async_session_factory, set_session_tenant

        truncated = output_raw[:_TOOL_RUN_OUTPUT_MAX_CHARS] if output_raw else ""
        async with async_session_factory() as session:
            await set_session_tenant(session, tenant_id)
            run = ToolRun(
                tenant_id=tenant_id,
                scan_id=scan_id,
                tool_name=tool_name,
                status=run_status,
                input_params=input_params,
                output_raw=truncated,
                started_at=started_at,
                finished_at=finished_at,
            )
            session.add(run)
            await session.commit()
    except Exception:
        logger.warning(
            "tool_run_persist_failed",
            extra={"event": "argus.tool_run.persist_failed", "tool": tool_name},
            exc_info=True,
        )


def _schedule_tool_run_record(
    tenant_id: str | None,
    scan_id: str | None,
    tool_name: str,
    result: dict[str, Any],
    started_at: datetime,
    finished_at: datetime,
    command: str,
) -> None:
    """Schedule ToolRun DB write on the running event loop (no-op when context is missing)."""
    if not tenant_id or not scan_id:
        return
    run_status = "success" if result.get("success") else "error"
    input_params = {"command": command}
    output_raw = str(result.get("stdout") or "")
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(
            _persist_tool_run(
                tenant_id=tenant_id,
                scan_id=scan_id,
                tool_name=tool_name,
                run_status=run_status,
                input_params=input_params,
                output_raw=output_raw,
                started_at=started_at,
                finished_at=finished_at,
            )
        )
    except RuntimeError as exc:
        logger.debug("tool_run persist skipped (no event loop)", exc_info=exc)


def _lease_gate_target(
    target: str | None,
    scan_options: dict[str, Any] | None,
) -> str:
    if target:
        return target
    if isinstance(scan_options, dict):
        raw = scan_options.get("target")
        if raw:
            return str(raw)
    return ""


def execute_command(
    command: str,
    use_cache: bool = True,
    use_sandbox: bool = False,
    timeout_sec: int | None = None,
    *,
    scan_id: str | None = None,
    tenant_id: str | None = None,
    scan_options: dict[str, Any] | None = None,
    engagement_id: str | None = None,
    target: str | None = None,
) -> dict[str, Any]:
    """
    Execute a shell command via subprocess.

    Uses list form (no shell) to reduce injection risk. Parameterized calls only.
    When *use_cache* is ``True``, successful results are stored in Redis-backed
    ``ToolResultCache`` and returned on subsequent identical invocations until the
    per-tool TTL expires. Redis outages are handled transparently — execution
    proceeds without caching.

    When *scan_id* and *tenant_id* are provided, a ``ToolRun`` record is persisted
    to the database (best-effort, fire-and-forget) for audit and observability.

    Args:
        command: Full command string (e.g. "nmap -sV 192.168.1.1")
        use_cache: If True, look up / store results via ``ToolResultCache``.
        use_sandbox: If True, run via docker exec in sandbox container.
        timeout_sec: Subprocess timeout seconds; defaults to ``settings.recon_tools_timeout``.
        scan_id: Optional scan UUID — enables ToolRun recording.
        tenant_id: Optional tenant UUID — enables ToolRun recording.
        scan_options: Scan options carrying ``execution_mode`` / ``lab_lease``.
        engagement_id: Optional engagement UUID for LAB lease tenant checks.
        target: Optional target URL/host for the LAB boundary gate.

    Returns:
        Dict with success, stdout, stderr, return_code, execution_time
    """
    started_at = datetime.now(UTC)
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

        assert_execution_allowed(
            tool_name,
            _lease_gate_target(target, scan_options),
            scan_options,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
        )

        if scan_id:
            try:
                from src.orchestration.mcp_allowlist import MCPAllowlist
                _phase = _current_scan_phase(scan_id) if scan_id else ""
                if _phase:
                    _guard_result = MCPAllowlist().guard_tool_call(tool_name, _phase)
                    if _guard_result:
                        logger.warning("mcp_allowlist_denied", extra={"tool": tool_name, "phase": _phase, "reason": _guard_result.reason})
            except Exception:
                pass

        if use_cache:
            cache = get_tool_cache()
            key = cache_key_for_execute(command, use_sandbox, timeout_sec)
            cached = cache.get(key)
            if cached is not None:
                cached["execution_time"] = 0.0
                logger.debug(
                    "tool_cache_hit",
                    extra={"event": "argus.tool_cache.hit", "tool": tool_name, "key": key},
                )
                return cached

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
        result = _result(
            bool(exec_out.get("success")),
            str(exec_out.get("stdout") or ""),
            str(exec_out.get("stderr") or ""),
            int(rc) if rc is not None else -1,
            elapsed,
        )

        if use_cache and result["success"]:
            ttl = ttl_for_tool(tool_name)
            if ttl > 0:
                cache.set(key, result, ttl)
                logger.debug(
                    "tool_cache_set",
                    extra={
                        "event": "argus.tool_cache.set",
                        "tool": tool_name,
                        "key": key,
                        "ttl": ttl,
                    },
                )

        _schedule_tool_run_record(
            tenant_id=tenant_id,
            scan_id=scan_id,
            tool_name=tool_name or "unknown",
            result=result,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            command=command,
        )

        return result
    except PermissionError:
        raise
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
    scan_id: str | None = None,
    tenant_id: str | None = None,
    scan_options: dict[str, Any] | None = None,
    engagement_id: str | None = None,
    target: str | None = None,
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
        scan_id=scan_id,
        tenant_id=tenant_id,
        scan_options=scan_options,
        engagement_id=engagement_id,
        target=target,
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
            scan_id=scan_id,
            tenant_id=tenant_id,
            scan_options=scan_options,
            engagement_id=engagement_id,
            target=target,
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


def _legacy_nuclei_command(
    target: str,
    severity: str,
    tags: str,
    template: str,
    additional_args: str,
) -> str:
    """Hand-built argv (pre-compiler). Emits legacy warning metric."""
    increment_legacy_argv(caller=_NUCLEI_EXECUTOR_CALLER)
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


def _append_nuclei_operator_args(
    argv: list[str],
    severity: str,
    tags: str,
    template: str,
    additional_args: str,
) -> list[str]:
    """Caller targeting only — never re-inject ``-ni`` / rate / concurrency caps."""
    out = list(argv)
    if severity:
        out.extend(["-severity", severity])
    if tags:
        out.extend(["-tags", tags])
    if template:
        out.extend(["-t", template])
    if additional_args:
        out.extend(shlex.split(additional_args))
    return out


def build_nuclei_command(
    target: str,
    severity: str,
    tags: str,
    template: str,
    additional_args: str,
    *,
    profile: str | None = None,
    execution_mode: str | None = None,
) -> str:
    """Build nuclei command from parameters.

    Legacy positional signature is unchanged. When ``profile`` is set or
    ``ARGUS_NUCLEI_PROFILE_COMPILER=1``, argv comes from
    :class:`~src.nuclei.profile_compiler.NucleiProfileCompiler`. LAB profiles
    do not inject ``-ni``, rate-limit, concurrency caps, or tag exclusions.
    """
    profile_id = (profile or "").strip() or None
    if not (is_profile_compiler_enabled() or profile_id):
        return _legacy_nuclei_command(target, severity, tags, template, additional_args)

    resolved_mode = (execution_mode or "production").strip() or "production"
    resolved_profile = profile_id or default_profile_id_for_mode(resolved_mode)
    argv = NucleiProfileCompiler.compile(resolved_profile, resolved_mode, target)
    if not argv:
        return ""
    argv = _append_nuclei_operator_args(argv, severity, tags, template, additional_args)
    return " ".join(shlex.quote(p) for p in argv)


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
