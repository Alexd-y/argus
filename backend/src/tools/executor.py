"""Command executor — subprocess-based execution for allowlisted tools only."""

import logging
import shlex
import threading
import time
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

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


# Reliable ToolRun persistence: ``execute_command`` is synchronous and is called
# from mixed contexts (worker thread via ``asyncio.to_thread`` or directly). The
# previous ``loop.create_task`` fire-and-forget was silently dropped when the
# per-phase event loop was torn down (``asyncio.run`` cancels pending tasks),
# leaving ``tool_runs`` empty. Instead we buffer records per scan (thread-safe)
# and flush them synchronously at the phase boundary via :func:`flush_tool_runs`,
# which runs inside the phase's committed transaction.
_PENDING_TOOL_RUNS: dict[str, list[dict[str, Any]]] = {}
_PENDING_TOOL_RUNS_LOCK = threading.Lock()

# Wave 2 (R-5.3.2): evidence rows are buffered per scan next to tool runs and
# written by ``flush_tool_runs`` at the phase boundary. The *object* is uploaded
# to storage immediately after the run (see ``_capture_tool_run_evidence``), so
# a lost buffer still leaves the artifact in MinIO linked by ``tool_run_id``.
_PENDING_EVIDENCE: dict[str, list[dict[str, Any]]] = {}
_PENDING_EVIDENCE_LOCK = threading.Lock()


def _schedule_tool_run_record(
    tenant_id: str | None,
    scan_id: str | None,
    tool_name: str,
    result: dict[str, Any],
    started_at: datetime,
    finished_at: datetime,
    command: str,
    *,
    tool_run_id: UUID | None = None,
    evidence_saved: bool | None = None,
    output_object_key: str | None = None,
) -> None:
    """Buffer a ToolRun record for later flush (no-op when scan context is missing)."""
    if not tenant_id or not scan_id:
        return
    success = bool(result.get("success"))
    stdout = str(result.get("stdout") or "")
    stderr = str(result.get("stderr") or "")
    # On failure the actionable reason lives in ``stderr`` (stdout is typically
    # empty for a crashed/denied tool). Persist stderr into ``output_raw`` so the
    # cause is visible directly in ``tool_runs`` instead of only worker logs.
    output_raw = stdout if success else "\n".join(part for part in (stderr, stdout) if part)
    full_len = len(output_raw)
    clipped = output_raw[:_TOOL_RUN_OUTPUT_MAX_CHARS] if output_raw else ""
    # Wave 2 (R-5.3.4 / stage 4): output_raw is a convenience excerpt only. When
    # it is clipped, say so explicitly with the full length and a pointer to the
    # complete output in object storage, so a reader of output_raw knows it is a
    # part, not the whole.
    if full_len > _TOOL_RUN_OUTPUT_MAX_CHARS:
        pointer = f" key={output_object_key}" if output_object_key else ""
        clipped = (
            f"{clipped}\n… [truncated: showing {_TOOL_RUN_OUTPUT_MAX_CHARS} of "
            f"{full_len} chars; full output in object storage{pointer}]"
        )
    input_params: dict[str, Any] = {"command": command}
    if evidence_saved is not None:
        # Explicit, visible state — "evidence not saved" must not be inferred
        # from an absence of rows (R-5.3.2).
        input_params["evidence_saved"] = bool(evidence_saved)
    record = {
        "id": str(tool_run_id) if tool_run_id is not None else None,
        "tenant_id": tenant_id,
        "tool_name": tool_name,
        "status": "success" if success else "error",
        "input_params": input_params,
        "output_raw": clipped,
        "output_object_key": output_object_key,
        "started_at": started_at,
        "finished_at": finished_at,
    }
    with _PENDING_TOOL_RUNS_LOCK:
        _PENDING_TOOL_RUNS.setdefault(scan_id, []).append(record)


def _capture_tool_run_evidence(
    tenant_id: str,
    scan_id: str,
    tool_run_id: UUID,
    tool_name: str,
    result: dict[str, Any],
    started_at: datetime,
    finished_at: datetime,
) -> tuple[bool, str | None]:
    """Upload a run's stdout/stderr to object storage and buffer evidence rows.

    The object upload happens immediately (survives a lost buffer); the DB rows
    are drained by :func:`flush_tool_runs` at the phase boundary. Returns
    ``(evidence_saved, stdout_object_key)``. Never raises — a pipeline failure is
    logged and surfaced as ``evidence_saved=False`` (R-5.3.2: the "no evidence"
    state is explicit, not inferred from missing rows).
    """
    try:
        tenant_uuid = UUID(str(tenant_id))
        scan_uuid = UUID(str(scan_id))
    except (ValueError, TypeError):
        return False, None
    try:
        from src.evidence.factory import get_evidence_pipeline
        from src.pipeline.contracts.finding_dto import EvidenceKind

        pipeline = get_evidence_pipeline()
    except Exception:
        logger.warning(
            "evidence_pipeline_unavailable",
            extra={"event": "argus.evidence.pipeline_unavailable", "tool": tool_name},
        )
        return False, None

    rows: list[dict[str, Any]] = []
    stdout_key: str | None = None
    saved = True
    produced_output = False
    for stream_name, text in (
        ("stdout", str(result.get("stdout") or "")),
        ("stderr", str(result.get("stderr") or "")),
    ):
        if not text:
            continue
        produced_output = True
        data = text.encode("utf-8", "replace")
        try:
            dto = pipeline.persist_sync(
                tool_run_id=tool_run_id,
                tenant_id=tenant_uuid,
                scan_id=scan_uuid,
                kind=EvidenceKind.RAW_OUTPUT,
                raw_data=data,
                content_type="text/plain",
            )
        except Exception:
            logger.warning(
                "tool_run_evidence_persist_failed",
                extra={
                    "event": "argus.evidence.persist_failed",
                    "tool": tool_name,
                    "stream": stream_name,
                },
            )
            saved = False
            continue
        rows.append(
            {
                "id": str(dto.id),
                "tenant_id": str(tenant_id),
                "scan_id": str(scan_id),
                "finding_id": None,
                "tool_run_id": str(tool_run_id),
                "object_key": dto.s3_key,
                "kind": dto.kind.value,
                "checksum_algorithm": "sha256",
                "checksum_value": dto.sha256,
                "size_bytes": len(data),
                "content_type": "text/plain",
                "tool_name": tool_name[:128],
                "started_at": started_at,
                "finished_at": finished_at,
                "redaction_applied": dto.redactions_applied > 0,
                "description": f"{stream_name} of {tool_name}"[:500],
            }
        )
        if stream_name == "stdout":
            stdout_key = dto.s3_key

    if rows:
        with _PENDING_EVIDENCE_LOCK:
            _PENDING_EVIDENCE.setdefault(scan_id, []).extend(rows)
    if produced_output and not rows:
        saved = False
    return saved, stdout_key


def drain_pending_evidence(scan_id: str) -> list[dict[str, Any]]:
    """Atomically remove and return buffered evidence rows for a scan."""
    with _PENDING_EVIDENCE_LOCK:
        return _PENDING_EVIDENCE.pop(scan_id, [])


def record_tool_run(
    tenant_id: str | None,
    scan_id: str | None,
    tool_name: str,
    result: dict[str, Any],
    started_at: datetime,
    finished_at: datetime,
    command: str,
) -> None:
    """Public seam for non-``execute_command`` runners (e.g. the recon MCP kal
    executor) to buffer a ToolRun record for the phase-boundary flush.

    Semantics are identical to the internal ``execute_command`` path so tool
    provenance is uniform across runners: ``result`` supplies ``stdout`` and
    ``success``; the record is drained + persisted by :func:`flush_tool_runs`.
    No-op when scan context is missing.
    """
    _schedule_tool_run_record(
        tenant_id, scan_id, tool_name, result, started_at, finished_at, command
    )


def drain_pending_tool_runs(scan_id: str) -> list[dict[str, Any]]:
    """Atomically remove and return buffered ToolRun records for a scan."""
    with _PENDING_TOOL_RUNS_LOCK:
        return _PENDING_TOOL_RUNS.pop(scan_id, [])


async def flush_tool_runs(session: Any, tenant_id: str, scan_id: str) -> int:
    """Persist buffered ToolRun + Evidence records for a scan.

    Rows are added to ``session`` but not committed here — the caller (phase
    runner) owns the transaction boundary. Tool runs are flushed before their
    evidence rows so the ``evidence.tool_run_id`` FK is satisfied. Returns the
    number of ToolRun records flushed.
    """
    records = drain_pending_tool_runs(scan_id)
    evidence_rows = drain_pending_evidence(scan_id)
    if not records and not evidence_rows:
        return 0
    from src.db.models import Evidence, ToolRun

    for rec in records:
        tr_kwargs: dict[str, Any] = {
            "tenant_id": str(rec.get("tenant_id") or tenant_id),
            "scan_id": scan_id,
            "tool_name": str(rec.get("tool_name") or "unknown")[:100],
            "status": str(rec.get("status") or "success")[:50],
            "input_params": rec.get("input_params"),
            "output_raw": rec.get("output_raw") or "",
            "output_object_key": rec.get("output_object_key"),
            "started_at": rec.get("started_at"),
            "finished_at": rec.get("finished_at"),
        }
        # Use the pre-assigned id so evidence.tool_run_id references this row.
        if rec.get("id"):
            tr_kwargs["id"] = str(rec["id"])
        session.add(ToolRun(**tr_kwargs))

    # Flush tool runs first so the FK target exists before evidence inserts.
    if evidence_rows:
        with suppress(Exception):
            await session.flush()
    for ev in evidence_rows:
        session.add(
            Evidence(
                id=str(ev["id"]),
                tenant_id=str(ev.get("tenant_id") or tenant_id),
                scan_id=scan_id,
                finding_id=ev.get("finding_id"),
                tool_run_id=ev.get("tool_run_id"),
                object_key=str(ev.get("object_key") or ""),
                content_type=ev.get("content_type"),
                description=ev.get("description"),
                kind=ev.get("kind"),
                checksum_algorithm=ev.get("checksum_algorithm"),
                checksum_value=ev.get("checksum_value"),
                size_bytes=ev.get("size_bytes"),
                tool_name=ev.get("tool_name"),
                started_at=ev.get("started_at"),
                finished_at=ev.get("finished_at"),
                redaction_applied=ev.get("redaction_applied"),
            )
        )
    logger.info(
        "tool_runs_flushed",
        extra={
            "event": "argus.tool_run.flushed",
            "count": len(records),
            "evidence_count": len(evidence_rows),
        },
    )
    return len(records)


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
                        logger.warning(
                            "mcp_allowlist_denied",
                            extra={
                                "tool": tool_name,
                                "phase": _phase,
                                "reason": _guard_result.reason,
                            },
                        )
            except Exception:
                # Allowlist guard is advisory — never fatal to command execution.
                logger.debug("mcp_allowlist_guard_skipped", exc_info=True)

        if use_cache:
            cache = get_tool_cache()
            key = cache_key_for_execute(command, use_sandbox, timeout_sec)
            cached = cache.get(key)
            if cached is not None:
                cached["execution_time"] = 0.0
                logger.debug(
                    "tool_cache_hit",
                    extra={
                        "event": "argus.tool_cache.hit",
                        "tool": tool_name,
                        "key": key,
                    },
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

        finished_at = datetime.now(UTC)
        # Wave 2 (R-5.3.2): upload this run's raw output to object storage NOW
        # (before the phase-boundary flush), so the artifact survives even if the
        # in-memory buffer is lost to a crash. evidence_saved is recorded on the
        # tool run so "no evidence" is an explicit, visible state.
        tool_run_id = uuid4()
        evidence_saved: bool | None = None
        output_object_key: str | None = None
        if scan_id and tenant_id:
            evidence_saved, output_object_key = _capture_tool_run_evidence(
                tenant_id,
                scan_id,
                tool_run_id,
                tool_name or "unknown",
                result,
                started_at,
                finished_at,
            )

        _schedule_tool_run_record(
            tenant_id=tenant_id,
            scan_id=scan_id,
            tool_name=tool_name or "unknown",
            result=result,
            started_at=started_at,
            finished_at=finished_at,
            command=command,
            tool_run_id=tool_run_id,
            evidence_saved=evidence_saved,
            output_object_key=output_object_key,
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
        info = recovery.build_recovery_info(
            original_tool, original_tool, attempts, from_cache=False
        )
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


def _result(
    success: bool, stdout: str, stderr: str, return_code: int, execution_time: float
) -> dict[str, Any]:
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
