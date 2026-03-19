"""Centralized MCP invocation audit trail with run/job linkage."""

from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from src.recon.mcp.policy import sanitize_args

logger = logging.getLogger(__name__)

MCP_AUDIT_LOG_FILENAME = "mcp_invocation_audit.jsonl"
MCP_AUDIT_META_FILENAME = "mcp_invocation_audit_meta.json"
MCP_TRACE_LOG_FILENAME = "mcp_trace.jsonl"

_AUDIT_CONTEXT: ContextVar[dict[str, Any] | None] = ContextVar(
    "recon_mcp_audit_context",
    default=None,
)


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def mcp_audit_context(
    *,
    stage: str,
    run_id: str,
    job_id: str,
    recon_dir: str | Path | None = None,
    trace_id: str | None = None,
):
    """Set contextual linkage for MCP audit events."""
    resolved_trace_id = trace_id or f"mcp-trace-{uuid4().hex[:12]}"
    context = {
        "stage": stage,
        "run_id": run_id,
        "job_id": job_id,
        "trace_id": resolved_trace_id,
        "run_link": f"recon://runs/{run_id}",
        "job_link": f"recon://jobs/{job_id}",
        "recon_dir": str(recon_dir) if recon_dir else "",
    }
    token = _AUDIT_CONTEXT.set(context)
    try:
        yield context
    finally:
        _AUDIT_CONTEXT.reset(token)


def current_audit_context() -> dict[str, Any]:
    """Return active audit context or empty mapping."""
    context = _AUDIT_CONTEXT.get()
    return dict(context) if context is not None else {}


def write_mcp_audit_meta(recon_dir: str | Path, *, stage: str, run_id: str, job_id: str, trace_id: str) -> Path:
    """Write trace linkage metadata artifact for report evidence."""
    base = Path(recon_dir)
    base.mkdir(parents=True, exist_ok=True)
    out_path = base / MCP_AUDIT_META_FILENAME
    payload = {
        "stage": stage,
        "run_id": run_id,
        "job_id": job_id,
        "trace_id": trace_id,
        "run_link": f"recon://runs/{run_id}",
        "job_link": f"recon://jobs/{job_id}",
        "audit_log_file": MCP_AUDIT_LOG_FILENAME,
        "generated_at": _utc_now(),
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def record_mcp_invocation(
    *,
    tool_name: str,
    operation: str,
    args: dict[str, Any],
    allowed: bool,
    policy_id: str,
    decision_reason: str,
    output_summary: str | dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record one MCP invocation event in structured log + JSONL trace.

    Args:
        output_summary: Optional summary of tool output or error status.
            When dict, stored as JSON string. When omitted, derived from
            allowed/decision_reason during mcp_trace.jsonl generation.
    """
    ctx = current_audit_context()
    out_summary_val: str | None = None
    if output_summary is not None:
        out_summary_val = (
            json.dumps(output_summary, ensure_ascii=False)
            if isinstance(output_summary, dict)
            else str(output_summary)
        )
        if len(out_summary_val) > 10000:
            out_summary_val = out_summary_val[:9997] + "..."

    event = {
        "event_type": "mcp_invocation_audit",
        "timestamp": _utc_now(),
        "stage": str(ctx.get("stage", "unknown") or "unknown"),
        "run_id": str(ctx.get("run_id", "") or ""),
        "job_id": str(ctx.get("job_id", "") or ""),
        "run_link": str(ctx.get("run_link", "") or ""),
        "job_link": str(ctx.get("job_link", "") or ""),
        "trace_id": str(ctx.get("trace_id", "") or ""),
        "tool": str(tool_name or ""),
        "operation": str(operation or ""),
        "policy_id": str(policy_id or ""),
        "allowed": bool(allowed),
        "decision_reason": str(decision_reason or ""),
        "args_sanitized": sanitize_args(args),
    }
    if out_summary_val is not None:
        event["output_summary"] = out_summary_val
    logger.info("mcp_invocation_audit", extra=event)

    recon_dir = str(ctx.get("recon_dir", "") or "")
    if recon_dir:
        try:
            out_path = Path(recon_dir) / MCP_AUDIT_LOG_FILENAME
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with out_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(event, ensure_ascii=False))
                handle.write("\n")
        except OSError:
            logger.warning(
                "mcp_audit_write_failed",
                extra={
                    "event_type": "mcp_audit_write_failed",
                    "trace_id": event["trace_id"],
                    "run_id": event["run_id"],
                    "job_id": event["job_id"],
                },
            )
    return event


def build_mcp_trace_from_audit(recon_dir: str | Path) -> Path | None:
    """Post-process mcp_invocation_audit.jsonl to produce mcp_trace.jsonl with McpTraceEvent schema.

    Each line in mcp_trace.jsonl is a McpTraceEvent JSON with: timestamp, tool_name,
    input_parameters (incl target), output_summary (or error status), run_id, job_id, status.

    Returns path to mcp_trace.jsonl or None if audit file missing/empty.
    """
    base = Path(recon_dir)
    audit_path = base / MCP_AUDIT_LOG_FILENAME
    if not audit_path.exists():
        return None

    trace_path = base / MCP_TRACE_LOG_FILENAME
    events: list[dict[str, Any]] = []

    with audit_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                logger.warning(
                    "mcp_audit_parse_failed",
                    extra={"event_type": "mcp_audit_parse_failed", "line_preview": line[:100]},
                )
                continue

            if raw.get("event_type") != "mcp_invocation_audit":
                continue

            run_id = str(raw.get("run_id", "") or "").strip() or "unknown"
            job_id = str(raw.get("job_id", "") or "").strip() or "unknown"
            allowed = bool(raw.get("allowed", False))
            args_sanitized = raw.get("args_sanitized") or {}
            if not isinstance(args_sanitized, dict):
                args_sanitized = {}

            out_summary = raw.get("output_summary")
            if out_summary is None:
                out_summary = (
                    json.dumps({"status": "denied", "reason": str(raw.get("decision_reason", ""))})
                    if not allowed
                    else None
                )

            ts_str = str(raw.get("timestamp", ""))
            try:
                ts_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                ts_dt = datetime.now(UTC)

            trace_event = {
                "timestamp": ts_dt.isoformat(),
                "tool_name": str(raw.get("tool", "") or "unknown"),
                "input_parameters": args_sanitized,
                "output_summary": out_summary,
                "run_id": run_id,
                "job_id": job_id,
                "status": "success" if allowed else "error",
            }
            events.append(trace_event)

    if not events:
        return None

    try:
        base.mkdir(parents=True, exist_ok=True)
        with trace_path.open("w", encoding="utf-8", newline="\n") as handle:
            for ev in events:
                handle.write(json.dumps(ev, ensure_ascii=False))
                handle.write("\n")
    except OSError:
        logger.warning(
            "mcp_trace_write_failed",
            extra={"event_type": "mcp_trace_write_failed", "path": str(trace_path)},
        )
        return None

    return trace_path
