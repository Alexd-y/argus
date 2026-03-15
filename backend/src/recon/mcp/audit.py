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
) -> dict[str, Any]:
    """Record one MCP invocation event in structured log + JSONL trace."""
    ctx = current_audit_context()
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
