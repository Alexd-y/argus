"""MCP enrichment/correlation helpers for Threat Modeling.

Invokes allowlisted MCP tools to enrich entry points and critical assets.
Records all invocations in MCPInvocationTrace for mcp_trace.json artifact.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from src.recon.mcp.audit import mcp_audit_context, record_mcp_invocation
from src.recon.mcp.client import fetch_url_mcp
from src.recon.mcp.policy import (
    THREAT_MODELING_ALLOWED_TOOLS,
    evaluate_threat_modeling_policy,
    sanitize_args,
)

if TYPE_CHECKING:
    from app.schemas.threat_modeling.schemas import MCPInvocationTrace, ThreatModelInputBundle

logger = logging.getLogger(__name__)

# Max chars for output_summary to avoid huge blobs
OUTPUT_SUMMARY_MAX_CHARS = 2000


def _is_http_url(value: str) -> bool:
    """Check if value looks like an HTTP(S) URL."""
    v = value.strip()
    return (
        v.startswith("http://")
        or v.startswith("https://")
    ) and " " not in v


def _collect_urls_from_bundle(bundle: ThreatModelInputBundle) -> set[str]:
    """Extract URLs from entry points and artifact refs for fetch enrichment."""
    urls: set[str] = set()
    for ep in bundle.entry_points or []:
        if ep.host_or_component and _is_http_url(ep.host_or_component):
            urls.add(ep.host_or_component.strip())
    for ref in bundle.artifact_refs or []:
        if _is_http_url(ref):
            urls.add(ref.strip())
    return urls


def _collect_artifact_paths(bundle: ThreatModelInputBundle) -> list[str]:
    """Extract safe artifact paths for read_file enrichment."""
    paths: list[str] = []
    for ref in bundle.artifact_refs or []:
        if not ref or not isinstance(ref, str):
            continue
        ref = ref.strip()
        if not ref:
            continue
        if ".." in ref or ref.startswith("/") or "\\" in ref:
            continue
        if not all(c.isalnum() or c in "._-/" for c in ref):
            continue
        paths.append(ref)
    return paths


def _invoke_fetch(url: str, timeout: float = 10.0) -> dict:
    """Invoke fetch via MCP. Returns result dict or error placeholder."""
    try:
        return fetch_url_mcp(
            url,
            timeout=timeout,
            operation="enrichment",
            use_threat_modeling_policy=True,
        )
    except Exception:
        logger.warning(
            "mcp_fetch_unavailable",
            extra={
                "url": url[:100] if url else "",
                "error_code": "mcp_fetch_unavailable",
            },
        )
        return {
            "status": 0,
            "body": "",
            "exists": False,
            "notes": "mcp_unavailable",
        }


def _read_file_local(recon_dir: Path, path: str) -> dict:
    """Read file from recon_dir. Returns content summary or error."""
    try:
        base = recon_dir.resolve()
        resolved = (recon_dir / path).resolve()
        try:
            resolved.relative_to(base)
        except ValueError:
            return {"error": "path_traversal_blocked", "lines": 0}
        if not resolved.is_file():
            return {"error": "not_found", "lines": 0}
        text = resolved.read_text(encoding="utf-8", errors="replace")
        lines = text.count("\n") + 1
        return {"lines": lines, "preview": text[:500] + ("..." if len(text) > 500 else "")}
    except OSError:
        return {"error": "read_failed", "lines": 0}


def _truncate_output(value: Any) -> Any:
    """Truncate output for summary."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            out[k] = _truncate_output(v)
        return out
    if isinstance(value, str):
        if len(value) > OUTPUT_SUMMARY_MAX_CHARS:
            return value[:OUTPUT_SUMMARY_MAX_CHARS] + "...[TRUNCATED]"
        return value
    if isinstance(value, list):
        return [_truncate_output(v) for v in value[:20]]
    return value


def enrich_with_mcp(
    bundle: ThreatModelInputBundle,
    mcp_tools: list[str],
    run_id: str,
    job_id: str,
    *,
    recon_dir: Path | None = None,
    timeout: float = 10.0,
) -> list[MCPInvocationTrace]:
    """Enrich threat model bundle with MCP tools.

    Invokes allowlisted tools (fetch, read_file) for correlation/enrichment
    of entry points and critical assets. Records all invocations for
    mcp_trace.json artifact.

    Args:
        bundle: Threat model input bundle.
        mcp_tools: List of tool names to invoke (e.g. ["fetch", "read_file"]).
        run_id: Run identifier.
        job_id: Job identifier.
        recon_dir: Optional recon directory for read_file (artifact paths).
        timeout: Timeout for fetch in seconds.

    Returns:
        List of MCPInvocationTrace for mcp_trace.json.
    """
    from app.schemas.threat_modeling.schemas import MCPInvocationTrace

    traces: list[MCPInvocationTrace] = []
    allowed = {t.strip().lower() for t in mcp_tools if t}
    allowed &= THREAT_MODELING_ALLOWED_TOOLS

    if not allowed:
        logger.info(
            "mcp_enrichment_skipped",
            extra={"reason": "no_allowlisted_tools", "run_id": run_id, "job_id": job_id},
        )
        return traces

    recon_path = Path(recon_dir) if recon_dir else None
    stage = "threat_modeling"

    with mcp_audit_context(
        stage=stage,
        run_id=run_id,
        job_id=job_id,
        recon_dir=str(recon_path) if recon_path else None,
    ):
        if "fetch" in allowed:
            urls = _collect_urls_from_bundle(bundle)
            for url in urls:
                ts_ms = int(time.time() * 1000)
                invocation_id = f"{run_id}:{job_id}:mcp:fetch:{ts_ms}"
                input_summary = {"url": url[:200]}

                result = _invoke_fetch(url, timeout=timeout)
                body = result.get("body", "")
                output_summary = {
                    "status": result.get("status", 0),
                    "exists": result.get("exists", False),
                    "body_preview": body[:500] + ("..." if len(body) > 500 else ""),
                }
                traces.append(
                    MCPInvocationTrace(
                        invocation_id=invocation_id,
                        tool_name="fetch",
                        input_summary=sanitize_args(input_summary),
                        output_summary=_truncate_output(output_summary),
                        timestamp=datetime.now(UTC),
                    )
                )

        if "read_file" in allowed and recon_path and recon_path.is_dir():
            paths = _collect_artifact_paths(bundle)
            for path in paths:
                ts_ms = int(time.time() * 1000)
                invocation_id = f"{run_id}:{job_id}:mcp:read_file:{ts_ms}"
                input_summary = {"path": path}

                decision = evaluate_threat_modeling_policy(
                    tool_name="read_file",
                    operation="enrichment",
                    args={"path": path},
                )
                record_mcp_invocation(
                    tool_name="read_file",
                    operation="enrichment",
                    args={"path": path},
                    allowed=decision.allowed,
                    policy_id=decision.policy_id,
                    decision_reason=decision.reason,
                )

                if not decision.allowed:
                    traces.append(
                        MCPInvocationTrace(
                            invocation_id=invocation_id,
                            tool_name="read_file",
                            input_summary=sanitize_args(input_summary),
                            output_summary={"status": "denied", "reason": decision.reason},
                            timestamp=datetime.now(UTC),
                        )
                    )
                    continue

                result = _read_file_local(recon_path, path)
                traces.append(
                    MCPInvocationTrace(
                        invocation_id=invocation_id,
                        tool_name="read_file",
                        input_summary=sanitize_args(input_summary),
                        output_summary=_truncate_output(result),
                        timestamp=datetime.now(UTC),
                    )
                )

        elif "read_file" in allowed and (not recon_path or not recon_path.is_dir()):
            logger.warning(
                "mcp_read_file_skipped",
                extra={
                    "reason": "recon_dir_unavailable",
                    "run_id": run_id,
                    "job_id": job_id,
                },
            )

    return traces
