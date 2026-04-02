"""KAL-002 — policy-gated argv execution for MCP + MinIO raw artifact upload."""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlparse

from src.core.config import settings
from src.recon.mcp.policy import evaluate_kal_mcp_policy, normalize_kal_binary
from src.recon.raw_artifact_sink import sink_raw_text, slug_for_artifact_type_component
from src.recon.sandbox_tool_runner import build_sandbox_exec_argv, run_argv_simple_sync
from src.tools.guardrails import validate_target_for_tool

logger = logging.getLogger(__name__)

KAL_MCP_RAW_PHASE = "recon"


def _host_from_target(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    if s.startswith("http://") or s.startswith("https://"):
        return (urlparse(s).hostname or "").strip()
    return s


def run_kal_mcp_tool(
    *,
    category: str,
    argv: list[str],
    target: str,
    tenant_id: str | None,
    scan_id: str | None,
    password_audit_opt_in: bool,
    timeout_sec: float | None = None,
) -> dict[str, Any]:
    """Evaluate KAL policy, optional target guardrails, subprocess (or sandbox exec), MinIO upload."""
    start = time.perf_counter()
    tid = (tenant_id or "").strip() or None
    sid = (scan_id or "").strip() or None
    bin_name = normalize_kal_binary(argv[0]) if argv else ""

    decision = evaluate_kal_mcp_policy(
        category=category,
        argv=argv,
        password_audit_opt_in=password_audit_opt_in,
        server_password_audit_enabled=bool(settings.kal_allow_password_audit),
    )
    if not decision.allowed:
        logger.info(
            "kal_mcp_policy_denied",
            extra={
                "event": "kal_mcp_policy_denied",
                "category": category,
                "reason": decision.reason,
                "policy_id": decision.policy_id,
            },
        )
        return {
            "success": False,
            "stdout": "",
            "stderr": "",
            "return_code": -1,
            "execution_time": 0.0,
            "policy_reason": decision.reason,
            "minio_keys": [],
        }

    host = _host_from_target(target)
    if host:
        vr = validate_target_for_tool(host, bin_name or "kal_mcp")
        if not vr["allowed"]:
            elapsed = time.perf_counter() - start
            logger.info(
                "kal_mcp_target_denied",
                extra={
                    "event": "kal_mcp_target_denied",
                    "category": category,
                    "reason": vr["reason"],
                },
            )
            return {
                "success": False,
                "stdout": "",
                "stderr": vr["reason"],
                "return_code": -1,
                "execution_time": elapsed,
                "policy_reason": "target_validation_failed",
                "minio_keys": [],
            }

    eff_timeout = timeout_sec if timeout_sec is not None else float(max(1, int(settings.recon_tools_timeout)))
    eff_timeout = max(1.0, float(eff_timeout))
    run_parts = build_sandbox_exec_argv(argv, use_sandbox=settings.sandbox_enabled)

    minio_keys: list[str] = []
    exec_out = run_argv_simple_sync(run_parts, timeout_sec=eff_timeout)
    stdout = str(exec_out.get("stdout") or "")
    stderr = str(exec_out.get("stderr") or "")
    rc_raw = exec_out.get("return_code")
    rc = int(rc_raw) if rc_raw is not None else -1
    elapsed = time.perf_counter() - start
    success = bool(exec_out.get("success"))

    cat_slug = slug_for_artifact_type_component(category)
    bin_slug = slug_for_artifact_type_component(bin_name or "tool")
    if tid and sid:
        k_out = sink_raw_text(
            tenant_id=tid,
            scan_id=sid,
            phase=KAL_MCP_RAW_PHASE,
            artifact_type=f"tool_mcp_kal_{cat_slug}_{bin_slug}_stdout",
            text=stdout,
            ext="txt",
        )
        k_err = sink_raw_text(
            tenant_id=tid,
            scan_id=sid,
            phase=KAL_MCP_RAW_PHASE,
            artifact_type=f"tool_mcp_kal_{cat_slug}_{bin_slug}_stderr",
            text=stderr,
            ext="txt",
        )
        for k in (k_out, k_err):
            if k:
                minio_keys.append(k)

    logger.info(
        "kal_mcp_run",
        extra={
            "event": "kal_mcp_run",
            "category": category,
            "tool": bin_name,
            "return_code": rc,
            "duration_sec": round(elapsed, 3),
            "minio_uploaded": bool(minio_keys),
            "scan_id": sid or "",
            "tenant_present": bool(tid),
        },
    )

    return {
        "success": success,
        "stdout": stdout,
        "stderr": stderr,
        "return_code": rc,
        "execution_time": elapsed,
        "policy_reason": None,
        "minio_keys": minio_keys,
    }
