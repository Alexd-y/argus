"""VA-003 — Celery tasks for sandbox VA scanners (single execution path: mcp_runner)."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from src.celery_app import app
from src.core.config import settings
from src.recon.mcp.policy import evaluate_va_active_scan_tool_policy
from src.recon.raw_artifact_sink import (
    sink_raw_json,
    sink_raw_text,
    slug_for_artifact_type_component,
)
from src.recon.vulnerability_analysis.active_scan.dalfox_adapter import (
    build_dalfox_argv,
)
from src.recon.vulnerability_analysis.active_scan.ffuf_adapter import build_ffuf_argv
from src.recon.vulnerability_analysis.active_scan.mcp_runner import (
    run_va_active_scan_sync,
)
from src.recon.vulnerability_analysis.active_scan.nikto_va_adapter import (
    build_nikto_va_argv,
)
from src.recon.vulnerability_analysis.active_scan.nuclei_va_adapter import (
    build_nuclei_va_argv,
)
from src.recon.vulnerability_analysis.active_scan.sqlmap_va_adapter import (
    build_sqlmap_va_argv,
)
from src.recon.vulnerability_analysis.active_scan.testssl_va_adapter import (
    build_sslscan_va_argv,
    build_testssl_va_argv,
)
from src.recon.vulnerability_analysis.active_scan.whatweb_va_adapter import (
    build_whatweb_va_argv,
)
from src.recon.vulnerability_analysis.xsstrike_adapter import (
    resolve_xsstrike_argv,
    validate_xsstrike_target_url,
)

logger = logging.getLogger(__name__)

PHASE_VULN_ANALYSIS = "vuln_analysis"
SANDBOX_WORKDIR = "/home/argus"

_MAX_ARGV_LEN = 64
_MAX_ARG_STRLEN = 4096


def _sanitize_argv_list(argv: list[str]) -> list[str] | None:
    if len(argv) > _MAX_ARGV_LEN:
        return None
    out: list[str] = []
    for a in argv:
        if not isinstance(a, str):
            return None
        if len(a) > _MAX_ARG_STRLEN or "\x00" in a:
            return None
        out.append(a)
    return out


def _validate_custom_argv_prefix(tool: str, argv: list[str]) -> bool:
    """Custom argv must keep the same executable prefix as a safe default build."""
    if tool == "dalfox":
        return bool(argv) and argv[0] == "dalfox"
    if tool == "ffuf":
        return bool(argv) and argv[0] == "ffuf"
    if tool == "nuclei":
        return bool(argv) and argv[0] == "nuclei"
    if tool == "whatweb":
        return bool(argv) and argv[0] == "whatweb"
    if tool == "nikto":
        return bool(argv) and argv[0] == "nikto"
    if tool == "testssl":
        return bool(argv) and argv[0] in ("testssl.sh", "testssl")
    if tool == "sslscan":
        return bool(argv) and argv[0] == "sslscan"
    if tool == "sqlmap":
        return bool(argv) and argv[0] == "sqlmap"
    if tool == "xsstrike":
        base = resolve_xsstrike_argv(use_sandbox=True)
        if not base or len(argv) < len(base):
            return False
        return argv[: len(base)] == base
    return False


def _default_argv_for_tool(tool: str, target: str) -> list[str]:
    ff_wp = (settings.ffuf_va_wordlist_path or "").strip() or None
    if tool == "dalfox":
        return build_dalfox_argv(target)
    if tool == "ffuf":
        return build_ffuf_argv(target, wordlist_path=ff_wp)
    if tool == "nuclei":
        return build_nuclei_va_argv(target)
    if tool == "whatweb":
        return build_whatweb_va_argv(target)
    if tool == "nikto":
        return build_nikto_va_argv(target, maxtime_sec=int(settings.va_nikto_timeout_sec))
    if tool == "testssl":
        return build_testssl_va_argv(target)
    if tool == "sslscan":
        return build_sslscan_va_argv(target)
    if tool == "sqlmap":
        return build_sqlmap_va_argv(target, None)
    if tool == "xsstrike":
        base = resolve_xsstrike_argv(use_sandbox=True)
        if not base:
            return []
        try:
            u = validate_xsstrike_target_url(target)
        except ValueError:
            return []
        return list(base) + ["-u", u, "--skip", "--skip-dom"]
    return []


def _resolve_argv(tool: str, target: str, args: list[str] | None) -> tuple[list[str], str]:
    """Returns (argv, error_reason). error_reason empty on success."""
    if args is None:
        argv = _default_argv_for_tool(tool, target)
        return argv, "" if argv else "empty_argv"
    cleaned = _sanitize_argv_list(list(args))
    if cleaned is None:
        return [], "invalid_args_shape"
    if not _validate_custom_argv_prefix(tool, cleaned):
        return [], "custom_argv_prefix_rejected"
    return cleaned, ""


def _celery_sink_va_run(
    *,
    tool: str,
    tenant_id: str,
    scan_id: str,
    at_base: str,
    result: dict[str, Any],
    celery_run_id: str | None = None,
) -> tuple[str, dict[str, str | None]]:
    err_reason = (result.get("error_reason") or "").strip()
    stderr_text = result.get("stderr") or ""
    if err_reason == "exec_os_error" and not (stderr_text or "").strip():
        stderr_text = (
            "va_active_scan: process_start_failed (binary_missing_or_exec_error)\n"
        )
    keys: dict[str, str | None] = {}
    keys["stdout"] = sink_raw_text(
        tenant_id=tenant_id,
        scan_id=scan_id,
        phase=PHASE_VULN_ANALYSIS,
        artifact_type=f"{at_base}_stdout",
        text=result.get("stdout") or "",
        ext="txt",
    )
    keys["stderr"] = sink_raw_text(
        tenant_id=tenant_id,
        scan_id=scan_id,
        phase=PHASE_VULN_ANALYSIS,
        artifact_type=f"{at_base}_stderr",
        text=stderr_text,
        ext="txt",
    )
    keys["meta"] = sink_raw_json(
        tenant_id=tenant_id,
        scan_id=scan_id,
        phase=PHASE_VULN_ANALYSIS,
        artifact_type=f"{at_base}_meta",
        payload={
            "tool": tool,
            "exit_code": result.get("exit_code"),
            "duration_ms": result.get("duration_ms"),
            "tool_id": result.get("tool_id"),
            "error_reason": err_reason or result.get("error_reason"),
            "celery_run_id": celery_run_id
            or (at_base[-16:] if len(at_base) >= 16 else at_base),
        },
    )
    return stderr_text, keys


def _run_testssl_va_celery_with_sslscan_fallback(
    tenant_id: str,
    scan_id: str,
    target: str,
    args: list[str] | None,
) -> dict[str, Any]:
    """Celery path: testssl.sh then sslscan if no usable stdout / error (KAL-004)."""
    run_slug = uuid.uuid4().hex[:16]
    pol_t = evaluate_va_active_scan_tool_policy(tool_name="testssl")
    if not pol_t.allowed:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "tool_id": "testssl",
            "error_reason": pol_t.reason,
            "artifact_keys": {},
        }

    argv, argv_err = _resolve_argv("testssl", target, args)
    if argv_err:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "tool_id": "testssl",
            "error_reason": argv_err,
            "artifact_keys": {},
        }

    ssl_to = float(settings.va_ssl_probe_timeout_sec)
    merged_keys: dict[str, str | None] = {}

    try:
        result_t = run_va_active_scan_sync(
            tool_name="testssl",
            target=target,
            argv=argv,
            timeout_sec=ssl_to,
            use_sandbox=True,
            sandbox_workdir=SANDBOX_WORKDIR,
        )
    except Exception:
        logger.exception(
            "va_named_tool_task_failed",
            extra={"event": "va_named_tool_task_failed", "tool": "testssl"},
        )
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "tool_id": "testssl",
            "error_reason": "task_error",
            "artifact_keys": {},
        }

    at_t = slug_for_artifact_type_component(f"tool_testssl_celery_{run_slug}_tssl")
    stderr_t, keys_t = _celery_sink_va_run(
        tool="testssl",
        tenant_id=tenant_id,
        scan_id=scan_id,
        at_base=at_t,
        result=result_t,
        celery_run_id=f"{run_slug}_tssl",
    )
    merged_keys.update(keys_t)

    err_t = (result_t.get("error_reason") or "").strip()
    out_t = (result_t.get("stdout") or "").strip()
    if not err_t and out_t:
        out = dict(result_t)
        out["stderr"] = stderr_t
        out["artifact_keys"] = merged_keys
        return out

    pol_s = evaluate_va_active_scan_tool_policy(tool_name="sslscan")
    if not pol_s.allowed:
        out = dict(result_t)
        out["stderr"] = (stderr_t or "") + "\nva_celery: sslscan_fallback_skipped_policy\n"
        out["artifact_keys"] = merged_keys
        return out

    argv_s = build_sslscan_va_argv(target)
    if not argv_s:
        out = dict(result_t)
        out["stderr"] = (stderr_t or "") + "\nva_celery: sslscan_fallback_empty_argv\n"
        out["artifact_keys"] = merged_keys
        return out

    try:
        result_s = run_va_active_scan_sync(
            tool_name="sslscan",
            target=target,
            argv=argv_s,
            timeout_sec=float(settings.va_ssl_probe_timeout_sec),
            use_sandbox=True,
            sandbox_workdir=SANDBOX_WORKDIR,
        )
    except Exception:
        logger.exception(
            "va_named_tool_task_failed",
            extra={"event": "va_named_tool_task_failed", "tool": "sslscan"},
        )
        out = dict(result_t)
        out["stderr"] = stderr_t
        out["artifact_keys"] = merged_keys
        return out

    at_s = slug_for_artifact_type_component(f"tool_sslscan_celery_{run_slug}_sscan")
    stderr_s, keys_s = _celery_sink_va_run(
        tool="sslscan",
        tenant_id=tenant_id,
        scan_id=scan_id,
        at_base=at_s,
        result=result_s,
        celery_run_id=f"{run_slug}_sscan",
    )
    merged_keys.update({f"fallback_{k}": v for k, v in keys_s.items()})

    out = dict(result_s)
    out["stderr"] = stderr_s
    out["artifact_keys"] = merged_keys
    out["tool_id"] = "sslscan"
    return out


def _run_va_tool_with_sink(
    *,
    tool: str,
    tenant_id: str,
    scan_id: str,
    target: str,
    args: list[str] | None,
) -> dict[str, Any]:
    run_slug = uuid.uuid4().hex[:16]
    at_base = slug_for_artifact_type_component(f"tool_{tool}_celery_{run_slug}")

    if tool == "testssl":
        return _run_testssl_va_celery_with_sslscan_fallback(tenant_id, scan_id, target, args)

    if tool == "sqlmap" and not settings.sqlmap_va_enabled:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "tool_id": "sqlmap",
            "error_reason": "sqlmap_va_disabled",
            "artifact_keys": {},
        }

    pol = evaluate_va_active_scan_tool_policy(tool_name=tool)
    if not pol.allowed:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "tool_id": tool,
            "error_reason": pol.reason,
            "artifact_keys": {},
        }

    argv, argv_err = _resolve_argv(tool, target, args)
    if argv_err:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "tool_id": tool,
            "error_reason": argv_err,
            "artifact_keys": {},
        }

    if tool == "whatweb":
        timeout_sec = float(settings.va_whatweb_timeout_sec)
    elif tool == "nikto":
        timeout_sec = float(settings.va_nikto_timeout_sec)
    elif tool == "sslscan":
        timeout_sec = float(settings.va_ssl_probe_timeout_sec)
    else:
        timeout_sec = float(settings.va_active_scan_tool_timeout_sec)
    try:
        result = run_va_active_scan_sync(
            tool_name=tool,
            target=target,
            argv=argv,
            timeout_sec=timeout_sec,
            use_sandbox=True,
            sandbox_workdir=SANDBOX_WORKDIR,
        )
    except Exception:
        logger.exception(
            "va_named_tool_task_failed",
            extra={"event": "va_named_tool_task_failed", "tool": tool},
        )
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "tool_id": tool,
            "error_reason": "task_error",
            "artifact_keys": {},
        }

    stderr_text, keys = _celery_sink_va_run(
        tool=tool,
        tenant_id=tenant_id,
        scan_id=scan_id,
        at_base=at_base,
        result=result,
        celery_run_id=run_slug,
    )

    out = dict(result)
    out["stderr"] = stderr_text
    out["artifact_keys"] = keys
    return out


def _wrap_task(tool: str, tenant_id: str, scan_id: str, target: str, args: list[str] | None) -> dict[str, Any]:
    return _run_va_tool_with_sink(
        tool=tool,
        tenant_id=tenant_id,
        scan_id=scan_id,
        target=target,
        args=args,
    )


@app.task(bind=True, name="argus.va.run_dalfox")
def run_dalfox(
    _self,
    tenant_id: str,
    scan_id: str,
    target: str,
    args: list[str] | None,
) -> dict[str, Any]:
    return _wrap_task("dalfox", tenant_id, scan_id, target, args)


@app.task(bind=True, name="argus.va.run_xsstrike")
def run_xsstrike(
    _self,
    tenant_id: str,
    scan_id: str,
    target: str,
    args: list[str] | None,
) -> dict[str, Any]:
    return _wrap_task("xsstrike", tenant_id, scan_id, target, args)


@app.task(bind=True, name="argus.va.run_ffuf")
def run_ffuf(
    _self,
    tenant_id: str,
    scan_id: str,
    target: str,
    args: list[str] | None,
) -> dict[str, Any]:
    return _wrap_task("ffuf", tenant_id, scan_id, target, args)


@app.task(bind=True, name="argus.va.run_sqlmap")
def run_sqlmap(
    _self,
    tenant_id: str,
    scan_id: str,
    target: str,
    args: list[str] | None,
) -> dict[str, Any]:
    return _wrap_task("sqlmap", tenant_id, scan_id, target, args)


@app.task(bind=True, name="argus.va.run_nuclei")
def run_nuclei(
    _self,
    tenant_id: str,
    scan_id: str,
    target: str,
    args: list[str] | None,
) -> dict[str, Any]:
    return _wrap_task("nuclei", tenant_id, scan_id, target, args)


@app.task(bind=True, name="argus.va.run_whatweb")
def run_whatweb(
    _self,
    tenant_id: str,
    scan_id: str,
    target: str,
    args: list[str] | None,
) -> dict[str, Any]:
    return _wrap_task("whatweb", tenant_id, scan_id, target, args)


@app.task(bind=True, name="argus.va.run_nikto")
def run_nikto(
    _self,
    tenant_id: str,
    scan_id: str,
    target: str,
    args: list[str] | None,
) -> dict[str, Any]:
    return _wrap_task("nikto", tenant_id, scan_id, target, args)


@app.task(bind=True, name="argus.va.run_testssl")
def run_testssl(
    _self,
    tenant_id: str,
    scan_id: str,
    target: str,
    args: list[str] | None,
) -> dict[str, Any]:
    return _wrap_task("testssl", tenant_id, scan_id, target, args)


VA_TOOL_TASK_BY_NAME: dict[str, Any] = {
    "dalfox": run_dalfox,
    "xsstrike": run_xsstrike,
    "ffuf": run_ffuf,
    "sqlmap": run_sqlmap,
    "nuclei": run_nuclei,
    "whatweb": run_whatweb,
    "nikto": run_nikto,
    "testssl": run_testssl,
}
