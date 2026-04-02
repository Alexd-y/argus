"""RECON-004 — httpx + whatweb + nuclei (tech-only) for active/full recon; MinIO via KAL executor."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from src.core.config import Settings, settings as default_settings
from src.recon.mcp.kal_executor import run_kal_mcp_tool
from src.recon.mcp.policy import evaluate_kal_mcp_policy, evaluate_va_active_scan_tool_policy
from src.recon.recon_runtime import ReconRuntimeConfig
from src.recon.vulnerability_analysis.active_scan.nuclei_va_adapter import parse_nuclei_stdout
from src.recon.vulnerability_analysis.active_scan.whatweb_va_adapter import (
    build_whatweb_va_argv,
    parse_whatweb_stdout,
    parse_whatweb_to_tech_stack,
)
from src.recon.vulnerability_analysis.active_scan.argv_safe import safe_http_url_for_argv

if TYPE_CHECKING:
    from src.orchestration.raw_phase_artifacts import RawPhaseSink

logger = logging.getLogger(__name__)


def build_recon_httpx_argv(url: str, rate_limit_rps: int) -> list[str]:
    """ProjectDiscovery httpx: JSON lines, tech-detect, rate limit from recon config."""
    u = safe_http_url_for_argv(url)
    if not u:
        return []
    rl = max(1, int(rate_limit_rps))
    return [
        "httpx",
        "-u",
        u,
        "-json",
        "-silent",
        "-tech-detect",
        "-status-code",
        "-title",
        "-server",
        "-content-type",
        "-follow-redirects",
        "-rate-limit",
        str(rl),
        "-timeout",
        "15",
    ]


def build_recon_nuclei_tech_argv(
    url: str,
    *,
    rate_limit_rps: int,
    tags_csv: str,
    templates_csv: str,
) -> list[str]:
    """Nuclei constrained to tech discovery: JSONL, no interactsh/update; tags or -t from env."""
    u = safe_http_url_for_argv(url)
    if not u:
        return []
    rl = max(1, int(rate_limit_rps))
    argv: list[str] = [
        "nuclei",
        "-u",
        u,
        "-jsonl",
        "-duc",
        "-ni",
        "-rate-limit",
        str(rl),
        "-silent",
    ]
    tpl = (templates_csv or "").strip()
    tags = (tags_csv or "").strip()
    if tpl:
        added_tpl = False
        for seg in tpl.split(","):
            s = seg.strip()
            if s and not _nuclei_template_segment_rejected(s):
                argv.extend(["-t", s])
                added_tpl = True
        if not added_tpl:
            argv.extend(["-tags", tags or "tech"])
    elif tags:
        argv.extend(["-tags", tags])
    else:
        argv.extend(["-tags", "tech"])
    return argv


def _nuclei_template_segment_rejected(seg: str) -> bool:
    s = seg.strip()
    if not s or len(s) > 1024:
        return True
    if ".." in s or "\n" in s or "\r" in s or "\0" in s:
        return True
    return False


def _tool_binary_visible(argv0: str, app_settings: Settings) -> bool:
    if app_settings.sandbox_enabled:
        return True
    return shutil.which(argv0) is not None


def _host_from_target_url(url: str) -> str:
    u = safe_http_url_for_argv(url)
    if not u:
        return ""
    h = (urlparse(u).hostname or "").strip().lower()
    return h


def _parse_httpx_tech_lines(stdout: str) -> list[tuple[str, str, str]]:
    """(host_key, technology_name, source_label)."""
    out: list[tuple[str, str, str]] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        raw_url = str(obj.get("url") or obj.get("input") or "").strip()
        host = (str(obj.get("host") or "").strip().lower())
        if not host and raw_url:
            try:
                host = (urlparse(raw_url).hostname or "").strip().lower()
            except Exception:
                host = ""
        if not host:
            host = "_unknown"
        tech = obj.get("tech") or obj.get("technologies") or []
        if isinstance(tech, list):
            for t in tech:
                if isinstance(t, str) and t.strip():
                    out.append((host, t.strip()[:512], "httpx"))
        ws = obj.get("webserver") or obj.get("server")
        if isinstance(ws, str) and ws.strip():
            out.append((host, f"server:{ws.strip()[:256]}", "httpx"))
    return out


def _parse_nuclei_tech_lines(stdout: str) -> list[tuple[str, str, str]]:
    rows = parse_nuclei_stdout(stdout or "")
    out: list[tuple[str, str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        matched = ""
        for key in ("matched-at", "matched_at", "url", "host"):
            v = row.get(key)
            if isinstance(v, str) and v.strip():
                matched = v.strip()
                break
        host = ""
        if matched:
            try:
                host = (urlparse(matched).hostname or "").strip().lower()
            except Exception:
                host = ""
        if not host:
            host = "_unknown"
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        name = ""
        if isinstance(info, dict):
            n = info.get("name")
            if isinstance(n, str) and n.strip():
                name = n.strip()
        if not name:
            tid = row.get("template-id") or row.get("template_id") or row.get("id")
            if isinstance(tid, str) and tid.strip():
                name = tid.strip()
        if name:
            out.append((host, name[:512], "nuclei_tech"))
    return out


def _whatweb_host(parsed: dict[str, Any] | None, fallback: str) -> str:
    if not isinstance(parsed, dict):
        return fallback
    t = parsed.get("target")
    if isinstance(t, str) and t.strip():
        try:
            h = (urlparse(t.strip()).hostname or "").strip().lower()
            if h:
                return h
        except Exception:
            pass
    return fallback


def _entries_from_whatweb(parsed: dict[str, Any] | None, host: str) -> list[tuple[str, str, str]]:
    ts = parse_whatweb_to_tech_stack(parsed)
    out: list[tuple[str, str, str]] = []
    for e in ts.get("entries") or []:
        if not isinstance(e, dict):
            continue
        tech = e.get("technology")
        if isinstance(tech, str) and tech.strip():
            out.append((host or "_unknown", tech.strip()[:512], "whatweb"))
    for label_key in ("web_server", "os", "cms"):
        s = ts.get(label_key)
        if isinstance(s, str) and s.strip():
            for part in s.split(";"):
                p = part.strip()
                if p:
                    out.append((host or "_unknown", p[:512], "whatweb"))
    for lst_key in ("frameworks", "js_libraries"):
        lst = ts.get(lst_key)
        if isinstance(lst, list):
            for it in lst:
                if isinstance(it, str) and it.strip():
                    out.append((host or "_unknown", it.strip()[:512], "whatweb"))
    return out


def merge_http_probe_tech_stack(
    *,
    httpx_stdout: str,
    whatweb_stdout: str,
    nuclei_stdout: str,
    primary_host: str,
) -> dict[str, Any]:
    """Per-host merged technologies + flat list (additive shape for downstream)."""
    triples: list[tuple[str, str, str]] = []
    triples.extend(_parse_httpx_tech_lines(httpx_stdout))
    w_merged = parse_whatweb_stdout(whatweb_stdout or "")
    whost = _whatweb_host(w_merged, primary_host)
    triples.extend(_entries_from_whatweb(w_merged, whost))
    triples.extend(_parse_nuclei_tech_lines(nuclei_stdout))

    by_host: dict[str, dict[str, Any]] = {}
    index: dict[tuple[str, str], dict[str, Any]] = {}

    for host, name, src in triples:
        raw_name = name.strip()
        if not raw_name:
            continue
        hk = host or "_unknown"
        nk = raw_name.lower()
        key = (hk, nk)
        entry = by_host.setdefault(hk, {"host": hk, "technologies": []})
        tech_list: list[dict[str, Any]] = entry["technologies"]
        if key not in index:
            row = {"name": raw_name, "version": None, "sources": [src]}
            tech_list.append(row)
            index[key] = row
        else:
            row = index[key]
            if src not in row["sources"]:
                row["sources"].append(src)

    flat: list[dict[str, Any]] = []
    for hk, blob in sorted(by_host.items()):
        for t in blob.get("technologies") or []:
            if isinstance(t, dict) and t.get("name"):
                flat.append({
                    "host": hk,
                    "name": t["name"],
                    "version": t.get("version"),
                    "sources": list(t.get("sources") or []),
                })

    return {
        "by_host": {k: v for k, v in sorted(by_host.items())},
        "technologies": flat,
        "tech_stack": {
            "primary_host": primary_host,
            "summary_hosts": list(by_host.keys()),
            "merged_entry_count": len(flat),
        },
    }


async def run_recon_http_probe_bundle(
    target: str,
    cfg: ReconRuntimeConfig,
    *,
    raw_sink: "RawPhaseSink | None",
    tenant_id: str | None,
    scan_id: str | None,
    app_settings: Settings | None = None,
) -> dict[str, Any]:
    """Run httpx, whatweb, nuclei (tech); policy/binary gates; return tool_result fragments."""
    s = app_settings or default_settings
    out: dict[str, Any] = {}
    safe_url = safe_http_url_for_argv(target)
    if not safe_url:
        logger.info("recon_http_probe_skipped", extra={"event": "recon_http_probe_skipped", "reason": "invalid_target_url"})
        return out

    ph = _host_from_target_url(target)
    timeout_sec = float(max(1, int(getattr(s, "recon_tools_timeout", 300) or 300)))
    ww_timeout = float(getattr(s, "va_whatweb_timeout_sec", 90.0) or 90.0)
    ww_timeout = max(timeout_sec, ww_timeout)

    httpx_argv = build_recon_httpx_argv(target, cfg.rate_limit_rps)
    whatweb_argv = build_whatweb_va_argv(target)
    nuclei_argv = build_recon_nuclei_tech_argv(
        target,
        rate_limit_rps=cfg.rate_limit_rps,
        tags_csv=cfg.nuclei_tech_tags_csv,
        templates_csv=cfg.nuclei_tech_templates_csv,
    )

    async def _run_tool(name: str, category: str, argv: list[str], to: float) -> dict[str, Any]:
        if not argv:
            return {
                "success": False,
                "stdout": "",
                "stderr": "invalid_argv",
                "return_code": -1,
                "execution_time": 0.0,
            }
        bin0 = argv[0]
        if not _tool_binary_visible(bin0, s):
            logger.info(
                "recon_http_probe_skipped",
                extra={"event": "recon_http_probe_skipped", "tool": name, "reason": "binary_missing"},
            )
            return {
                "success": False,
                "stdout": "",
                "stderr": "binary_missing",
                "return_code": -1,
                "execution_time": 0.0,
            }
        pol = evaluate_kal_mcp_policy(
            category=category,
            argv=argv,
            password_audit_opt_in=False,
            server_password_audit_enabled=bool(s.kal_allow_password_audit),
        )
        if not pol.allowed:
            logger.info(
                "recon_http_probe_skipped",
                extra={"event": "recon_http_probe_skipped", "tool": name, "reason": pol.reason},
            )
            return {
                "success": False,
                "stdout": "",
                "stderr": f"policy_denied:{pol.reason}",
                "return_code": -1,
                "execution_time": 0.0,
            }
        if name == "nuclei_tech":
            va = evaluate_va_active_scan_tool_policy(tool_name="nuclei")
            if not va.allowed:
                logger.info(
                    "recon_http_probe_skipped",
                    extra={"event": "recon_http_probe_skipped", "tool": name, "reason": va.reason},
                )
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"policy_denied:{va.reason}",
                    "return_code": -1,
                    "execution_time": 0.0,
                }
        return await asyncio.to_thread(
            run_kal_mcp_tool,
            category=category,
            argv=argv,
            target=target,
            tenant_id=tenant_id,
            scan_id=scan_id,
            password_audit_opt_in=False,
            timeout_sec=to,
        )

    hx_r, ww_r, nuc_r = await asyncio.gather(
        _run_tool("httpx", "web_fingerprinting", httpx_argv, timeout_sec),
        _run_tool("whatweb", "web_fingerprinting", whatweb_argv, ww_timeout),
        _run_tool("nuclei_tech", "api_testing", nuclei_argv, timeout_sec),
    )

    def _strip_internal(d: dict[str, Any]) -> dict[str, Any]:
        d2 = {k: v for k, v in d.items() if k not in ("policy_reason", "minio_keys")}
        return d2

    out["httpx"] = _strip_internal(hx_r)
    out["whatweb"] = _strip_internal(ww_r)
    out["nuclei_tech"] = _strip_internal(nuc_r)

    merged = merge_http_probe_tech_stack(
        httpx_stdout=str(hx_r.get("stdout") or ""),
        whatweb_stdout=str(ww_r.get("stdout") or ""),
        nuclei_stdout=str(nuc_r.get("stdout") or ""),
        primary_host=ph,
    )
    out["http_probe_tech_stack"] = merged

    if raw_sink is not None:
        try:
            await asyncio.to_thread(raw_sink.upload_json, "http_probe_tech_stack", merged)
        except Exception:
            logger.warning("http_probe_tech_stack_upload_failed", extra={"event": "http_probe_tech_stack_upload_failed"})

    return out
