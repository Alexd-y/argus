"""RECON-007 — query-parameter harvest from URL lists; optional JS fetch + linkfinder / regex endpoints."""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlparse

import httpx

from src.core.config import Settings, settings as default_settings
from src.recon.mcp.kal_executor import run_kal_mcp_tool
from src.recon.mcp.policy import evaluate_kal_mcp_policy
from src.recon.recon_runtime import ReconRuntimeConfig
from src.recon.recon_url_history import (
    merge_dedupe_urls,
    parse_url_lines_from_text,
    parse_urls_from_katana_jsonl,
)
from src.recon.vulnerability_analysis.active_scan.argv_safe import safe_http_url_for_argv
from src.tools.guardrails import validate_target_for_tool

if TYPE_CHECKING:
    from src.orchestration.raw_phase_artifacts import RawPhaseSink

logger = logging.getLogger(__name__)


def _cfg_int(settings_obj: Any, attr: str, default: int) -> int:
    """Read positive-int setting; 0 is preserved (no ``or default`` coercion)."""
    v = getattr(settings_obj, attr, default)
    if v is None:
        return default
    return int(v)


_JS_SUFFIXES: tuple[str, ...] = (".js", ".mjs")
_ENDPOINT_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"""['"`](/[a-zA-Z0-9_\-./~?&=%+]{1,512})['"`]"""),
    re.compile(r"""(?i)\bfetch\s*\(\s*["']([^"']{1,512})["']"""),
    re.compile(r"""(?i)\baxios\.(?:get|post)\s*\(\s*["']([^"']{1,512})["']"""),
    re.compile(r"""(?i)url\s*:\s*["']([^"']{1,512})["']"""),
)


def _host_ok_for_fetch(url: str, tool_tag: str) -> bool:
    u = safe_http_url_for_argv(url)
    if not u:
        return False
    try:
        host = (urlparse(u).hostname or "").strip()
    except Exception:
        return False
    if not host:
        return False
    vr = validate_target_for_tool(host, tool_tag)
    return bool(vr.get("allowed"))


def merged_http_urls_from_tool_results(tool_results: dict[str, Any]) -> list[str]:
    """Union url_history_urls + gau / waybackurls / katana stdout if present."""
    batches: list[list[str]] = []
    bundle = tool_results.get("url_history_urls")
    if isinstance(bundle, dict):
        raw = bundle.get("urls")
        if isinstance(raw, list):
            batches.append([str(u).strip() for u in raw if isinstance(u, str) and str(u).strip()])
    for key, parser in (
        ("gau", parse_url_lines_from_text),
        ("waybackurls", parse_url_lines_from_text),
        ("katana", parse_urls_from_katana_jsonl),
    ):
        block = tool_results.get(key)
        if isinstance(block, dict):
            st = block.get("stdout")
            if isinstance(st, str) and st.strip():
                batches.append(parser(st))
    if not batches:
        return []
    return merge_dedupe_urls(*batches)


def extract_query_param_names(urls: list[str], *, max_urls: int) -> dict[str, Any]:
    """Unique query keys from http(s) URLs (urllib.parse_qsl)."""
    seen_keys: set[str] = set()
    urls_with_query = 0
    capped = urls[: max(0, int(max_urls))]
    for u in capped:
        try:
            parsed = urlparse((u or "").strip())
        except Exception:
            continue
        if not parsed.query:
            continue
        urls_with_query += 1
        try:
            pairs = parse_qsl(parsed.query, keep_blank_values=False)
        except Exception:
            continue
        for k, _v in pairs:
            nk = (k or "").strip()
            if nk:
                seen_keys.add(nk)
    return {
        "unique_names": sorted(seen_keys),
        "urls_examined": len(capped),
        "urls_with_query": urls_with_query,
    }


def is_js_asset_url(url: str) -> bool:
    try:
        path = (urlparse(url).path or "").lower()
    except Exception:
        return False
    return path.endswith(_JS_SUFFIXES)


def extract_endpoints_regex(js_text: str) -> list[str]:
    """Lightweight linkfinder-style hints from JS source (relative paths and common API strings)."""
    found: set[str] = set()
    text = js_text or ""
    for rx in _ENDPOINT_RES:
        for m in rx.finditer(text):
            g = (m.group(1) or "").strip()
            if not g or len(g) > 512:
                continue
            if g.startswith(("http://", "https://", "//")):
                continue
            if g.startswith("/") or "api/" in g.lower():
                found.add(g[:512])
    return sorted(found)


def _strip_internal(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if k not in ("policy_reason", "minio_keys")}


def _tool_visible(argv0: str, app_settings: Settings) -> bool:
    if app_settings.sandbox_enabled:
        return True
    return shutil.which(argv0) is not None


def _run_linkfinder_file(
    file_path: str,
    sample_url: str,
    *,
    tenant_id: str | None,
    scan_id: str | None,
    timeout_sec: float,
) -> dict[str, Any]:
    argv = ["linkfinder", "-i", file_path, "-o", "cli"]
    pol = evaluate_kal_mcp_policy(
        category="js_analysis",
        argv=argv,
        password_audit_opt_in=False,
        server_password_audit_enabled=False,
    )
    if not pol.allowed:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"policy_denied:{pol.reason}",
            "return_code": -1,
            "execution_time": 0.0,
        }
    return run_kal_mcp_tool(
        category="js_analysis",
        argv=argv,
        target=sample_url,
        tenant_id=tenant_id,
        scan_id=scan_id,
        password_audit_opt_in=False,
        timeout_sec=timeout_sec,
    )


def _run_unfurl_url(
    url: str,
    *,
    tenant_id: str | None,
    scan_id: str | None,
    timeout_sec: float,
) -> dict[str, Any]:
    argv = ["unfurl", url]
    pol = evaluate_kal_mcp_policy(
        category="js_analysis",
        argv=argv,
        password_audit_opt_in=False,
        server_password_audit_enabled=False,
    )
    if not pol.allowed:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"policy_denied:{pol.reason}",
            "return_code": -1,
            "execution_time": 0.0,
        }
    return run_kal_mcp_tool(
        category="js_analysis",
        argv=argv,
        target=url,
        tenant_id=tenant_id,
        scan_id=scan_id,
        password_audit_opt_in=False,
        timeout_sec=min(timeout_sec, 60.0),
    )


async def run_recon_js_analysis_bundle(
    target: str,
    domain: str,
    tool_results: dict[str, Any],
    cfg: ReconRuntimeConfig,
    *,
    raw_sink: RawPhaseSink | None,
    tenant_id: str | None,
    scan_id: str | None,
    app_settings: Settings | None = None,
) -> dict[str, Any]:
    """Parameter names from merged URLs; optional rate-limited JS fetch + linkfinder / regex. Fail-soft."""
    s = app_settings or default_settings
    out: dict[str, Any] = {}

    merged = merged_http_urls_from_tool_results(tool_results)
    max_merge = max(100, min(100_000, _cfg_int(s, "recon_js_max_merged_urls", 20000)))
    merged = merged[:max_merge]

    param_block = extract_query_param_names(merged, max_urls=max_merge)
    js_urls = [u for u in merged if is_js_asset_url(u)]
    max_js_list = max(0, min(500, _cfg_int(s, "recon_js_max_js_urls", 200)))
    if max_js_list > 0:
        js_urls = js_urls[:max_js_list]
    else:
        js_urls = []

    bundle: dict[str, Any] = {
        "apex_domain": (domain or "").strip().lower().rstrip("."),
        "target_url_present": bool((target or "").strip()),
        "query_params": param_block,
        "js_urls": js_urls,
        "counts": {
            "merged_urls": len(merged),
            "js_urls": len(js_urls),
        },
        "deep": None,
    }

    timeout_sec = float(max(1, int(getattr(s, "recon_tools_timeout", 300) or 300)))
    max_dl = max(0, min(100, _cfg_int(s, "recon_js_max_downloads", 15)))
    max_bytes = max(4096, min(10_485_760, _cfg_int(s, "recon_js_max_response_bytes", 1_048_576)))
    linkfinder_on = bool(getattr(s, "recon_js_linkfinder_enabled", True))
    unfurl_on = bool(getattr(s, "recon_js_unfurl_enabled", False))
    rps = max(1, int(cfg.rate_limit_rps))

    deep: dict[str, Any] = {
        "fetched": [],
        "regex_endpoints": [],
        "linkfinder_blocks": [],
        "unfurl_blocks": [],
        "skipped_reasons": [],
    }

    fetch_targets = [u for u in js_urls if _host_ok_for_fetch(u, "recon_js_fetch")][:max_dl]

    async def _download_one(client: httpx.AsyncClient, url: str) -> tuple[str, str, int, str]:
        u = safe_http_url_for_argv(url)
        if not u:
            return url, "", -1, "invalid_url"
        try:
            resp = await client.get(u)
            text = resp.text or ""
            if len(text) > max_bytes:
                text = text[:max_bytes]
            return u, text, resp.status_code, ""
        except Exception as ex:
            return u, "", -1, type(ex).__name__

    if max_dl > 0 and fetch_targets:
        delay = 1.0 / float(rps)
        limits = httpx.Limits(max_connections=4, max_keepalive_connections=2)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(45.0),
            follow_redirects=True,
            headers={"User-Agent": "ARGUS-ReconJS/1.0"},
            limits=limits,
        ) as client:
            for u in fetch_targets:
                await asyncio.sleep(delay)
                url_norm, body, status, err = await _download_one(client, u)
                entry = {"url": url_norm, "status": status, "bytes": len(body), "error": err}
                deep["fetched"].append(entry)
                if body and status > 0:
                    for ep in extract_endpoints_regex(body):
                        deep["regex_endpoints"].append(ep)
                    if linkfinder_on and _tool_visible("linkfinder", s) and _host_ok_for_fetch(url_norm, "linkfinder"):

                        def _lf_run() -> dict[str, Any]:
                            path: Path | None = None
                            try:
                                fd, name = tempfile.mkstemp(suffix=".js", prefix="argus_js_")
                                path = Path(name)
                                with open(fd, "wb") as f:
                                    f.write(body.encode("utf-8", errors="replace"))
                                return _run_linkfinder_file(
                                    str(path),
                                    url_norm,
                                    tenant_id=tenant_id,
                                    scan_id=scan_id,
                                    timeout_sec=min(timeout_sec, 120.0),
                                )
                            except Exception:
                                return {
                                    "success": False,
                                    "stdout": "",
                                    "stderr": "linkfinder_temp_failed",
                                    "return_code": -1,
                                    "execution_time": 0.0,
                                }
                            finally:
                                if path is not None:
                                    try:
                                        path.unlink(missing_ok=True)
                                    except OSError:
                                        pass

                        lf = await asyncio.to_thread(_lf_run)
                        deep["linkfinder_blocks"].append(
                            {
                                "url": url_norm,
                                "result": _strip_internal(lf),
                            },
                        )
                if raw_sink is not None and body and status > 0:
                    try:
                        slug = str(abs(hash(url_norm)))[:12]
                        await asyncio.to_thread(
                            raw_sink.upload_text,
                            f"js_analysis_fetch_{slug}",
                            body,
                            "js",
                        )
                    except Exception:
                        logger.warning(
                            "js_analysis_raw_upload_failed",
                            extra={"event": "js_analysis_raw_upload_failed"},
                        )

    elif max_dl > 0:
        deep["skipped_reasons"].append("no_in_scope_js_urls")

    # Dedupe regex endpoints
    deep["regex_endpoints"] = sorted(frozenset(deep["regex_endpoints"]))

    if unfurl_on and _tool_visible("unfurl", s):
        uf_cap = max(0, min(30, _cfg_int(s, "recon_js_unfurl_max_urls", 10)))
        sample = [u for u in merged if urlparse(u).query][:uf_cap]
        for u in sample:
            su = safe_http_url_for_argv(u)
            if not su or not _host_ok_for_fetch(su, "unfurl"):
                continue

            def _uf() -> dict[str, Any]:
                return _run_unfurl_url(
                    su,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    timeout_sec=timeout_sec,
                )

            unf = await asyncio.to_thread(_uf)
            deep["unfurl_blocks"].append({"url": su, "result": _strip_internal(unf)})
    elif unfurl_on:
        deep["skipped_reasons"].append("unfurl_binary_missing")

    bundle["deep"] = deep
    out["js_analysis"] = bundle

    if raw_sink is not None:
        try:
            await asyncio.to_thread(raw_sink.upload_json, "js_analysis", bundle)
        except Exception:
            logger.warning(
                "js_analysis_json_upload_failed",
                extra={"event": "js_analysis_json_upload_failed"},
            )
        for i, block in enumerate(deep.get("linkfinder_blocks") or []):
            res = block.get("result") if isinstance(block, dict) else None
            if isinstance(res, dict):
                st = res.get("stdout")
                if isinstance(st, str) and st.strip():
                    try:
                        await asyncio.to_thread(
                            raw_sink.upload_text,
                            f"js_analysis_linkfinder_{i}",
                            st,
                            "txt",
                        )
                    except Exception:
                        logger.warning(
                            "js_analysis_linkfinder_upload_failed",
                            extra={"event": "js_analysis_linkfinder_upload_failed", "index": i},
                        )

    return out
