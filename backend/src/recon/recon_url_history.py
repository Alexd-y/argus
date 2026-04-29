"""RECON-006 — gau + waybackurls (passive) + katana crawl; dedupe, scope filter, MinIO raw."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from src.core.config import Settings, settings as default_settings
from src.recon.mcp.kal_executor import run_kal_mcp_tool
from src.recon.mcp.policy import evaluate_kal_mcp_policy
from src.recon.recon_runtime import ReconRuntimeConfig
from src.recon.vulnerability_analysis.active_scan.argv_safe import safe_http_url_for_argv

if TYPE_CHECKING:
    from src.orchestration.raw_phase_artifacts import RawPhaseSink

logger = logging.getLogger(__name__)

_STATIC_SUFFIXES: frozenset[str] = frozenset(
    {
        ".css",
        ".js",
        ".mjs",
        ".map",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".webp",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp4",
        ".mp3",
        ".wav",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".bmp",
        ".tiff",
    }
)


def _host_matches_apex(host: str, apex: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    a = (apex or "").strip().lower().rstrip(".")
    if not h or not a:
        return False
    return h == a or h.endswith("." + a)


def url_in_scope(url: str, apex_domain: str, *, scope_strict: bool) -> bool:
    """If strict, keep only http(s) URLs whose hostname is apex or its subdomain."""
    u = (url or "").strip()
    if not u:
        return False
    try:
        parsed = urlparse(u)
    except Exception:
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False
    if not scope_strict:
        return True
    return _host_matches_apex(host, apex_domain)


def is_probably_static_asset_url(url: str) -> bool:
    """True if path looks like a static asset (filtered out from surface list)."""
    try:
        path = (urlparse(url).path or "").lower()
    except Exception:
        return True
    if not path or path.endswith("/"):
        return False
    for suf in _STATIC_SUFFIXES:
        if path.endswith(suf):
            return True
    return False


def _normalize_url_key(url: str) -> str:
    u = url.strip()
    try:
        p = urlparse(u)
        path = p.path or ""
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        netloc = (p.netloc or "").lower()
        return f"{p.scheme.lower()}://{netloc}{path}{('?' + p.query) if p.query else ''}"
    except Exception:
        return u.lower()


def parse_url_lines_from_text(text: str) -> list[str]:
    out: list[str] = []
    for line in (text or "").splitlines():
        s = line.strip()
        if s and (s.startswith("http://") or s.startswith("https://")):
            out.append(s)
    return out


def parse_urls_from_katana_jsonl(stdout: str) -> list[str]:
    found: list[str] = []
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        for key in ("url", "endpoint", "request", "matched"):
            v = obj.get(key)
            if isinstance(v, str) and v.strip().startswith(("http://", "https://")):
                found.append(v.strip())
                break
    return found


def merge_dedupe_urls(
    *batches: list[str],
) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for batch in batches:
        for u in batch:
            key = _normalize_url_key(u)
            if key in seen:
                continue
            seen.add(key)
            ordered.append(u.strip())
    return ordered


def filter_surface_urls(
    urls: list[str],
    *,
    apex_domain: str,
    scope_strict: bool,
    drop_static_assets: bool,
) -> list[str]:
    out: list[str] = []
    for u in urls:
        if drop_static_assets and is_probably_static_asset_url(u):
            continue
        if not url_in_scope(u, apex_domain, scope_strict=scope_strict):
            continue
        out.append(u)
    return merge_dedupe_urls(out)


def build_gau_argv(domain: str) -> list[str]:
    d = (domain or "").strip().lower().rstrip(".")
    if not d or any(c in d for c in (" ", "\n", "\r", "\0", "/")):
        return []
    return ["gau", d]


def build_waybackurls_argv(domain: str) -> list[str]:
    d = (domain or "").strip().lower().rstrip(".")
    if not d or any(c in d for c in (" ", "\n", "\r", "\0", "/")):
        return []
    return ["waybackurls", d]


def build_katana_argv(url: str, *, depth: int, rate_limit_rps: int) -> list[str]:
    u = safe_http_url_for_argv(url)
    if not u:
        return []
    d = max(1, min(10, int(depth)))
    rl = max(1, int(rate_limit_rps))
    return [
        "katana",
        "-u",
        u,
        "-d",
        str(d),
        "-silent",
        "-jsonl",
        "-rate-limit",
        str(rl),
    ]


def _tool_binary_visible(argv0: str, app_settings: Settings) -> bool:
    if app_settings.sandbox_enabled:
        return True
    return shutil.which(argv0) is not None


def _strip_internal(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if k not in ("policy_reason", "minio_keys")}


async def run_recon_url_history_bundle(
    target: str,
    domain: str,
    cfg: ReconRuntimeConfig,
    *,
    raw_sink: RawPhaseSink | None,
    tenant_id: str | None,
    scan_id: str | None,
    app_settings: Settings | None = None,
) -> dict[str, Any]:
    """Run gau, waybackurls, optional katana; return tool_result fragments + url_history_urls."""
    s = app_settings or default_settings
    out: dict[str, Any] = {}
    apex = (domain or "").strip().lower().rstrip(".")
    if not apex:
        logger.info(
            "recon_url_history_skipped",
            extra={"event": "recon_url_history_skipped", "reason": "empty_domain"},
        )
        return out

    timeout_sec = float(max(1, int(getattr(s, "recon_tools_timeout", 300) or 300)))
    scope_strict = bool(getattr(s, "recon_scope_strict", True))

    gau_argv = build_gau_argv(apex)
    wb_argv = build_waybackurls_argv(apex)
    kat_depth = int(cfg.active_depth)
    kat_argv = (
        build_katana_argv(target, depth=kat_depth, rate_limit_rps=cfg.rate_limit_rps)
        if kat_depth > 0
        else []
    )

    async def _run(name: str, argv: list[str]) -> dict[str, Any]:
        if not argv:
            return {
                "success": False,
                "stdout": "",
                "stderr": "skipped",
                "return_code": -1,
                "execution_time": 0.0,
            }
        bin0 = argv[0]
        if not _tool_binary_visible(bin0, s):
            logger.info(
                "recon_url_history_skipped",
                extra={"event": "recon_url_history_skipped", "tool": name, "reason": "binary_missing"},
            )
            return {
                "success": False,
                "stdout": "",
                "stderr": "binary_missing",
                "return_code": -1,
                "execution_time": 0.0,
            }
        pol = evaluate_kal_mcp_policy(
            category="url_history",
            argv=argv,
            password_audit_opt_in=False,
            server_password_audit_enabled=bool(s.kal_allow_password_audit),
        )
        if not pol.allowed:
            logger.info(
                "recon_url_history_skipped",
                extra={"event": "recon_url_history_skipped", "tool": name, "reason": pol.reason},
            )
            return {
                "success": False,
                "stdout": "",
                "stderr": f"policy_denied:{pol.reason}",
                "return_code": -1,
                "execution_time": 0.0,
            }
        seed = target if name == "katana" else apex
        return await asyncio.to_thread(
            run_kal_mcp_tool,
            category="url_history",
            argv=argv,
            target=seed,
            tenant_id=tenant_id,
            scan_id=scan_id,
            password_audit_opt_in=False,
            timeout_sec=timeout_sec,
        )

    gau_r, wb_r, kat_r = await asyncio.gather(
        _run("gau", gau_argv),
        _run("waybackurls", wb_argv),
        _run("katana", kat_argv),
    )

    out["gau"] = _strip_internal(gau_r)
    out["waybackurls"] = _strip_internal(wb_r)
    if kat_depth > 0:
        out["katana"] = _strip_internal(kat_r)

    raw_gau = parse_url_lines_from_text(str(gau_r.get("stdout") or ""))
    raw_wb = parse_url_lines_from_text(str(wb_r.get("stdout") or ""))
    raw_kat = parse_urls_from_katana_jsonl(str(kat_r.get("stdout") or "")) if kat_depth > 0 else []

    merged = merge_dedupe_urls(raw_gau, raw_wb, raw_kat)
    filtered = filter_surface_urls(
        merged,
        apex_domain=apex,
        scope_strict=scope_strict,
        drop_static_assets=True,
    )

    bundle = {
        "apex_domain": apex,
        "scope_strict": scope_strict,
        "counts": {
            "gau_lines": len(raw_gau),
            "waybackurls_lines": len(raw_wb),
            "katana_lines": len(raw_kat),
            "merged": len(merged),
            "filtered": len(filtered),
        },
        "urls": filtered,
    }
    out["url_history_urls"] = bundle

    if raw_sink is not None:
        try:
            await asyncio.to_thread(raw_sink.upload_json, "url_history_urls", bundle)
        except Exception:
            logger.warning(
                "url_history_json_upload_failed",
                extra={"event": "url_history_json_upload_failed"},
            )
        for tool_key, block in (("gau", gau_r), ("waybackurls", wb_r), ("katana", kat_r)):
            if tool_key == "katana" and kat_depth <= 0:
                continue
            if isinstance(block, dict):
                st = block.get("stdout")
                if isinstance(st, str) and len(st) > 0:
                    try:
                        await asyncio.to_thread(raw_sink.upload_text, f"url_history_{tool_key}_stdout", st)
                    except Exception:
                        logger.warning(
                            "url_history_raw_upload_failed",
                            extra={"event": "url_history_raw_upload_failed", "tool": tool_key},
                        )

    return out
