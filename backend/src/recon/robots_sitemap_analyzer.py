"""VDF-008 — Fetch robots.txt, sitemap(s), security.txt; parse + MinIO (recon phase).

Extended stage (VA_ROBOTS_EXTENDED_PIPELINE): shallow gospider/parsero via sandbox when enabled.
Heavy fuzz stays off by default.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from src.core.config import settings
from src.recon.raw_artifact_sink import sink_raw_json, sink_raw_text

logger = logging.getLogger(__name__)

_SENSITIVE_SEGMENTS = frozenset(
    {
        "admin",
        "wp-admin",
        "wp-login",
        "phpmyadmin",
        "api",
        "internal",
        "private",
        "backup",
        "config",
        ".env",
        "debug",
        "test",
        "staging",
        "graphql",
        "actuator",
        "swagger",
        "jenkins",
    }
)
_MAX_BODY = 512_000
_FETCH_TIMEOUT = 15.0
_USER_AGENT = "ArgusReconBot/1.0 (+https://example.invalid/bot)"


def _origin_from_url(url: str) -> str | None:
    u = (url or "").strip()
    if not u.startswith(("http://", "https://")):
        return None
    p = urlparse(u)
    if not p.scheme or not p.netloc:
        return None
    return f"{p.scheme}://{p.netloc}"


def _parse_robots_rules(text: str) -> tuple[list[str], list[str], list[str]]:
    disallow: list[str] = []
    allow: list[str] = []
    sitemaps: list[str] = []
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("disallow:"):
            p = line.split(":", 1)[1].strip()
            if p:
                disallow.append(p[:512])
        elif low.startswith("allow:"):
            p = line.split(":", 1)[1].strip()
            if p:
                allow.append(p[:512])
        elif low.startswith("sitemap:"):
            u = line.split(":", 1)[1].strip()
            if u:
                sitemaps.append(u[:1024])
    return disallow[:256], allow[:128], sitemaps[:64]


def _loc_urls_from_sitemap(text: str) -> list[str]:
    return [
        u.strip()
        for u in re.findall(r"<loc>\s*([^<]+)\s*</loc>", text or "", flags=re.I)
        if u.strip()
    ][:5000]


def _sensitive_hints_from_paths(paths: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for p in paths:
        low = (p or "").lower()
        for seg in _SENSITIVE_SEGMENTS:
            if seg in low and seg not in seen:
                seen.add(seg)
                out.append(seg)
        if len(out) >= 24:
            break
    return out


async def _fetch_text(client: httpx.AsyncClient, url: str) -> tuple[int, str]:
    try:
        r = await client.get(url, follow_redirects=True)
        body = (r.text or "")[:_MAX_BODY]
        return int(r.status_code), body
    except Exception:
        return 0, ""


async def analyze_robots_sitemap_and_sink(
    base_url: str,
    *,
    tenant_id: str | None,
    scan_id: str | None,
) -> dict[str, Any]:
    """
    Fetch well-known URLs from origin of *base_url*; write raw + summary JSON to MinIO (phase=recon).
    Returns summary dict (safe for logs; no bodies).
    """
    origin = _origin_from_url(base_url)
    tid = (tenant_id or "").strip()
    sid = (scan_id or "").strip()
    empty_out: dict[str, Any] = {
        "origin": origin or "",
        "robots_status": 0,
        "sitemap_status": 0,
        "security_txt_status": 0,
        "sitemap_index_status": 0,
        "disallow_count": 0,
        "allow_count": 0,
        "sitemap_loc_count": 0,
        "sensitive_hints": [],
    }
    if not origin or not tid or not sid:
        return empty_out

    robots_url = urljoin(origin + "/", "robots.txt")
    sitemap_url = urljoin(origin + "/", "sitemap.xml")
    sitemap_index_url = urljoin(origin + "/", "sitemap_index.xml")
    sec_url = urljoin(origin + "/", ".well-known/security.txt")

    headers = {"User-Agent": _USER_AGENT}
    async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT, headers=headers) as client:
        rs, robots_body = await _fetch_text(client, robots_url)
        ss, sm_body = await _fetch_text(client, sitemap_url)
        sis, sidx_body = await _fetch_text(client, sitemap_index_url)
        sts, sec_body = await _fetch_text(client, sec_url)

    disallow, allow, sm_hints = _parse_robots_rules(robots_body)
    locs = _loc_urls_from_sitemap(sm_body)
    if not locs and sidx_body.strip():
        locs = _loc_urls_from_sitemap(sidx_body)

    path_samples = list(disallow[:48]) + list(allow[:16])
    sensitive = _sensitive_hints_from_paths(path_samples + [u[:256] for u in locs[:32]])

    summary: dict[str, Any] = {
        "origin": origin,
        "robots_url": robots_url,
        "robots_http_status": rs,
        "sitemap_url": sitemap_url,
        "sitemap_http_status": ss,
        "sitemap_index_http_status": sis,
        "security_txt_url": sec_url,
        "security_txt_http_status": sts,
        "disallow_count": len(disallow),
        "allow_count": len(allow),
        "sitemap_loc_count": len(locs),
        "robots_sitemap_hints": sm_hints[:16],
        "sensitive_path_hints": sensitive,
        "sample_disallow": disallow[:16],
        "sample_allow": allow[:8],
        "sample_sitemap_urls": locs[:24],
    }

    try:
        sink_raw_text(
            tenant_id=tid,
            scan_id=sid,
            phase="recon",
            artifact_type="recon_robots_txt_raw",
            text=robots_body if robots_body.strip() else f"# fetch status={rs}\n",
            ext="txt",
        )
        sink_raw_text(
            tenant_id=tid,
            scan_id=sid,
            phase="recon",
            artifact_type="recon_sitemap_xml_raw",
            text=sm_body if sm_body.strip() else f"# fetch status={ss}\n",
            ext="txt",
        )
        sink_raw_text(
            tenant_id=tid,
            scan_id=sid,
            phase="recon",
            artifact_type="recon_sitemap_index_xml_raw",
            text=sidx_body if sidx_body.strip() else f"# fetch status={sis}\n",
            ext="txt",
        )
        sink_raw_text(
            tenant_id=tid,
            scan_id=sid,
            phase="recon",
            artifact_type="recon_security_txt_raw",
            text=sec_body if sec_body.strip() else f"# fetch status={sts}\n",
            ext="txt",
        )
        sink_raw_json(
            tenant_id=tid,
            scan_id=sid,
            phase="recon",
            artifact_type="recon_robots_sitemap_summary",
            payload=summary,
        )
    except Exception:
        logger.warning(
            "robots_sitemap_sink_failed",
            extra={"event": "robots_sitemap_sink_failed", "scan_id": sid},
        )

    if bool(settings.va_robots_extended_pipeline) and settings.sandbox_enabled:
        await _maybe_run_extended_crawl(origin, tenant_id=tid, scan_id=sid)

    return summary


async def _maybe_run_extended_crawl(origin: str, *, tenant_id: str, scan_id: str) -> None:
    """Shallow gospider + parsero (best-effort). No heavy ffuf by default (see VA task note)."""
    from src.recon.vulnerability_analysis.active_scan.mcp_runner import run_va_active_scan

    job_slug = "robots_ext"
    argv_g = ["gospider", "-s", origin, "-d", "1", "-t", "2", "--json", "-q"]
    try:
        res = await run_va_active_scan(
            tool_name="gospider",
            target=origin,
            argv=argv_g,
            timeout_sec=90.0,
            use_sandbox=True,
            sandbox_workdir="/home/argus",
        )
        sink_raw_text(
            tenant_id=tenant_id,
            scan_id=scan_id,
            phase="recon",
            artifact_type=f"tool_gospider_{job_slug}_stdout",
            text=(res.get("stdout") or "")[:_MAX_BODY],
            ext="txt",
        )
    except Exception:
        logger.info("robots_ext_gospider_skipped", extra={"event": "robots_ext_gospider_skipped"})

    argv_p = ["parsero", "-u", origin, "-o", "-l", "50"]
    try:
        res_p = await run_va_active_scan(
            tool_name="parsero",
            target=origin,
            argv=argv_p,
            timeout_sec=60.0,
            use_sandbox=True,
            sandbox_workdir="/home/argus",
        )
        sink_raw_text(
            tenant_id=tenant_id,
            scan_id=scan_id,
            phase="recon",
            artifact_type=f"tool_parsero_{job_slug}_stdout",
            text=(res_p.get("stdout") or "")[:_MAX_BODY],
            ext="txt",
        )
    except Exception:
        logger.info("robots_ext_parsero_skipped", extra={"event": "robots_ext_parsero_skipped"})
