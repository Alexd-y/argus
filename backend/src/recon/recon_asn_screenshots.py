"""RECON-008 — asnmap (apex ASN intel) + gowitness screenshots for live HTTP URLs; MinIO refs; passive-safe."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from typing import TYPE_CHECKING, Any

from src.core.config import Settings, settings as default_settings
from src.recon.mcp.kal_executor import run_kal_mcp_tool
from src.recon.mcp.policy import evaluate_kal_mcp_policy
from src.recon.raw_artifact_sink import sink_raw_bytes, slug_for_artifact_type_component
from src.recon.recon_runtime import ReconRuntimeConfig
from src.recon.sandbox_tool_runner import build_sandbox_exec_argv, run_argv_simple_sync
from src.recon.vulnerability_analysis.active_scan.argv_safe import safe_http_url_for_argv
from src.tools.guardrails import validate_target_for_tool

if TYPE_CHECKING:
    from src.orchestration.raw_phase_artifacts import RawPhaseSink

logger = logging.getLogger(__name__)

_RECON_PHASE = "recon"
_APEX_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", re.IGNORECASE)
_IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".webp")


def _normalize_apex_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    if not d:
        return ""
    d = d.split("/")[0].split(":")[0].strip(".")
    return d


def _apex_domain_allowed(d: str) -> bool:
    if not d or ".." in d or len(d) > 253:
        return False
    return bool(_APEX_DOMAIN_RE.match(d))


def build_recon_asnmap_argv(domain: str) -> list[str]:
    d = _normalize_apex_domain(domain)
    if not _apex_domain_allowed(d):
        return []
    return ["asnmap", "-d", d, "-silent", "-json"]


def parse_asnmap_stdout_structured(stdout: str) -> dict[str, Any]:
    """Best-effort JSONL / JSON array parse; always returns additive summary shape."""
    raw = (stdout or "").strip()
    rows: list[dict[str, Any]] = []

    def _push_obj(obj: Any) -> None:
        if isinstance(obj, dict):
            rows.append(obj)
        elif isinstance(obj, list):
            for it in obj:
                if isinstance(it, dict):
                    rows.append(it)

    if raw:
        try:
            _push_obj(json.loads(raw))
        except json.JSONDecodeError:
            pass
    if not rows:
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                _push_obj(json.loads(ln))
            except json.JSONDecodeError:
                continue

    asns: dict[str, dict[str, Any]] = {}
    cidrs: list[str] = []
    inputs: list[str] = []

    for r in rows:
        inp = r.get("input") or r.get("domain") or r.get("host")
        if isinstance(inp, str) and inp.strip():
            inputs.append(inp.strip())
        asn = r.get("as_number") or r.get("asn")
        if asn is None:
            continue
        key = str(asn).strip()
        if not key:
            continue
        entry = asns.setdefault(
            key,
            {
                "as_number": key,
                "as_name": None,
                "as_country": None,
                "ranges": [],
            },
        )
        name = r.get("as_name") or r.get("organization")
        if isinstance(name, str) and name.strip():
            entry["as_name"] = name.strip()[:512]
        country = r.get("as_country") or r.get("country")
        if isinstance(country, str) and country.strip():
            entry["as_country"] = country.strip()[:8]
        ar = r.get("as_range") or r.get("cidr") or r.get("ranges")
        if isinstance(ar, list):
            for x in ar:
                if isinstance(x, str) and x.strip():
                    cidrs.append(x.strip())
                    if x.strip() not in entry["ranges"]:
                        entry["ranges"].append(x.strip())
        elif isinstance(ar, str) and ar.strip():
            cidrs.append(ar.strip())
            if ar.strip() not in entry["ranges"]:
                entry["ranges"].append(ar.strip())

    return {
        "row_count": len(rows),
        "unique_asns": list(asns.values()),
        "cidrs_sample": sorted(set(cidrs))[:200],
        "inputs": sorted(set(inputs)),
    }


def collect_live_http_urls(
    target: str,
    tool_results: dict[str, Any],
    *,
    max_urls: int,
) -> list[str]:
    """Prefer httpx JSONL lines with successful probe; fallback to target URL."""
    cap = max(1, min(500, int(max_urls)))
    seen: set[str] = set()
    out: list[str] = []

    def push(u: str) -> None:
        su = safe_http_url_for_argv(u)
        if not su or su in seen:
            return
        seen.add(su)
        out.append(su)

    block = tool_results.get("httpx")
    stdout = ""
    if isinstance(block, dict):
        stdout = str(block.get("stdout") or "")

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        failed = obj.get("failed")
        if failed is True:
            continue
        sc = obj.get("status_code") or obj.get("status-code")
        if isinstance(sc, int) and (sc < 200 or sc >= 600):
            continue
        raw_url = str(obj.get("url") or obj.get("input") or "").strip()
        if raw_url:
            push(raw_url)
        if len(out) >= cap:
            break

    if len(out) < cap:
        push(str(target or ""))

    return out[:cap]


def _tool_binary_visible(argv0: str, app_settings: Settings) -> bool:
    if app_settings.sandbox_enabled:
        return True
    return shutil.which(argv0) is not None


def _gowitness_screenshot_exts_in_dir(directory: str) -> list[tuple[str, float]]:
    found: list[tuple[str, float]] = []
    try:
        for root, _, files in os.walk(directory):
            for name in files:
                low = name.lower()
                if any(low.endswith(ext) for ext in _IMAGE_EXTS):
                    path = os.path.join(root, name)
                    try:
                        m = os.path.getmtime(path)
                    except OSError:
                        m = 0.0
                    found.append((path, m))
    except OSError:
        pass
    found.sort(key=lambda x: -x[1])
    return found


def build_gowitness_single_argv(url: str, screenshot_dir: str, timeout_sec: int) -> list[str]:
    u = safe_http_url_for_argv(url)
    if not u:
        return []
    to = max(5, min(300, int(timeout_sec)))
    return [
        "gowitness",
        "-q",
        "scan",
        "single",
        "-u",
        u,
        "-s",
        screenshot_dir,
        "-t",
        "1",
        "-T",
        str(to),
        "--write-none",
    ]


def _run_gowitness_one_sync(
    url: str,
    *,
    timeout_sec: float,
    tenant_id: str | None,
    scan_id: str | None,
    password_audit_opt_in: bool,
    app_settings: Settings,
) -> dict[str, Any]:
    host = ""
    try:
        from urllib.parse import urlparse

        host = (urlparse(url).hostname or "").strip().lower()
    except Exception:
        host = ""
    if host:
        vr = validate_target_for_tool(host, "gowitness")
        if not vr["allowed"]:
            return {
                "url": url,
                "success": False,
                "minio_key": None,
                "error": str(vr.get("reason") or "target_denied"),
            }

    if not safe_http_url_for_argv(url):
        return {"url": url, "success": False, "minio_key": None, "error": "invalid_url"}

    with tempfile.TemporaryDirectory(prefix="gw_") as tmp:
        shot_root = os.path.join(tmp, "shots")
        os.makedirs(shot_root, exist_ok=True)
        argv = build_gowitness_single_argv(url, shot_root, timeout_sec=int(timeout_sec))
        if not argv:
            return {"url": url, "success": False, "minio_key": None, "error": "invalid_url"}

        pol = evaluate_kal_mcp_policy(
            category="web_screenshots",
            argv=argv,
            password_audit_opt_in=password_audit_opt_in,
            server_password_audit_enabled=bool(app_settings.kal_allow_password_audit),
        )
        if not pol.allowed:
            return {
                "url": url,
                "success": False,
                "minio_key": None,
                "error": f"policy:{pol.reason}",
            }

        run_parts = build_sandbox_exec_argv(argv, use_sandbox=app_settings.sandbox_enabled)
        exec_out = run_argv_simple_sync(run_parts, timeout_sec=max(float(timeout_sec) + 15.0, 20.0))
        ok = bool(exec_out.get("success"))
        imgs = _gowitness_screenshot_exts_in_dir(shot_root)
        if not imgs:
            return {
                "url": url,
                "success": False,
                "minio_key": None,
                "error": "no_screenshot_file" if ok else str(exec_out.get("stderr") or "run_failed")[:200],
            }

        path = imgs[0][0]
        ext = os.path.splitext(path)[1].lstrip(".").lower() or "jpeg"
        if ext not in ("png", "jpg", "jpeg", "webp"):
            ext = "jpeg"
        try:
            with open(path, "rb") as f:
                body = f.read()
        except OSError:
            body = b""

        slug = slug_for_artifact_type_component(url, max_len=40)
        artifact_type = f"gowitness_{slug}"
        key = sink_raw_bytes(
            tenant_id=tenant_id,
            scan_id=scan_id or "",
            phase=_RECON_PHASE,
            artifact_type=artifact_type,
            ext=ext,
            data=body,
            content_type=None,
        )
        return {"url": url, "success": key is not None, "minio_key": key, "error": None}


async def run_recon_asnmap_bundle(
    domain: str,
    cfg: ReconRuntimeConfig,
    *,
    raw_sink: RawPhaseSink | None,
    tenant_id: str | None,
    scan_id: str | None,
    app_settings: Settings | None = None,
) -> dict[str, Any]:
    s = app_settings or default_settings
    out: dict[str, Any] = {}
    if not cfg.asnmap_enabled:
        return out

    argv = build_recon_asnmap_argv(domain)
    if not argv:
        logger.info("recon_asnmap_skipped", extra={"event": "recon_asnmap_skipped", "reason": "bad_domain"})
        return out

    if not _tool_binary_visible(argv[0], s):
        logger.info("recon_asnmap_skipped", extra={"event": "recon_asnmap_skipped", "reason": "binary_missing"})
        return out

    target_url = f"https://{_normalize_apex_domain(domain)}/"
    res = await asyncio.to_thread(
        run_kal_mcp_tool,
        category="asn_mapping",
        argv=argv,
        target=target_url,
        tenant_id=tenant_id,
        scan_id=scan_id,
        password_audit_opt_in=False,
        timeout_sec=float(max(1, int(getattr(s, "recon_tools_timeout", 300) or 300))),
    )

    def _strip_internal(d: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in d.items() if k not in ("policy_reason", "minio_keys")}

    out["asnmap"] = _strip_internal(res)
    summary = parse_asnmap_stdout_structured(str(res.get("stdout") or ""))
    out["asn_summary"] = summary

    if raw_sink is not None:
        try:
            await asyncio.to_thread(raw_sink.upload_json, "asn_summary", summary)
        except Exception:
            logger.warning("asn_summary_upload_failed", extra={"event": "asn_summary_upload_failed"})

    return out


async def run_recon_gowitness_bundle(
    target: str,
    tool_results: dict[str, Any],
    cfg: ReconRuntimeConfig,
    *,
    raw_sink: RawPhaseSink | None,
    tenant_id: str | None,
    scan_id: str | None,
    app_settings: Settings | None = None,
) -> dict[str, Any]:
    s = app_settings or default_settings
    out: dict[str, Any] = {}
    if not cfg.screenshots:
        return out

    if not _tool_binary_visible("gowitness", s):
        logger.info("recon_gowitness_skipped", extra={"event": "recon_gowitness_skipped", "reason": "binary_missing"})
        out["gowitness"] = {
            "success": False,
            "stdout": "",
            "stderr": "binary_missing",
            "return_code": -1,
            "execution_time": 0.0,
        }
        out["gowitness_screenshots"] = {"artifacts": [], "summary": {"attempted": 0, "uploaded": 0}}
        return out

    eff_to = cfg.gowitness_timeout_sec
    if eff_to is None:
        eff_to = int(getattr(s, "recon_tools_timeout", 300) or 300)
    eff_to = max(10, min(600, int(eff_to)))

    urls = collect_live_http_urls(target, tool_results, max_urls=cfg.gowitness_max_urls)
    if not urls:
        out["gowitness_screenshots"] = {"artifacts": [], "summary": {"attempted": 0, "uploaded": 0}}
        return out

    conc = max(1, min(8, int(cfg.gowitness_concurrency)))
    sem = asyncio.Semaphore(conc)

    async def _one(u: str) -> dict[str, Any]:
        async with sem:
            return await asyncio.to_thread(
                _run_gowitness_one_sync,
                u,
                timeout_sec=float(eff_to),
                tenant_id=tenant_id,
                scan_id=scan_id,
                password_audit_opt_in=False,
                app_settings=s,
            )

    results = await asyncio.gather(*[_one(u) for u in urls], return_exceptions=True)
    artifacts: list[dict[str, Any]] = []
    uploaded = 0
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            artifacts.append(
                {
                    "url": urls[i] if i < len(urls) else "",
                    "success": False,
                    "minio_key": None,
                    "error": type(r).__name__,
                }
            )
            continue
        if r.get("success") and r.get("minio_key"):
            uploaded += 1
        artifacts.append(
            {
                "url": r.get("url"),
                "success": bool(r.get("success")),
                "minio_key": r.get("minio_key"),
                "error": r.get("error"),
            }
        )

    out["gowitness_screenshots"] = {
        "artifacts": artifacts,
        "summary": {"attempted": len(urls), "uploaded": uploaded},
    }

    if raw_sink is not None:
        try:
            await asyncio.to_thread(
                raw_sink.upload_json,
                "gowitness_screenshots_index",
                out["gowitness_screenshots"],
            )
        except Exception:
            logger.warning("gowitness_index_upload_failed", extra={"event": "gowitness_index_upload_failed"})

    out["gowitness"] = {
        "success": uploaded > 0 or len(urls) == 0,
        "stdout": json.dumps({"urls": len(urls), "uploaded": uploaded}, ensure_ascii=True),
        "stderr": "",
        "return_code": 0 if uploaded else 1,
        "execution_time": 0.0,
    }
    return out
