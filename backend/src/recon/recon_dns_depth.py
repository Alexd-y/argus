"""RECON-003 — dnsx multi-record probing, optional dig, structured dns_records + raw MinIO; takeover hints (heuristic)."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shlex
import tempfile
from pathlib import Path
from typing import Any

from src.core.config import settings
from src.recon.recon_dns_sandbox import _apex_domain, _domain_allowed
from src.recon.recon_runtime import ReconRuntimeConfig
from src.recon.sandbox_tool_runner import build_sandbox_exec_argv, run_argv_simple_sync

logger = logging.getLogger(__name__)

# Extra dnsx flags allowed from env / scan options (flag-only; no arbitrary values).
_SAFE_DNSX_FLAGS = frozenset({
    "-silent",
    "-wd",
    "-resp",
    "-oc",
    "-debug",
    "-v",
    "-verbose",
    "-trace",
})

_TYPE_ALIASES: dict[str, str] = {
    "a": "A",
    "aaaa": "AAAA",
    "cname": "CNAME",
    "mx": "MX",
    "txt": "TXT",
    "ns": "NS",
}

_DNSX_JSON_KEYS: dict[str, str] = {
    "a": "A",
    "aaaa": "AAAA",
    "cname": "CNAME",
    "mx": "MX",
    "txt": "TXT",
    "ns": "NS",
}

_TAKEOVER_SUFFIXES: tuple[str, ...] = (
    ".github.io",
    ".gitlab.io",
    ".herokuapp.com",
    ".netlify.app",
    ".vercel.app",
    ".azurewebsites.net",
    ".cloudfront.net",
    ".s3.amazonaws.com",
    ".s3-website",
    ".blob.core.windows.net",
    ".pantheonsite.io",
    ".shopify.com",
    ".readme.io",
    ".surge.sh",
    ".fastly.net",
)


def _first_resolver_ip(raw: str) -> str | None:
    s = (raw or "").strip()
    if not s:
        return None
    first = s.split(",")[0].strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", first):
        return first
    return None


def _parse_record_types_csv(csv: str) -> list[str]:
    out: list[str] = []
    for part in (csv or "").lower().split(","):
        p = part.strip()
        if p in _TYPE_ALIASES and p not in out:
            out.append(p)
    return out or ["a", "aaaa", "cname", "mx", "txt", "ns"]


def _dnsx_type_argv(types: list[str]) -> list[str]:
    argv: list[str] = []
    for t in types:
        flag = f"-{t}"
        if flag not in argv:
            argv.append(flag)
    return argv


def _sanitize_dnsx_extra_tokens(tokens: list[str] | None) -> list[str]:
    if not tokens:
        return []
    out: list[str] = []
    i = 0
    retry_added = False
    while i < len(tokens):
        tok = str(tokens[i]).strip()
        if not tok.startswith("-"):
            i += 1
            continue
        if tok == "-retry" and i + 1 < len(tokens) and not retry_added:
            nxt = str(tokens[i + 1]).strip()
            if nxt.isdigit() and 1 <= int(nxt) <= 5:
                out.extend(["-retry", nxt])
                retry_added = True
                i += 2
                continue
        if tok in _SAFE_DNSX_FLAGS and tok not in out:
            out.append(tok)
        i += 1
    return out


def _merge_extra_flags_from_env_and_cfg(
    cfg_tokens: frozenset[str] | None,
    env_str: str,
) -> list[str]:
    merged: list[str] = []
    try:
        env_parts = shlex.split(env_str or "", posix=True)
    except ValueError:
        env_parts = []
    for t in _sanitize_dnsx_extra_tokens(list(env_parts)):
        if t not in merged:
            merged.append(t)
    for t in _sanitize_dnsx_extra_tokens(list(cfg_tokens) if cfg_tokens else []):
        if t not in merged:
            merged.append(t)
    return merged


def build_dnsx_argv(domain: str, cfg: ReconRuntimeConfig) -> list[str]:
    if not _domain_allowed(domain):
        return []
    types = _parse_record_types_csv(cfg.dnsx_record_types_csv)
    argv = ["dnsx", "-d", domain, "-json"]
    argv.extend(_dnsx_type_argv(types))
    if cfg.dnsx_include_resp:
        argv.append("-resp")
    if cfg.dnsx_silent:
        argv.append("-silent")
    argv.extend(_merge_extra_flags_from_env_and_cfg(cfg.dnsx_extra_flags, settings.recon_dnsx_extra_flags))
    res = _first_resolver_ip(settings.recon_default_dns_resolver)
    if res:
        argv.extend(["-r", res])
    return argv


def _normalize_dns_value(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(x).strip() for x in val if str(x).strip()]
    s = str(val).strip()
    return [s] if s else []


def _records_from_dnsx_obj(obj: dict[str, Any]) -> list[dict[str, Any]]:
    host = str(obj.get("host") or obj.get("input") or "").strip()
    rows: list[dict[str, Any]] = []
    if not host:
        return rows
    for key, rtype in _DNSX_JSON_KEYS.items():
        for v in _normalize_dns_value(obj.get(key)):
            rows.append({"host": host, "record_type": rtype, "value": v})
    return rows


def parse_dnsx_stdout(stdout: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (flattened records, raw_json_objects one per parsed line)."""
    records: list[dict[str, Any]] = []
    raw_objs: list[dict[str, Any]] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        raw_objs.append(obj)
        records.extend(_records_from_dnsx_obj(obj))
    return records, raw_objs


def _apex_of_host(hostname: str) -> str:
    parts = hostname.lower().strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname.lower()


def _collect_cname_targets(records: list[dict[str, Any]], apex: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    apex_l = apex.lower()
    for r in records:
        if str(r.get("record_type") or "").upper() != "CNAME":
            continue
        tgt = str(r.get("value") or "").strip().rstrip(".")
        if not tgt or not _domain_allowed(tgt):
            continue
        if _apex_of_host(tgt) == apex_l:
            continue
        tlow = tgt.lower()
        if tlow not in seen:
            seen.add(tlow)
            out.append(tgt)
    return out


def _host_has_a_or_aaaa(hostname: str, *record_lists: list[dict[str, Any]]) -> bool:
    h = hostname.strip().lower().rstrip(".")
    if not h:
        return False
    for lst in record_lists:
        for r in lst:
            rh = str(r.get("host") or "").strip().lower().rstrip(".")
            if rh != h:
                continue
            if str(r.get("record_type") or "").upper() in ("A", "AAAA"):
                return True
    return False


def build_takeover_hints(
    records: list[dict[str, Any]],
    cname_follow_records: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    follow = cname_follow_records or []

    for r in records:
        if str(r.get("record_type") or "").upper() != "CNAME":
            continue
        host = str(r.get("host") or "").strip()
        tgt = str(r.get("value") or "").strip().rstrip(".")
        if not host or not tgt:
            continue
        tlow = tgt.lower()
        matched = next((s for s in _TAKEOVER_SUFFIXES if tlow.endswith(s)), None)
        if not matched:
            continue
        tgt_resolved = _host_has_a_or_aaaa(tgt, records, follow)
        hint_type = "cloud_cname_target"
        note = (
            f"CNAME from {host} points to {tgt} ({matched}). "
            "Heuristic only: verify ownership on the provider; unclaimed buckets/pages may indicate takeover risk."
        )
        if not tgt_resolved:
            hint_type = "potential_dangling_cname"
            note = (
                f"CNAME from {host} points to {tgt} ({matched}); no A/AAAA observed for the target in this probe. "
                "Heuristic only: may be NXDOMAIN, blocking, or resolver noise — confirm manually."
            )
        hints.append({
            "hint_type": hint_type,
            "hostname": host,
            "cname_target": tgt,
            "provider_guess": matched.strip("."),
            "severity": "info",
            "note": note,
        })
    return hints


def _dns_depth_timeout_sec(cfg: ReconRuntimeConfig) -> float:
    v = cfg.dns_depth_timeout_sec
    if v is None:
        v = settings.recon_dns_depth_timeout_sec
    if v is None or int(v) <= 0:
        return float(max(5, int(settings.recon_tools_timeout or 300)))
    return float(max(5, int(v)))


def _run_dnsx_argv(argv: list[str], timeout_sec: float) -> dict[str, Any]:
    if not argv:
        return {"success": False, "stdout": "", "stderr": "invalid argv", "return_code": -1, "execution_time": 0.0}
    parts = build_sandbox_exec_argv(argv, use_sandbox=settings.sandbox_enabled)
    return run_argv_simple_sync(parts, timeout_sec=timeout_sec)


def _run_dnsx_on_list_file(
    path: Path,
    types: list[str],
    timeout_sec: float,
    *,
    include_resp: bool,
    extra_cfg: frozenset[str] | None,
) -> dict[str, Any]:
    argv = ["dnsx", "-l", str(path), "-json"]
    argv.extend(_dnsx_type_argv(types))
    if include_resp:
        argv.append("-resp")
    res = _first_resolver_ip(settings.recon_default_dns_resolver)
    if res:
        argv.extend(["-r", res])
    argv.extend(_merge_extra_flags_from_env_and_cfg(extra_cfg, settings.recon_dnsx_extra_flags))
    return _run_dnsx_argv(argv, timeout_sec)


def _run_dig_bundle(domain: str, timeout_sec: float) -> dict[str, Any]:
    from src.tools.executor import execute_command

    res = _first_resolver_ip(settings.recon_default_dns_resolver) or ""
    at = f"@{res} " if res else ""
    cmd = f"dig {at}+noall +answer {domain} ANY"
    return execute_command(cmd, use_cache=False, use_sandbox=False, timeout_sec=int(timeout_sec))


async def run_recon_dns_depth_bundle(
    target: str,
    cfg: ReconRuntimeConfig,
    *,
    raw_sink: Any | None,
) -> dict[str, Any]:
    """Returns tool_results fragment for pipeline merge; never raises."""
    out: dict[str, Any] = {}
    if not cfg.dns_depth_enabled:
        return out

    domain = _apex_domain(target)
    if not domain:
        return out

    timeout_sec = _dns_depth_timeout_sec(cfg)
    types = _parse_record_types_csv(cfg.dnsx_record_types_csv)

    try:
        argv = build_dnsx_argv(domain, cfg)
        if not argv:
            out["dnsx"] = {
                "success": False,
                "stdout": "",
                "stderr": "invalid domain or empty dnsx argv",
                "return_code": -1,
                "execution_time": 0.0,
            }
            return out

        dnsx_result = await asyncio.to_thread(_run_dnsx_argv, argv, timeout_sec)
        out["dnsx"] = dnsx_result

        records, raw_objs = parse_dnsx_stdout(str(dnsx_result.get("stdout") or ""))

        cname_follow: list[dict[str, Any]] = []
        if cfg.dns_depth_takeover_hints:
            targets = _collect_cname_targets(records, domain)[:25]
            if targets:
                try:
                    with tempfile.NamedTemporaryFile(
                        mode="w",
                        encoding="utf-8",
                        suffix=".txt",
                        delete=False,
                    ) as tmp:
                        for t in targets:
                            tmp.write(t + "\n")
                        tmp_path = Path(tmp.name)
                    try:
                        follow = await asyncio.to_thread(
                            _run_dnsx_on_list_file,
                            tmp_path,
                            ["a", "aaaa"],
                            timeout_sec,
                            include_resp=cfg.dnsx_include_resp,
                            extra_cfg=cfg.dnsx_extra_flags,
                        )
                        out["dnsx_cname_follow"] = follow
                        cname_follow.extend(parse_dnsx_stdout(str(follow.get("stdout") or ""))[0])
                    finally:
                        try:
                            tmp_path.unlink(missing_ok=True)
                        except OSError:
                            pass
                except Exception:
                    logger.warning(
                        "recon_dns_depth_cname_follow_failed",
                        extra={"event": "recon_dns_depth_cname_follow_failed"},
                        exc_info=True,
                    )

        hints: list[dict[str, Any]] = []
        if cfg.dns_depth_takeover_hints:
            hints = build_takeover_hints(records, cname_follow or None)

        dig_result: dict[str, Any] | None = None
        if cfg.dns_depth_dig_deep:
            dig_result = await asyncio.to_thread(_run_dig_bundle, domain, timeout_sec)
            out["dig_depth"] = dig_result

        doc: dict[str, Any] = {
            "apex": domain,
            "records": records,
            "raw_dnsx_objects": raw_objs,
            "takeover_hints": hints,
            "meta": {
                "dnsx": {
                    "success": dnsx_result.get("success"),
                    "return_code": dnsx_result.get("return_code"),
                },
                "dnsx_cname_follow": (
                    (out.get("dnsx_cname_follow") or {}).get("success")
                    if isinstance(out.get("dnsx_cname_follow"), dict)
                    else None
                ),
                "dig_depth": (
                    {"success": dig_result.get("success"), "return_code": dig_result.get("return_code")}
                    if isinstance(dig_result, dict)
                    else None
                ),
            },
        }

        if raw_sink is not None:
            try:
                await asyncio.to_thread(raw_sink.upload_json, "dns_records", doc)
            except Exception:
                logger.warning("recon_dns_records_upload_failed", extra={"event": "recon_dns_records_upload_failed"})
            try:
                if isinstance(dnsx_result.get("stdout"), str) and dnsx_result["stdout"].strip():
                    await asyncio.to_thread(raw_sink.upload_text, "dnsx_raw", dnsx_result["stdout"])
            except Exception:
                logger.warning("recon_dnsx_raw_upload_failed", extra={"event": "recon_dnsx_raw_upload_failed"})
            if isinstance(dig_result, dict) and str(dig_result.get("stdout") or "").strip():
                try:
                    await asyncio.to_thread(raw_sink.upload_text, "dig_depth_raw", str(dig_result.get("stdout")))
                except Exception:
                    logger.warning(
                        "recon_dig_depth_raw_upload_failed",
                        extra={"event": "recon_dig_depth_raw_upload_failed"},
                    )

        try:
            summary = json.dumps(doc, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            summary = "{}"

        out["dns_depth"] = {
            "success": bool(dnsx_result.get("success")),
            "stdout": summary[:150_000],
            "stderr": str(dnsx_result.get("stderr") or ""),
            "return_code": dnsx_result.get("return_code"),
            "execution_time": dnsx_result.get("execution_time"),
            "structured": doc,
        }
    except Exception as ex:
        logger.warning(
            "recon_dns_depth_failed",
            extra={"event": "recon_dns_depth_failed", "exc_type": type(ex).__name__},
            exc_info=True,
        )
        out["dns_depth"] = {
            "success": False,
            "stdout": "",
            "stderr": "dns_depth probe failed",
            "return_code": -1,
            "execution_time": 0.0,
        }

    return out
