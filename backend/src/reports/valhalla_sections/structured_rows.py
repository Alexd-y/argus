"""Structured PoC rows for XSS / CSRF / CMDi findings (Wave 4 / Stage 6).

Extracted verbatim from ``valhalla_report_context`` (T6/T7/T8): the Pydantic row
models + their builders that project a finding's proof-of-concept into compact,
LLM-ready rows (no raw HTTP bodies). Pure functions over finding dicts; shared helpers
come from :mod:`._common` so this module never imports the monolith.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.reports.valhalla_sections._common import _finding_id_for_risk, _truncate


class ValhallaXssStructuredRowModel(BaseModel):
    """T6 — XSS PoC fields passed to LLM context (valhalla_context / compact AI block)."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str = ""
    parameter: str | None = None
    payload_entered: str | None = None
    payload_reflected: str | None = None
    payload_used: str | None = None
    reflection_context: str | None = None
    verification_method: str | None = None
    verified_via_browser: bool | None = None
    browser_alert_text: str | None = None
    artifact_keys: list[str] = Field(default_factory=list)
    artifact_urls: list[str] = Field(default_factory=list)


class ValhallaCsrfStructuredRowModel(BaseModel):
    """T7 — CSRF PoC fields passed to LLM context."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str = ""
    endpoint: str | None = None
    method: str = "POST"
    state_changing: bool | None = None
    token_status: str | None = None
    raw_html_form: str | None = None
    raw_post: str | None = None
    cookies: str = ""
    origin_referer: str = ""
    negative_control: str | None = None
    verified: bool = False


class ValhallaCmdiStructuredRowModel(BaseModel):
    """T8 — Command Injection PoC fields passed to LLM context."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str = ""
    parameter: str | None = None
    payload: str | None = None
    harmless_marker: str | None = None
    controlled_output: str | None = None
    server_proof: str | None = None
    output_source: str = "stdout"
    negative_control: str | None = None
    verified: bool = False


_MAX_XSS_CONTEXT_ROWS = 48
_MAX_XSS_FIELD_LEN = 600


def _poc_as_dict(f: dict[str, Any]) -> dict[str, Any]:
    poc = f.get("proof_of_concept")
    return poc if isinstance(poc, dict) else {}


def finding_qualifies_for_xss_structured_context(f: dict[str, Any]) -> bool:
    """True when PoC / CWE / title suggests XSS and structured XSS context is useful for reports."""
    poc = _poc_as_dict(f)
    if not poc:
        cwe = str(f.get("cwe") or "").upper()
        return "79" in cwe
    cwe = str(f.get("cwe") or "").upper()
    if "79" in cwe:
        return True
    title_l = str(f.get("title") or "").lower()
    if ("xss" in title_l or "cross-site scripting" in title_l) and poc:
        return True
    signal_keys = (
        "reflection_context",
        "verified_via_browser",
        "verification_method",
        "browser_alert_text",
        "payload_entered",
        "payload_used",
        "screenshot_key",
        "poc_screenshot_url",
        "screenshot_url",
    )
    if any(k in poc and poc.get(k) is not None for k in signal_keys):
        return True
    param = poc.get("parameter")
    if isinstance(param, str) and param.strip():
        for k in ("payload", "javascript_code", "payload_entered", "payload_used"):
            v = poc.get(k)
            if isinstance(v, str) and v.strip():
                return True
    return False


def _truncate_xss_field(val: str | None, max_len: int = _MAX_XSS_FIELD_LEN) -> str | None:
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    return _truncate(s, max_len)


def _normalize_payload_reflected_value(poc: dict[str, Any]) -> str | None:
    v = poc.get("payload_reflected")
    if isinstance(v, str) and v.strip():
        return _truncate_xss_field(v.strip())
    if isinstance(v, bool):
        return "true" if v else "false"
    return None


def _collect_poc_artifact_keys(poc: dict[str, Any]) -> list[str]:
    keys: list[str] = []
    sk = poc.get("screenshot_key")
    if isinstance(sk, str) and sk.strip():
        keys.append(sk.strip()[:512])
    for alt in ("screenshot_keys", "artifact_keys", "poc_screenshot_keys"):
        raw = poc.get(alt)
        if not isinstance(raw, list):
            continue
        for x in raw[:16]:
            if isinstance(x, str) and x.strip():
                keys.append(x.strip()[:512])
    seen: set[str] = set()
    out: list[str] = []
    for k in keys:
        low = k.lower()
        if low not in seen:
            seen.add(low)
            out.append(k)
        if len(out) >= 16:
            break
    return out


def _is_likely_http_url(s: str) -> bool:
    t = s.strip().lower()
    return t.startswith("http://") or t.startswith("https://")


def _collect_poc_artifact_urls(poc: dict[str, Any]) -> list[str]:
    """Presigned or public artifact URLs when stored on PoC (distinct from object keys)."""
    urls: list[str] = []
    for k in ("poc_screenshot_url", "screenshot_url", "artifact_url"):
        v = poc.get(k)
        if isinstance(v, str) and v.strip() and _is_likely_http_url(v):
            urls.append(v.strip()[:1024])
    for alt in ("artifact_urls", "poc_screenshot_urls", "screenshot_urls"):
        raw = poc.get(alt)
        if not isinstance(raw, list):
            continue
        for x in raw[:8]:
            if isinstance(x, str) and x.strip() and _is_likely_http_url(x):
                urls.append(x.strip()[:1024])
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        low = u.lower()
        if low not in seen:
            seen.add(low)
            out.append(u)
        if len(out) >= 8:
            break
    return out


def _verified_via_browser_from_poc(poc: dict[str, Any]) -> bool | None:
    raw = poc.get("verified_via_browser")
    if raw is None:
        return None
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        low = raw.strip().lower()
        if low in ("true", "1", "yes"):
            return True
        if low in ("false", "0", "no"):
            return False
    return None


def build_xss_structured_rows_from_findings(
    findings: list[dict[str, Any]],
    *,
    max_rows: int = _MAX_XSS_CONTEXT_ROWS,
) -> list[ValhallaXssStructuredRowModel]:
    """Extract XSS-oriented PoC fields for Valhalla AI / compact context (no raw HTTP bodies)."""
    out: list[ValhallaXssStructuredRowModel] = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        if not finding_qualifies_for_xss_structured_context(f):
            continue
        poc = _poc_as_dict(f)
        fid = _finding_id_for_risk(f, i)
        title = _truncate_xss_field(str(f.get("title") or "").strip(), 300) or ""
        param = poc.get("parameter")
        param_s = _truncate_xss_field(param.strip() if isinstance(param, str) else None, 256)
        pe = poc.get("payload_entered")
        pu = poc.get("payload_used")
        legacy_pl = poc.get("payload")
        payload_entered = _truncate_xss_field(pe.strip() if isinstance(pe, str) else None)
        payload_used = _truncate_xss_field(
            pu.strip()
            if isinstance(pu, str)
            else (legacy_pl.strip() if isinstance(legacy_pl, str) else None)
        )
        pref = _normalize_payload_reflected_value(poc)
        refl_ctx = poc.get("reflection_context") or poc.get("context")
        reflection_context = _truncate_xss_field(
            refl_ctx.strip() if isinstance(refl_ctx, str) else None, 400
        )
        vm = poc.get("verification_method")
        verification_method = _truncate_xss_field(vm.strip() if isinstance(vm, str) else None, 128)
        bat = poc.get("browser_alert_text")
        browser_alert_text = _truncate_xss_field(bat.strip() if isinstance(bat, str) else None, 400)
        out.append(
            ValhallaXssStructuredRowModel(
                finding_id=fid[:256],
                title=title or "—",
                parameter=param_s,
                payload_entered=payload_entered,
                payload_reflected=pref,
                payload_used=payload_used,
                reflection_context=reflection_context,
                verification_method=verification_method,
                verified_via_browser=_verified_via_browser_from_poc(poc),
                browser_alert_text=browser_alert_text,
                artifact_keys=_collect_poc_artifact_keys(poc),
                artifact_urls=_collect_poc_artifact_urls(poc),
            )
        )
        if len(out) >= max_rows:
            break
    return out


def build_csrf_structured_rows_from_findings(
    findings: list[dict[str, Any]],
    *,
    max_rows: int = 40,
) -> list[ValhallaCsrfStructuredRowModel]:
    """Extract CSRF-oriented PoC fields for Valhalla AI / compact context."""
    out: list[ValhallaCsrfStructuredRowModel] = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        title_l = str(f.get("title", "") or "").lower()
        is_csrf = "csrf" in title_l or "cross-site request" in title_l or "session" in title_l
        if not is_csrf:
            continue
        poc = _poc_as_dict(f)
        fid = _finding_id_for_risk(f, i)
        title = _truncate_xss_field(str(f.get("title") or "").strip(), 300) or ""
        endpoint = poc.get("url") or poc.get("endpoint") or f.get("affected_endpoint", "")
        endpoint_s = (
            _truncate_xss_field(endpoint.strip() if isinstance(endpoint, str) else None, 512)
            or None
        )
        method = str(poc.get("method", "POST") or "POST")
        state_changing = poc.get("state_changing")
        token_status = str(poc.get("csrf_token_status", "missing") or "missing")
        raw_form = str(poc.get("raw_html_form", "") or "")[:1024] or None
        raw_post = str(poc.get("raw_post", poc.get("payload", "")) or "")[:512] or None
        cookies = str(poc.get("cookies", "") or "")
        origin_ref = str(poc.get("origin", poc.get("referer", "")) or "")
        nc = str(poc.get("negative_control", "") or "")
        nc_s = _truncate_xss_field(nc, 256) or None
        verified = bool(poc.get("verified_via_browser")) or bool(poc.get("exploit_demonstrated"))
        out.append(
            ValhallaCsrfStructuredRowModel(
                finding_id=fid[:256],
                title=title or "—",
                endpoint=endpoint_s,
                method=method,
                state_changing=state_changing,
                token_status=token_status,
                raw_html_form=raw_form,
                raw_post=raw_post,
                cookies=cookies,
                origin_referer=origin_ref,
                negative_control=nc_s,
                verified=verified,
            )
        )
        if len(out) >= max_rows:
            break
    return out


def build_cmdi_structured_rows_from_findings(
    findings: list[dict[str, Any]],
    *,
    max_rows: int = 40,
) -> list[ValhallaCmdiStructuredRowModel]:
    """Extract Command Injection-oriented PoC fields for Valhalla AI / compact context."""
    out: list[ValhallaCmdiStructuredRowModel] = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        cwe = str(f.get("cwe", "") or "").upper()
        title_l = str(f.get("title", "") or "").lower()
        is_cmdi = "78" in cwe or "command" in title_l or "injection" in title_l
        if not is_cmdi:
            continue
        poc = _poc_as_dict(f)
        fid = _finding_id_for_risk(f, i)
        title = _truncate_xss_field(str(f.get("title") or "").strip(), 300) or ""
        param = poc.get("parameter") or poc.get("input", "")
        param_s = (
            _truncate_xss_field(param.strip() if isinstance(param, str) else None, 256) or None
        )
        payload = poc.get("payload", "")
        payload_s = (
            _truncate_xss_field(payload.strip() if isinstance(payload, str) else None, 512) or None
        )
        marker = poc.get("harmless_marker", "")
        marker_s = (
            _truncate_xss_field(marker.strip() if isinstance(marker, str) else None, 256) or None
        )
        output = poc.get("controlled_output", poc.get("command_output", ""))
        output_s = (
            _truncate_xss_field(output.strip() if isinstance(output, str) else None, 512) or None
        )
        proof = poc.get("server_proof", poc.get("log_entry", ""))
        proof_s = (
            _truncate_xss_field(proof.strip() if isinstance(proof, str) else None, 512) or None
        )
        source = str(poc.get("output_source", "stdout") or "stdout")
        nc = str(poc.get("negative_control", "") or "")
        nc_s = _truncate_xss_field(nc, 256) or None
        verified = bool(poc.get("verified_via_browser")) or bool(poc.get("exploit_demonstrated"))
        out.append(
            ValhallaCmdiStructuredRowModel(
                finding_id=fid[:256],
                title=title or "—",
                parameter=param_s,
                payload=payload_s,
                harmless_marker=marker_s,
                controlled_output=output_s,
                server_proof=proof_s,
                output_source=source,
                negative_control=nc_s,
                verified=verified,
            )
        )
        if len(out) >= max_rows:
            break
    return out


def serialize_xss_structured_for_ai(rows: list[ValhallaXssStructuredRowModel]) -> str:
    """One JSON object per row (newlines); for tests and optional prompt attachment."""
    chunks: list[str] = []
    for r in rows:
        try:
            chunks.append(json.dumps(r.model_dump(mode="json"), ensure_ascii=False))
        except (TypeError, ValueError):
            continue
    return "\n".join(chunks)


__all__ = [
    "ValhallaCmdiStructuredRowModel",
    "ValhallaCsrfStructuredRowModel",
    "ValhallaXssStructuredRowModel",
    "build_cmdi_structured_rows_from_findings",
    "build_csrf_structured_rows_from_findings",
    "build_xss_structured_rows_from_findings",
    "finding_qualifies_for_xss_structured_context",
    "serialize_xss_structured_for_ai",
]
