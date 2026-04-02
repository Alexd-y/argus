"""VHL-001 — Valhalla-tier structured context for reports (recon + raw artifacts + phases).

Safe defaults: empty lists / false / None. No secrets in logs; raw excerpts are capped.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ValhallaSectionCoverageStatus = Literal["completed", "partial", "not_executed", "no_data"]

_MANDATORY_SECTION_IDS: tuple[str, ...] = (
    "tech_stack_structured",
    "outdated_components",
    "ssl_tls_analysis",
    "security_headers_analysis",
    "robots_sitemap_analysis",
    "leaked_emails",
)

from src.recon.vulnerability_analysis.active_scan.whatweb_va_adapter import (
    _plugin_strings,
    merge_whatweb_json_roots,
    parse_whatweb_stdout,
    parse_whatweb_text_fallback,
    parse_whatweb_to_tech_stack,
)
from src.storage.s3 import download_by_key

logger = logging.getLogger(__name__)

_ROBOTS_KEY_HINTS = frozenset({"robots", "robots_txt", "robotstxt"})
_SITEMAP_KEY_HINTS = frozenset({"sitemap", "sitemap_xml", "sitemapxml"})
_TLS_ARTIFACT_HINTS = frozenset({"testssl", "sslscan", "tls", "ssl"})
_DEP_ARTIFACT_HINTS = frozenset(
    {
        "trivy",
        "recon_trivy",
        "safety",
        "pip_audit",
        "npm_audit",
        "manifest",
        "package_lock",
        "requirements",
    }
)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_CVSS_V3_INLINE_RE = re.compile(
    r"CVSS:3\.[01]/[A-Za-z]{2,3}:[^\s\])]+(?:/[A-Za-z]{2,3}:[^\s\])]+)*",
    re.IGNORECASE,
)
_CIA_TRIPLET_RE = re.compile(r"/(C|I|A):([NLHP])", re.IGNORECASE)
_AV_NETWORK_RE = re.compile(r"/AV:N", re.IGNORECASE)
_NMAP_SV_LINE_RE = re.compile(
    r"^\d+/(?:tcp|udp)\s+open\s+(\S+)\s+(.+)$",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+"
)
_LOC_RE = re.compile(r"<loc>\s*([^<]+)\s*</loc>", re.IGNORECASE)
_MAX_EXCERPT = 4000
_MAX_RAW_FETCH = 256 * 1024


class RobotsTxtAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    found: bool = False
    raw_excerpt: str | None = None
    disallowed_paths_sample: list[str] = Field(default_factory=list)
    allow_paths_sample: list[str] = Field(default_factory=list)
    sitemap_hints: list[str] = Field(default_factory=list)
    sensitive_path_hints: list[str] = Field(default_factory=list)
    disallow_rule_count: int = 0
    allow_rule_count: int = 0


class SitemapAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    found: bool = False
    index_found: bool = False
    url_count: int = 0
    sample_urls: list[str] = Field(default_factory=list)


class TechStackTableRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str
    name: str
    detail: str = ""
    source: str = ""


class TechStackEntryModel(BaseModel):
    """VDF-001 — per-plugin row (WhatWeb certainty → confidence when available)."""

    model_config = ConfigDict(extra="forbid")

    technology: str = Field(max_length=512)
    version: str | None = Field(default=None, max_length=256)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class TechStackStructuredModel(BaseModel):
    """Structured fingerprint merge (WhatWeb + recon fallbacks) for ScanReportData / Valhalla."""

    model_config = ConfigDict(extra="forbid")

    web_server: str = ""
    os: str = ""
    cms: str = ""
    frameworks: list[str] = Field(default_factory=list)
    js_libraries: list[str] = Field(default_factory=list)
    ports_summary: str = ""
    services_summary: str = ""
    entries: list[TechStackEntryModel] = Field(default_factory=list)


class OutdatedComponentRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    component: str
    installed_version: str | None = None
    latest_stable: str | None = None
    support_status: str | None = None
    cves: list[str] = Field(default_factory=list)
    recommendation: str = ""
    exploit_available: bool = False


class SslTlsAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer: str | None = None
    validity: str | None = None
    protocols: list[str] = Field(default_factory=list)
    weak_protocols: list[str] = Field(default_factory=list)
    weak_ciphers: list[str] = Field(default_factory=list)
    hsts: str | None = None


class SecurityHeadersAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rows: list[dict[str, Any]] = Field(default_factory=list)
    missing_recommended: list[str] = Field(default_factory=list)
    summary: str | None = None


class DependencyAnalysisRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package: str
    version: str | None = None
    severity: str | None = None
    source: str = ""
    detail: str | None = None


class ThreatModelRefModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    phase: str = "threat_modeling"
    scan_id: str = ""
    tenant_id: str = ""
    excerpt: str = ""
    api_hint: str = ""


class RiskMatrixCellModel(BaseModel):
    """One occupied cell in impact × likelihood space (VHL-002)."""

    model_config = ConfigDict(extra="forbid")

    impact: Literal["low", "medium", "high"]
    likelihood: Literal["low", "medium", "high"]
    finding_ids: list[str] = Field(default_factory=list)
    count: int = 0


class RiskMatrixDistributionEntryModel(BaseModel):
    """Single severity row when matrix view is too sparse (VHL-002)."""

    model_config = ConfigDict(extra="forbid")

    severity: str
    count: int = 0
    finding_ids: list[str] = Field(default_factory=list)


class RiskMatrixModel(BaseModel):
    """Either quadrant-style cells or a severity distribution table."""

    model_config = ConfigDict(extra="forbid")

    variant: Literal["matrix", "distribution"] = "matrix"
    cells: list[RiskMatrixCellModel] = Field(default_factory=list)
    distribution: list[RiskMatrixDistributionEntryModel] = Field(default_factory=list)


class CriticalVulnRefModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vuln_id: str
    title: str
    description: str = ""
    cvss: float | None = None
    exploit_available: bool = False
    severity: str = ""


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
            pu.strip() if isinstance(pu, str) else (legacy_pl.strip() if isinstance(legacy_pl, str) else None)
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


def serialize_xss_structured_for_ai(rows: list[ValhallaXssStructuredRowModel]) -> str:
    """One JSON object per row (newlines); for tests and optional prompt attachment."""
    chunks: list[str] = []
    for r in rows:
        try:
            chunks.append(json.dumps(r.model_dump(mode="json"), ensure_ascii=False))
        except (TypeError, ValueError):
            continue
    return "\n".join(chunks)


class AppendixToolEntryModel(BaseModel):
    """Appendix A — scanner/tool line (VHL-008); version omitted in templates when unset."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str | None = None


class ValhallaSectionEnvelopeModel(BaseModel):
    """Structured status for a mandatory Valhalla block (scan data or explicit fallback reason)."""

    model_config = ConfigDict(extra="forbid")

    status: ValhallaSectionCoverageStatus = "no_data"
    reason: str = ""


class ValhallaMandatorySectionsModel(BaseModel):
    """T6 — every mandatory section always has status + machine-readable reason when not completed."""

    model_config = ConfigDict(extra="forbid")

    tech_stack_structured: ValhallaSectionEnvelopeModel = Field(
        default_factory=ValhallaSectionEnvelopeModel
    )
    outdated_components: ValhallaSectionEnvelopeModel = Field(
        default_factory=ValhallaSectionEnvelopeModel
    )
    ssl_tls_analysis: ValhallaSectionEnvelopeModel = Field(default_factory=ValhallaSectionEnvelopeModel)
    security_headers_analysis: ValhallaSectionEnvelopeModel = Field(
        default_factory=ValhallaSectionEnvelopeModel
    )
    robots_sitemap_analysis: ValhallaSectionEnvelopeModel = Field(
        default_factory=ValhallaSectionEnvelopeModel
    )
    leaked_emails: ValhallaSectionEnvelopeModel = Field(default_factory=ValhallaSectionEnvelopeModel)


class ValhallaCoverageModel(BaseModel):
    """T7 — traceability: phases, flags, per-section status, tool error hints (no secrets)."""

    model_config = ConfigDict(extra="forbid")

    phases_executed: list[str] = Field(default_factory=list)
    feature_flags: dict[str, bool] = Field(default_factory=dict)
    sections: dict[str, dict[str, str]] = Field(default_factory=dict)
    tool_errors_summary: list[dict[str, str]] = Field(default_factory=list)


class RobotsSitemapMergedSummaryModel(BaseModel):
    """VDF-008 — merged robots + sitemap signals for templates / AI."""

    model_config = ConfigDict(extra="forbid")

    robots_found: bool = False
    sitemap_found: bool = False
    security_txt_reachable: bool = False
    disallow_rule_count: int = 0
    allow_rule_count: int = 0
    sitemap_url_count: int = 0
    sensitive_path_hints: list[str] = Field(default_factory=list)
    notes_ru: str = ""


class ValhallaRobotsSitemapAnalysisBundleModel(BaseModel):
    """Single object for Jinja: robots + sitemap + merged summary (T6 naming)."""

    model_config = ConfigDict(extra="forbid")

    robots_txt: RobotsTxtAnalysisModel = Field(default_factory=RobotsTxtAnalysisModel)
    sitemap: SitemapAnalysisModel = Field(default_factory=SitemapAnalysisModel)
    merged: RobotsSitemapMergedSummaryModel = Field(default_factory=RobotsSitemapMergedSummaryModel)


class ValhallaReportContext(BaseModel):
    """Nested context for Valhalla HTML/PDF templates (RPT / VHL-001)."""

    model_config = ConfigDict(extra="forbid")

    robots_txt_analysis: RobotsTxtAnalysisModel = Field(default_factory=RobotsTxtAnalysisModel)
    sitemap_analysis: SitemapAnalysisModel = Field(default_factory=SitemapAnalysisModel)
    robots_sitemap_merged: RobotsSitemapMergedSummaryModel = Field(
        default_factory=RobotsSitemapMergedSummaryModel
    )
    tech_stack_table: list[TechStackTableRow] = Field(default_factory=list)
    tech_stack_structured: TechStackStructuredModel = Field(default_factory=TechStackStructuredModel)
    tech_stack_fallback_message: str | None = None
    ssl_tls_fallback_message: str | None = None
    security_headers_fallback_message: str | None = None
    outdated_components_fallback_message: str | None = None
    robots_sitemap_fallback_message: str | None = None
    leaked_emails_fallback_message: str | None = None
    outdated_components: list[OutdatedComponentRow] = Field(default_factory=list)
    leaked_emails: list[str] = Field(default_factory=list)
    ssl_tls_analysis: SslTlsAnalysisModel = Field(default_factory=SslTlsAnalysisModel)
    security_headers_analysis: SecurityHeadersAnalysisModel = Field(
        default_factory=SecurityHeadersAnalysisModel
    )
    dependency_analysis: list[DependencyAnalysisRow] = Field(default_factory=list)
    threat_model: ThreatModelRefModel = Field(default_factory=ThreatModelRefModel)
    threat_model_excerpt: str = ""
    threat_model_phase_link: str = ""
    exploitation_post_excerpt: str = ""
    risk_matrix: RiskMatrixModel = Field(default_factory=RiskMatrixModel)
    critical_vulns: list[CriticalVulnRefModel] = Field(default_factory=list)
    appendix_tools: list[AppendixToolEntryModel] = Field(default_factory=list)
    mandatory_sections: ValhallaMandatorySectionsModel = Field(
        default_factory=ValhallaMandatorySectionsModel
    )
    robots_sitemap_analysis: ValhallaRobotsSitemapAnalysisBundleModel = Field(
        default_factory=ValhallaRobotsSitemapAnalysisBundleModel
    )
    coverage: ValhallaCoverageModel = Field(default_factory=ValhallaCoverageModel)
    recon_pipeline_summary: dict[str, Any] = Field(default_factory=dict)
    xss_structured: list[ValhallaXssStructuredRowModel] = Field(default_factory=list)


_TOOL_VERSION_PARAM_KEYS: tuple[str, ...] = (
    "version",
    "tool_version",
    "scanner_version",
    "nuclei_version",
    "binary_version",
    "app_version",
)
_TOOL_STREAM_RE = re.compile(r"^tool_(?P<name>.+)_(stdout|stderr)$", re.IGNORECASE)


def _version_from_input_params(params: dict[str, Any] | None) -> str | None:
    if not isinstance(params, dict):
        return None
    for k in _TOOL_VERSION_PARAM_KEYS:
        v = params.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()[:128]
        if isinstance(v, (int, float)):
            return str(v)
    return None


def _coerce_tool_version_value(obj: Any) -> str | None:
    if isinstance(obj, str) and obj.strip():
        return obj.strip()[:128]
    if isinstance(obj, (int, float)):
        return str(obj)
    return None


def _walk_phase_blob_for_tools(obj: Any, acc: list[tuple[str, str | None]]) -> None:
    """Collect (tool_name, version?) from nested dicts with key ``tool``."""
    if isinstance(obj, dict):
        t_raw = obj.get("tool")
        if isinstance(t_raw, str) and t_raw.strip():
            name = t_raw.strip()
            ver: str | None = None
            for k in _TOOL_VERSION_PARAM_KEYS:
                ver = _coerce_tool_version_value(obj.get(k))
                if ver:
                    break
            acc.append((name, ver))
        for v in obj.values():
            _walk_phase_blob_for_tools(v, acc)
    elif isinstance(obj, list):
        for it in obj:
            _walk_phase_blob_for_tools(it, acc)


def _tool_name_from_raw_artifact_type(artifact_type: str) -> str | None:
    s = (artifact_type or "").strip()
    m = _TOOL_STREAM_RE.match(s)
    if not m:
        return None
    return m.group("name").strip() or None


def build_appendix_tools(
    *,
    tool_runs: list[tuple[str, dict[str, Any] | None]] | None,
    phase_outputs: list[tuple[str, dict[str, Any] | None]],
    raw_artifact_types: list[str] | None,
) -> list[AppendixToolEntryModel]:
    """
    Appendix A tool list: prefer ``tool_runs`` (name + optional version from ``input_params``),
    then phase output blobs (``tool`` key), then raw artifact ``artifact_type`` like ``tool_nuclei_stdout``.
    """
    seen: set[tuple[str, str]] = set()
    out: list[AppendixToolEntryModel] = []

    def add_entry(name: str, version: str | None) -> None:
        n = (name or "").strip()
        if not n:
            return
        n = n[:200]
        v = (version or "").strip()[:128] if version else None
        if v == "":
            v = None
        key = (n.lower(), (v or "").lower())
        if key in seen:
            return
        seen.add(key)
        out.append(AppendixToolEntryModel(name=n, version=v))

    if tool_runs:
        for tool_name, params in tool_runs:
            tn = (tool_name or "").strip()
            if not tn:
                continue
            add_entry(tn, _version_from_input_params(params))

    for _ph, od in phase_outputs:
        if not isinstance(od, dict):
            continue
        found: list[tuple[str, str | None]] = []
        _walk_phase_blob_for_tools(od, found)
        for name, ver in found:
            add_entry(name, ver)

    if raw_artifact_types:
        for at in raw_artifact_types:
            parsed = _tool_name_from_raw_artifact_type(str(at))
            if parsed:
                add_entry(parsed, None)

    out.sort(key=lambda e: (e.name.lower(), (e.version or "").lower()))
    return out


def _truncate(text: str, max_len: int) -> str:
    t = (text or "").strip()
    if len(t) <= max_len:
        return t
    return t[: max_len - 1].rstrip() + "…"


def _mask_email(addr: str) -> str:
    s = (addr or "").strip()
    if "@" not in s:
        return "***"
    local, domain = s.split("@", 1)
    local = local.strip()
    domain = domain.strip()
    if not local or not domain:
        return "***"
    if len(local) <= 2:
        masked_local = local[0] + "***"
    else:
        masked_local = local[0] + "***" + local[-1]
    parts = domain.split(".")
    if len(parts) >= 2:
        root = parts[0]
        masked_dom = (root[0] + "***" if root else "***") + "." + ".".join(parts[1:])
    else:
        masked_dom = domain[0] + "***" if len(domain) > 1 else "***"
    return f"{masked_local}@{masked_dom}"


def _extract_emails_from_text(text: str) -> list[str]:
    found = _EMAIL_RE.findall(text or "")
    out: list[str] = []
    seen: set[str] = set()
    for e in found:
        key = e.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(_mask_email(e))
        if len(out) >= 64:
            break
    return out


def _parse_robots_body(text: str) -> tuple[list[str], list[str], list[str]]:
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
    return disallow[:32], allow[:32], sitemaps[:32]


def _parse_sitemap_body(text: str) -> tuple[int, list[str]]:
    raw = text or ""
    urls = [u.strip() for u in _LOC_RE.findall(raw) if u.strip()]
    sample = urls[:24]
    return len(urls), sample


def _sensitive_hints_from_paths(paths: list[str]) -> list[str]:
    needle = (
        "admin",
        "wp-admin",
        "api",
        "backup",
        "graphql",
        ".env",
        "internal",
        "staging",
        "swagger",
        "jenkins",
        "phpmyadmin",
        "debug",
    )
    out: list[str] = []
    seen: set[str] = set()
    for p in paths:
        low = (p or "").lower()
        for h in needle:
            if h in low and h not in seen:
                seen.add(h)
                out.append(h)
        if len(out) >= 16:
            break
    return out


def _artifact_name_matches(key: str, hints: frozenset[str]) -> bool:
    base = key.rsplit("/", 1)[-1].lower()
    name_no_ext = base.rsplit(".", 1)[0] if "." in base else base
    parts = name_no_ext.split("_")
    tail = parts[-1] if parts else name_no_ext
    for h in hints:
        if h in base or h in tail:
            return True
    if len(parts) >= 3:
        at = parts[2]
        for h in hints:
            if h in at:
                return True
    return False


def _safe_download_raw(key: str) -> bytes | None:
    try:
        raw = download_by_key(key)
    except Exception:
        logger.warning(
            "valhalla_raw_fetch_failed",
            extra={"event": "valhalla_raw_fetch_failed", "key_suffix": key[-64:]},
        )
        return None
    if raw is None or len(raw) > _MAX_RAW_FETCH:
        return None
    return raw


def _text_from_raw_bytes(raw: bytes) -> str | None:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return None


def _collect_robots_sitemap_from_keys(
    raw_keys: list[tuple[str, str]],
    *,
    fetch_bodies: bool,
) -> tuple[RobotsTxtAnalysisModel, SitemapAnalysisModel]:
    robots = RobotsTxtAnalysisModel()
    sitemap = SitemapAnalysisModel()
    robot_key: str | None = None
    sm_key: str | None = None
    for key, _phase in raw_keys:
        if robot_key is None and _artifact_name_matches(key, _ROBOTS_KEY_HINTS):
            robot_key = key
        if sm_key is None and _artifact_name_matches(key, _SITEMAP_KEY_HINTS):
            sm_key = key
    if fetch_bodies and robot_key:
        blob = _safe_download_raw(robot_key)
        if blob:
            text = _text_from_raw_bytes(blob)
            if text:
                dis, alw, sm = _parse_robots_body(text)
                sens = _sensitive_hints_from_paths(dis + alw)
                robots = RobotsTxtAnalysisModel(
                    found=True,
                    raw_excerpt=_truncate(text, _MAX_EXCERPT),
                    disallowed_paths_sample=dis[:16],
                    allow_paths_sample=alw[:16],
                    sitemap_hints=sm[:16],
                    sensitive_path_hints=sens,
                    disallow_rule_count=len(dis),
                    allow_rule_count=len(alw),
                )
    elif robot_key:
        robots = RobotsTxtAnalysisModel(found=True, raw_excerpt=None, disallowed_paths_sample=[], sitemap_hints=[])

    if fetch_bodies and sm_key:
        blob = _safe_download_raw(sm_key)
        if blob:
            text = _text_from_raw_bytes(blob)
            if text:
                n, sample = _parse_sitemap_body(text)
                low = (text or "").lower()
                sitemap = SitemapAnalysisModel(
                    found=True,
                    index_found="<sitemapindex" in low,
                    url_count=n,
                    sample_urls=sample,
                )
    elif sm_key:
        sitemap = SitemapAnalysisModel(found=True, url_count=0, sample_urls=[])

    return robots, sitemap


_WHATWEB_KEY_HINTS = frozenset({"whatweb"})
_THEHARVESTER_KEY_HINTS = frozenset({"theharvester"})
_NMAP_OPEN_LINE_RE = re.compile(
    r"^\d+/(?:tcp|udp)\s+open(?:\s+|\s*$)", re.IGNORECASE | re.MULTILINE
)
_MAX_TECH_MERGE = 2000


def _walk_collect_whatweb_candidates(obj: Any, acc: list[dict[str, Any]]) -> None:
    if isinstance(obj, dict):
        plugs = obj.get("plugins")
        if isinstance(plugs, dict) and plugs:
            if obj.get("target") is not None or obj.get("http_status") is not None:
                acc.append(obj)
                return
            if any(isinstance(plugs.get(k), (dict, str)) for k in ("HTTPServer", "Apache", "nginx", "WordPress")):
                acc.append(obj)
                return
        tool = str(obj.get("tool") or "").lower()
        if tool == "whatweb":
            for k in ("stdout", "raw_out", "output", "stderr", "result"):
                v = obj.get(k)
                if isinstance(v, str) and v.strip():
                    parsed = parse_whatweb_stdout(v) or parse_whatweb_text_fallback(v)
                    if parsed:
                        acc.append(parsed)
        for v in obj.values():
            _walk_collect_whatweb_candidates(v, acc)
    elif isinstance(obj, list):
        for it in obj:
            _walk_collect_whatweb_candidates(it, acc)


def _whatweb_roots_from_phase_outputs(
    phase_outputs: list[tuple[str, dict[str, Any] | None]],
) -> list[dict[str, Any]]:
    acc: list[dict[str, Any]] = []
    for _ph, od in phase_outputs:
        if isinstance(od, dict):
            _walk_collect_whatweb_candidates(od, acc)
    return acc


def _whatweb_roots_from_raw_keys(
    raw_keys: list[tuple[str, str]],
    *,
    fetch_bodies: bool,
) -> list[dict[str, Any]]:
    if not fetch_bodies:
        return []
    out: list[dict[str, Any]] = []
    for key, _phase in raw_keys:
        if not _artifact_name_matches(key, _WHATWEB_KEY_HINTS):
            continue
        blob = _safe_download_raw(key)
        if not blob:
            continue
        text = _text_from_raw_bytes(blob)
        if not text:
            continue
        parsed = parse_whatweb_stdout(text.strip()) or parse_whatweb_text_fallback(text.strip())
        if parsed:
            out.append(parsed)
    return out


def _walk_collect_nmap_text(obj: Any, acc: list[str]) -> None:
    if isinstance(obj, dict):
        tool = str(obj.get("tool") or "").lower()
        if "nmap" in tool:
            for k in ("stdout", "output", "raw_out", "stderr"):
                v = obj.get(k)
                if isinstance(v, str) and "nmap" in v.lower():
                    acc.append(v)
        for v in obj.values():
            _walk_collect_nmap_text(v, acc)
    elif isinstance(obj, list):
        for it in obj:
            _walk_collect_nmap_text(it, acc)


def _nmap_text_from_phase_outputs(
    phase_outputs: list[tuple[str, dict[str, Any] | None]],
) -> str:
    chunks: list[str] = []
    for _ph, od in phase_outputs:
        if isinstance(od, dict):
            _walk_collect_nmap_text(od, chunks)
    merged = "\n".join(chunks)
    if len(merged) > _MAX_TECH_MERGE:
        return merged[: _MAX_TECH_MERGE - 1].rstrip() + "…"
    return merged


def _services_summary_from_nmap_text(text: str) -> str:
    raw = text or ""
    if not raw.strip():
        return ""
    lines_out: list[str] = []
    for line in raw.splitlines():
        if _NMAP_OPEN_LINE_RE.search(line):
            lines_out.append(line.strip()[:512])
        if len(lines_out) >= 32:
            break
    summary = "\n".join(lines_out)
    if len(summary) > _MAX_TECH_MERGE:
        return summary[: _MAX_TECH_MERGE - 1].rstrip() + "…"
    return summary


def _dict_to_structured(d: dict[str, Any]) -> TechStackStructuredModel:
    fw = d.get("frameworks")
    js = d.get("js_libraries")
    ent_raw = d.get("entries")
    entries: list[TechStackEntryModel] = []
    if isinstance(ent_raw, list):
        for it in ent_raw[:128]:
            if not isinstance(it, dict):
                continue
            tech = str(it.get("technology") or it.get("name") or "").strip()
            if not tech:
                continue
            ver = it.get("version")
            conf = it.get("confidence")
            cv = float(conf) if isinstance(conf, (int, float)) else None
            entries.append(
                TechStackEntryModel(
                    technology=tech[:512],
                    version=str(ver)[:256] if ver is not None else None,
                    confidence=cv,
                )
            )
    return TechStackStructuredModel(
        web_server=str(d.get("web_server") or "")[:1024],
        os=str(d.get("os") or "")[:1024],
        cms=str(d.get("cms") or "")[:1024],
        frameworks=[str(x)[:512] for x in fw if isinstance(x, str) and x.strip()][:64],
        js_libraries=[str(x)[:512] for x in js if isinstance(x, str) and x.strip()][:64],
        ports_summary=str(d.get("ports_summary") or "")[:1024],
        services_summary=str(d.get("services_summary") or "")[:_MAX_TECH_MERGE],
        entries=entries,
    )


def _apply_recon_fallbacks_to_structured(
    model: TechStackStructuredModel,
    recon: dict[str, Any] | None,
    tech_profile: list[dict[str, Any]] | None,
    report_tech: list[str] | None,
    ports: list[int] | None,
    nmap_blob: str,
) -> TechStackStructuredModel:
    m = model.model_copy(deep=True)

    def add_fw(name: str) -> None:
        t = name.strip()
        if t and t not in m.frameworks:
            m.frameworks.append(t[:512])

    def add_js(name: str) -> None:
        t = name.strip()
        if t and t not in m.js_libraries:
            m.js_libraries.append(t[:512])

    if isinstance(recon, dict):
        rps = recon.get("recon_pipeline_summary")
        if isinstance(rps, dict):
            tc = rps.get("technologies_combined")
            if isinstance(tc, dict):
                tech_list = tc.get("technologies")
                if isinstance(tech_list, list):
                    for ent in tech_list:
                        if not isinstance(ent, dict):
                            continue
                        val = str(ent.get("value") or ent.get("name") or "").strip()
                        if not val:
                            continue
                        host = str(ent.get("host") or "").strip()
                        detail = host
                        name_l = val.lower()
                        if any(x in name_l for x in ("nginx", "apache", "caddy", "iis", "openresty")) and not m.web_server:
                            m.web_server = (val + (f" ({detail})" if detail else ""))[:1024]
                        elif any(x in name_l for x in ("wordpress", "drupal", "joomla")) and not m.cms:
                            m.cms = (val + (f" ({detail})" if detail else ""))[:1024]
                        else:
                            add_fw(val if not detail else f"{val} ({detail})")

        ts = recon.get("tech_stack")
        if isinstance(ts, list):
            for ent in ts:
                if not isinstance(ent, dict):
                    continue
                it = str(ent.get("indicator_type") or "").lower()
                val = str(ent.get("value") or "").strip()
                if not val:
                    continue
                host = str(ent.get("host") or "").strip()
                ev = str(ent.get("evidence") or "").strip()
                detail = host or ev
                if it in ("platform", "server", "web_server") and not m.web_server:
                    m.web_server = (val + (f" ({detail})" if detail else ""))[:1024]
                elif it == "cms" and not m.cms:
                    m.cms = (val + (f" ({detail})" if detail else ""))[:1024]
                elif "framework" in it:
                    add_fw(val if not detail else f"{val} ({detail})")
                elif "js" in it or "javascript" in it:
                    add_js(val if not detail else f"{val} ({detail})")

    if isinstance(tech_profile, list):
        for ent in tech_profile:
            if not isinstance(ent, dict):
                continue
            it = str(ent.get("indicator_type") or "").lower()
            val = str(ent.get("value") or "").strip()
            if not val:
                continue
            host = str(ent.get("host") or "").strip()
            if it in ("platform", "server") and not m.web_server:
                m.web_server = (val + (f" ({host})" if host else ""))[:1024]
            elif "framework" in it:
                add_fw(val if not host else f"{val} ({host})")
            elif "js" in it or "javascript" in it:
                add_js(val if not host else f"{val} ({host})")

    if report_tech:
        for t in report_tech:
            s = str(t).strip()
            if s and s not in m.frameworks and s not in m.js_libraries:
                if not m.cms and any(x in s.lower() for x in ("wordpress", "drupal", "joomla")):
                    m.cms = s[:1024]
                elif not m.web_server and any(
                    x in s.lower() for x in ("nginx", "apache", "iis", "caddy", "openresty")
                ):
                    m.web_server = s[:1024]
                else:
                    add_fw(s)

    if ports:
        uniq = sorted({int(p) for p in ports if isinstance(p, int)})[:64]
        if uniq:
            ps = ", ".join(str(x) for x in uniq)
            if not m.ports_summary:
                m.ports_summary = ps[:1024]
            elif ps not in m.ports_summary:
                m.ports_summary = f"{m.ports_summary}; {ps}"[:1024]

    if nmap_blob.strip() and not m.services_summary:
        m.services_summary = _services_summary_from_nmap_text(nmap_blob)

    m.frameworks = m.frameworks[:64]
    m.js_libraries = m.js_libraries[:64]
    return m


def _tech_rows_from_structured(model: TechStackStructuredModel) -> list[TechStackTableRow]:
    rows: list[TechStackTableRow] = []
    if model.web_server.strip():
        rows.append(
            TechStackTableRow(
                category="web_server",
                name=model.web_server[:512],
                detail="",
                source="tech_stack.structured",
            )
        )
    if model.os.strip():
        rows.append(
            TechStackTableRow(
                category="os",
                name=model.os[:512],
                detail="",
                source="tech_stack.structured",
            )
        )
    if model.cms.strip():
        rows.append(
            TechStackTableRow(
                category="cms",
                name=model.cms[:512],
                detail="",
                source="tech_stack.structured",
            )
        )
    for f in model.frameworks:
        rows.append(
            TechStackTableRow(
                category="framework",
                name=f[:512],
                detail="",
                source="tech_stack.structured",
            )
        )
    for j in model.js_libraries:
        rows.append(
            TechStackTableRow(
                category="javascript",
                name=j[:512],
                detail="",
                source="tech_stack.structured",
            )
        )
    if model.ports_summary.strip():
        rows.append(
            TechStackTableRow(
                category="ports",
                name=model.ports_summary[:512],
                detail="",
                source="tech_stack.structured",
            )
        )
    if model.services_summary.strip():
        rows.append(
            TechStackTableRow(
                category="services",
                name="nmap (open ports / services)",
                detail=_truncate(model.services_summary, 1024),
                source="nmap.summary",
            )
        )
    return rows


def _merge_tech_stack_tables(
    primary: list[TechStackTableRow],
    extra: list[TechStackTableRow],
    *,
    structured: TechStackStructuredModel,
) -> list[TechStackTableRow]:
    seen: set[tuple[str, str]] = set()
    out: list[TechStackTableRow] = []

    def norm_key(r: TechStackTableRow) -> tuple[str, str]:
        return (r.category.lower().strip(), r.name.lower().strip()[:200])

    for r in primary:
        k = norm_key(r)
        if k in seen:
            continue
        seen.add(k)
        out.append(r)

    for r in extra:
        k = norm_key(r)
        if k in seen:
            continue
        if r.category.lower() == "ports" and structured.ports_summary.strip():
            continue
        seen.add(k)
        out.append(r)
    return out[:200]


def _tech_rows_from_recon(
    recon: dict[str, Any] | None,
    tech_profile: list[dict[str, Any]] | None,
    report_tech: list[str] | None,
    ports: list[int] | None,
) -> list[TechStackTableRow]:
    rows: list[TechStackTableRow] = []
    seen: set[tuple[str, str, str]] = set()

    def add_row(category: str, name: str, detail: str = "", source: str = "") -> None:
        key = (category, name[:256], detail[:256])
        if key in seen:
            return
        seen.add(key)
        rows.append(
            TechStackTableRow(
                category=category[:128],
                name=name[:512] or "—",
                detail=detail[:1024],
                source=source[:256],
            )
        )

    if isinstance(recon, dict):
        ts = recon.get("tech_stack")
        if isinstance(ts, list):
            for ent in ts:
                if not isinstance(ent, dict):
                    continue
                it = str(ent.get("indicator_type") or "technology").lower()
                cat = (
                    "web_server"
                    if it in ("platform", "server", "web_server")
                    else "cms"
                    if it == "cms"
                    else "framework"
                    if "framework" in it
                    else "javascript"
                    if "js" in it or "javascript" in it
                    else "technology"
                )
                val = str(ent.get("value") or "").strip()
                host = str(ent.get("host") or "").strip()
                ev = str(ent.get("evidence") or "").strip()
                if val:
                    add_row(cat, val, host or ev, "recon_results.tech_stack")

    if isinstance(tech_profile, list):
        for ent in tech_profile:
            if not isinstance(ent, dict):
                continue
            it = str(ent.get("indicator_type") or "technology").lower()
            cat = "web_server" if it in ("platform", "server") else "technology"
            val = str(ent.get("value") or "").strip()
            host = str(ent.get("host") or "").strip()
            if val:
                add_row(cat, val, host, "tech_profile.json")

    if report_tech:
        for t in report_tech:
            s = str(t).strip()
            if s:
                add_row("report", s, "", "report.technologies")

    if ports:
        uniq = sorted({int(p) for p in ports if isinstance(p, int)})[:64]
        if uniq:
            add_row("ports", ", ".join(str(x) for x in uniq), "", "recon_output.ports")

    return rows[:200]


def _ssl_from_recon_certs(recon: dict[str, Any] | None) -> SslTlsAnalysisModel:
    out = SslTlsAnalysisModel()
    if not isinstance(recon, dict):
        return out
    certs = recon.get("ssl_certs")
    if not isinstance(certs, dict) or not certs:
        return out
    # first host's first cert
    for _host, lst in certs.items():
        if not isinstance(lst, list) or not lst:
            continue
        c0 = lst[0]
        if not isinstance(c0, dict):
            continue
        issuer = str(c0.get("issuer") or "").strip() or None
        nb = c0.get("validity_not_before")
        na = c0.get("validity_not_after")
        validity = None
        if nb is not None and na is not None:
            validity = f"{nb} — {na}"
        elif nb is not None:
            validity = str(nb)
        return SslTlsAnalysisModel(issuer=issuer, validity=validity)
    return out


def _ssl_from_testssl_json(blob: dict[str, Any]) -> SslTlsAnalysisModel:
    protocols: list[str] = []
    weak: list[str] = []
    weak_proto: list[str] = []
    hsts: str | None = None
    issuer: str | None = None
    scan_result = blob.get("scanResult")
    if isinstance(scan_result, list):
        for entry in scan_result:
            if not isinstance(entry, dict):
                continue
            fid = str(entry.get("id") or "").lower()
            finding = str(entry.get("finding") or "").strip()
            if not finding:
                continue
            low = finding.lower()
            if "hsts" in fid or "hsts" in low:
                hsts = _truncate(finding, 500)
            if "issuer" in fid or "certificate issuer" in low:
                issuer = issuer or _truncate(finding, 512)
            if "protocol" in fid or fid.startswith("sslv") or "tls1" in fid:
                protocols.append(_truncate(finding, 240))
            if any(
                x in low or x in fid
                for x in (
                    "sslv2",
                    "sslv3",
                    "tls1",
                    "tls 1.0",
                    "tls1_0",
                    "tls1.0",
                    "tls 1.1",
                    "tls1_1",
                    "tls1.1",
                )
            ):
                if len(weak_proto) < 32:
                    weak_proto.append(_truncate(finding, 400))
            if any(x in low for x in ("cbc", "rc4", "weak", "deprecated", "sslv2", "sslv3")):
                if len(weak) < 48:
                    weak.append(_truncate(finding, 400))
    protos = blob.get("protocols")
    if isinstance(protos, dict) and not protocols:
        for label, detail in list(protos.items())[:32]:
            if isinstance(label, str) and label.strip():
                d = detail if not isinstance(detail, dict) else detail.get("finding") or detail
                protocols.append(f"{label}: {d}"[:300])
    ciphers = blob.get("ciphers")
    if isinstance(ciphers, dict) and len(weak) < 48:
        for label, detail in list(ciphers.items())[:24]:
            low = str(detail).lower()
            if "weak" in low or "cbc" in low or "rc4" in low:
                weak.append(f"{label}: {detail}"[:400])
    return SslTlsAnalysisModel(
        issuer=issuer,
        validity=None,
        protocols=protocols[:32],
        weak_protocols=weak_proto[:32],
        weak_ciphers=weak[:32],
        hsts=hsts,
    )


def _json_dict_from_tls_artifact_text(text: str) -> dict[str, Any] | None:
    """Parse testssl/sslscan stdout saved as .txt (may contain noise before ``{``)."""
    s = (text or "").strip()
    if not s:
        return None
    if s.startswith("{") or s.startswith("["):
        try:
            val = json.loads(s)
        except json.JSONDecodeError:
            val = None
        else:
            return val if isinstance(val, dict) else None
    idx = s.find("{")
    if idx >= 0:
        tail = s[idx:]
        try:
            val = json.loads(tail)
        except json.JSONDecodeError:
            return None
        return val if isinstance(val, dict) else None
    return None


def _latest_tls_blob_from_raw(
    raw_keys: list[tuple[str, str]],
    *,
    fetch_bodies: bool,
) -> dict[str, Any] | None:
    if not fetch_bodies:
        return None
    candidates: list[str] = []
    for key, _p in raw_keys:
        if _artifact_name_matches(key, _TLS_ARTIFACT_HINTS):
            candidates.append(key)
    candidates.sort(key=lambda k: k)
    for key in reversed(candidates):
        blob = _safe_download_raw(key)
        if not blob:
            continue
        text = _text_from_raw_bytes(blob)
        if not text:
            continue
        parsed = _json_dict_from_tls_artifact_text(text)
        if parsed:
            return parsed
    return None


def _normalize_http_headers_host_map(raw: dict[str, Any]) -> dict[str, dict[str, str]]:
    """URL/host → lowercase header name → value."""
    out: dict[str, dict[str, str]] = {}
    for host, hdrs in raw.items():
        hkey = str(host).strip()[:512]
        if not hkey or not isinstance(hdrs, dict):
            continue
        inner: dict[str, str] = {}
        for k, v in hdrs.items():
            ks = str(k).strip().lower()
            vs = str(v).strip()
            if ks and vs:
                inner[ks] = vs
        if inner:
            out[hkey] = inner
    return out


def _walk_collect_http_headers_maps(obj: Any, acc: list[dict[str, Any]]) -> None:
    """VDF-003 — pull http_headers blobs from nested recon / phase JSON."""
    if isinstance(obj, dict):
        hh = obj.get("http_headers")
        if isinstance(hh, dict) and hh:
            acc.append(hh)
        rr = obj.get("recon_results")
        if isinstance(rr, dict):
            hh2 = rr.get("http_headers")
            if isinstance(hh2, dict) and hh2:
                acc.append(hh2)
        for alt in ("response_headers", "headers", "headers_sample"):
            hs = obj.get(alt)
            if not isinstance(hs, dict) or not hs:
                continue
            keys_low = {str(x).lower() for x in hs.keys()}
            if keys_low & {
                "content-security-policy",
                "x-frame-options",
                "strict-transport-security",
                "server",
            }:
                acc.append(hs)
        for v in obj.values():
            _walk_collect_http_headers_maps(v, acc)
    elif isinstance(obj, list):
        for it in obj[:400]:
            _walk_collect_http_headers_maps(it, acc)


def _http_headers_merged_from_recon_and_phases(
    recon_results: dict[str, Any] | None,
    phase_outputs: list[tuple[str, dict[str, Any] | None]],
) -> dict[str, dict[str, str]]:
    blobs: list[dict[str, Any]] = []
    if isinstance(recon_results, dict):
        root_h = recon_results.get("http_headers")
        if isinstance(root_h, dict) and root_h:
            blobs.append(root_h)
        rps = recon_results.get("recon_pipeline_summary")
        if isinstance(rps, dict):
            sh = rps.get("security_headers")
            if isinstance(sh, dict) and sh:
                blobs.append(sh)
    for ph, od in phase_outputs:
        if not isinstance(od, dict):
            continue
        if (ph or "").lower() in ("recon", "threat_modeling", "vuln_analysis"):
            _walk_collect_http_headers_maps(od, blobs)
    merged: dict[str, dict[str, str]] = {}
    for blob in blobs:
        part = _normalize_http_headers_host_map(blob)
        for host, hdrs in part.items():
            cur = merged.get(host, {})
            merged[host] = {**cur, **hdrs}
    return merged


def _security_headers_from_host_map(http_headers: dict[str, dict[str, str]]) -> SecurityHeadersAnalysisModel:
    rows: list[dict[str, Any]] = []
    if not http_headers:
        return SecurityHeadersAnalysisModel()
    # VDF-003 — canonical security header rows (CSP, XFO, XCTO, HSTS, Referrer-Policy, X-XSS-Protection)
    canonical = (
        ("content-security-policy", "Content-Security-Policy"),
        ("x-frame-options", "X-Frame-Options"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("strict-transport-security", "Strict-Transport-Security"),
        ("referrer-policy", "Referrer-Policy"),
        ("x-xss-protection", "X-XSS-Protection"),
    )
    extra_recommended = ("permissions-policy",)
    missing: set[str] = set()
    for host, hdrs in list(http_headers.items())[:32]:
        lower_map = dict(hdrs)
        hstr = str(host)[:256]
        for low_name, display in canonical:
            if low_name not in lower_map:
                missing.add(low_name)
                rows.append(
                    {
                        "host": hstr,
                        "header": display,
                        "present": False,
                        "value_sample": "",
                    }
                )
            else:
                sample = lower_map[low_name]
                if len(sample) > 200:
                    sample = sample[:197] + "…"
                rows.append(
                    {
                        "host": hstr,
                        "header": display,
                        "present": True,
                        "value_sample": sample,
                    }
                )
        for low_name in extra_recommended:
            if low_name not in lower_map:
                missing.add(low_name)
    miss_sorted = sorted(missing)
    summary = None
    if miss_sorted:
        summary = "Отсутствуют рекомендуемые заголовки: " + ", ".join(miss_sorted[:12])
    return SecurityHeadersAnalysisModel(
        rows=rows[:500],
        missing_recommended=miss_sorted[:24],
        summary=summary,
    )


def _dependency_rows_from_artifact_json(val: Any, source_key: str) -> list[DependencyAnalysisRow]:
    out: list[DependencyAnalysisRow] = []
    if isinstance(val, list):
        for item in val[:200]:
            if not isinstance(item, dict):
                continue
            pkg = str(item.get("package") or item.get("PkgName") or item.get("name") or "").strip()
            ver = item.get("version") or item.get("InstalledVersion") or item.get("installed_version")
            sev = item.get("severity") or item.get("Severity")
            detail = item.get("detail") or item.get("Title") or item.get("description")
            if pkg:
                out.append(
                    DependencyAnalysisRow(
                        package=pkg[:256],
                        version=str(ver)[:64] if ver is not None else None,
                        severity=str(sev).lower()[:32] if sev is not None else None,
                        source=source_key[-120:],
                        detail=str(detail)[:500] if detail is not None else None,
                    )
                )
    elif isinstance(val, dict):
        findings = val.get("findings")
        if isinstance(findings, list):
            return _dependency_rows_from_artifact_json(findings, source_key)
        results = val.get("Results") or val.get("results")
        if isinstance(results, list):
            return _dependency_rows_from_artifact_json(results, source_key)
        vulns = val.get("vulnerabilities") or val.get("Vulnerabilities")
        if isinstance(vulns, list):
            return _dependency_rows_from_artifact_json(vulns, source_key)
    return out


def _collect_dependency_rows(
    raw_keys: list[tuple[str, str]],
    *,
    fetch_bodies: bool,
) -> list[DependencyAnalysisRow]:
    rows: list[DependencyAnalysisRow] = []
    if not fetch_bodies:
        return rows
    for key, _p in raw_keys:
        if not _artifact_name_matches(key, _DEP_ARTIFACT_HINTS):
            continue
        blob = _safe_download_raw(key)
        if not blob:
            continue
        text = _text_from_raw_bytes(blob)
        if not text or not text.strip().startswith("{"):
            continue
        try:
            val = json.loads(text)
        except json.JSONDecodeError:
            continue
        rows.extend(_dependency_rows_from_artifact_json(val, key))
        if len(rows) >= 300:
            break
    return rows[:300]


def _normalize_severity_label(raw: Any) -> str:
    s = str(raw or "").lower().strip()
    if s in ("informational",):
        return "info"
    return s if s else "info"


_IMPACT_FROM_SEVERITY_03: dict[str, int] = {
    "critical": 3,
    "high": 3,
    "medium": 2,
    "moderate": 2,
    "low": 1,
    "info": 0,
    "informational": 0,
}


def derive_exploit_available_flag(f: dict[str, Any]) -> bool:
    """Derive exploit exposure from intel, PoC payload, or wording (VHQ-004)."""
    intel = f.get("intel")
    if isinstance(intel, dict) and intel.get("exploit_available") is True:
        return True
    poc = f.get("proof_of_concept")
    if isinstance(poc, dict) and poc:
        return True
    title = str(f.get("title") or "").lower()
    desc = str(f.get("description") or "").lower()
    blob = f"{title}\n{desc}"
    if (
        "searchsploit" in blob
        or "metasploit" in blob
        or "public exploit" in blob
        or "exploit available" in blob
    ):
        return True
    st = str(f.get("source_tool") or "").lower()
    if st == "searchsploit" or "exploit" in st:
        return True
    if _CVE_RE.search(blob) and re.search(
        r"\b(exploit|proof.of.concept|poc|metasploit|weaponized)\b", blob, re.IGNORECASE
    ):
        return True
    return False


def _cvss_vector_string(f: dict[str, Any]) -> str | None:
    for k in ("cvss_vector", "cvss_v3_vector", "vectorString", "vector_string"):
        v = f.get(k)
        if isinstance(v, str) and v.strip() and ("/AV:" in v or "CVSS:3" in v):
            return v.strip()
    poc = f.get("proof_of_concept")
    if isinstance(poc, dict):
        for k in ("cvss_vector", "vectorString", "vector_string"):
            pv = poc.get(k)
            if isinstance(pv, str) and pv.strip() and ("/AV:" in pv or "CVSS:3" in pv):
                return pv.strip()
    desc = str(f.get("description") or "")
    m = _CVSS_V3_INLINE_RE.search(desc)
    if m:
        return m.group(0).strip()
    return None


def _impact_score_03(f: dict[str, Any]) -> int:
    vs = _cvss_vector_string(f)
    if vs:
        vals = {"N": 0, "L": 1, "H": 2, "P": 1}
        scores = [vals.get(letter.upper(), 0) for _axis, letter in _CIA_TRIPLET_RE.findall(vs)]
        if scores:
            return min(3, max(scores) * 2)
    sev = _normalize_severity_label(f.get("severity"))
    return min(3, max(0, _IMPACT_FROM_SEVERITY_03.get(sev, 0)))


def _likelihood_score_03(f: dict[str, Any]) -> int:
    score = 0
    vs = _cvss_vector_string(f) or ""
    if _AV_NETWORK_RE.search(vs):
        score += 1
    title = str(f.get("title") or "").lower()
    desc = str(f.get("description") or "").lower()
    blob = f"{title}\n{desc}"
    if re.search(r"\bsearchsploit\b", blob) or "public exploit" in blob or "metasploit" in blob:
        score += 1
    if derive_exploit_available_flag(f):
        score += 1
    return min(3, score)


def _score_to_axis_label(score: int) -> Literal["low", "medium", "high"]:
    if score <= 1:
        return "low"
    if score == 2:
        return "medium"
    return "high"


def _finding_id_for_risk(f: dict[str, Any], fallback_idx: int) -> str:
    for key in ("finding_id", "id"):
        v = f.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return f"finding-{fallback_idx}"


def build_risk_matrix(findings: list[dict[str, Any]]) -> RiskMatrixModel:
    """VHQ-003 — Impact×Likelihood: CIA max from CVSS vector (or severity fallback) × exploit/PoC/AV signals."""
    if not findings:
        return RiskMatrixModel(variant="matrix", cells=[], distribution=[])

    cells_map: dict[
        tuple[Literal["low", "medium", "high"], Literal["low", "medium", "high"]],
        list[str],
    ] = {}
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        imp = _impact_score_03(f)
        lik = _likelihood_score_03(f)
        key = (_score_to_axis_label(imp), _score_to_axis_label(lik))
        fid = _finding_id_for_risk(f, i)
        cells_map.setdefault(key, []).append(fid)

    cells: list[RiskMatrixCellModel] = []
    for (impact_k, likelihood_k), ids in sorted(cells_map.items()):
        cells.append(
            RiskMatrixCellModel(
                impact=impact_k,
                likelihood=likelihood_k,
                finding_ids=ids[:500],
                count=len(ids),
            )
        )
    return RiskMatrixModel(variant="matrix", cells=cells, distribution=[])


def _finding_verified_or_confirmed(f: dict[str, Any]) -> bool:
    st = f.get("status")
    if isinstance(st, str) and st.lower().strip() in ("verified", "confirmed"):
        return True
    intel = f.get("intel")
    if isinstance(intel, dict):
        s = str(intel.get("status") or intel.get("verification_status") or "").lower()
        if s in ("verified", "confirmed"):
            return True
    desc = str(f.get("description") or "")
    return bool(re.search(r"\b(verified|confirmed)\b", desc, re.IGNORECASE))


def _cve_known_exploit_heuristic(f: dict[str, Any]) -> bool:
    blob = f"{f.get('title')}\n{f.get('description')}"
    if not _CVE_RE.search(blob):
        return False
    low = blob.lower()
    return bool(
        re.search(r"\b(exploit|metasploit|searchsploit|weaponized|poc|proof.of.concept)\b", low)
    )


def _critical_vuln_include(f: dict[str, Any]) -> bool:
    cvss_raw = f.get("cvss")
    if not isinstance(cvss_raw, (int, float)) or float(cvss_raw) < 7.0:
        return False
    if _finding_verified_or_confirmed(f):
        return True
    if derive_exploit_available_flag(f):
        return True
    if _cve_known_exploit_heuristic(f):
        return True
    return False


def _critical_vulns_from_findings(findings: list[dict[str, Any]]) -> list[CriticalVulnRefModel]:
    """VHQ-004 — CVSS ≥ 7.0 and (verified/confirmed OR exploit signal OR CVE+exploit heuristic)."""
    out: list[CriticalVulnRefModel] = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        if not _critical_vuln_include(f):
            continue
        fid = _finding_id_for_risk(f, i)
        title = str(f.get("title") or "").strip() or "—"
        cvss = float(f["cvss"]) if isinstance(f.get("cvss"), (int, float)) else None
        desc = str(f.get("description") or "").strip()
        short = _truncate(desc, 280) if desc else ""
        sev = _normalize_severity_label(f.get("severity"))
        out.append(
            CriticalVulnRefModel(
                vuln_id=fid,
                title=title[:500],
                description=short,
                cvss=cvss,
                exploit_available=derive_exploit_available_flag(f),
                severity=sev,
            )
        )
    return out


def _outdated_from_findings(findings: list[dict[str, Any]]) -> list[OutdatedComponentRow]:
    out: list[OutdatedComponentRow] = []
    for f in findings[:200]:
        title = str(f.get("title") or "")
        desc = str(f.get("description") or "")
        blob = f"{title}\n{desc}"
        cves = sorted({m.group(0).upper() for m in _CVE_RE.finditer(blob)})[:16]
        tl = title.lower()
        if not cves and "cve" not in tl and "trivy" not in tl and "searchsploit" not in tl:
            continue
        comp = title.split("—")[0].strip()[:256] or "component"
        st = f.get("source_tool")
        support = str(st) if st else None
        out.append(
            OutdatedComponentRow(
                component=comp,
                installed_version=None,
                latest_stable="—",
                support_status=support,
                cves=cves,
                recommendation="Отслеживать патчи; устранить уязвимые версии по advisory",
            )
        )
    return out[:80]


def _outdated_from_whatweb(merged: dict[str, Any] | None) -> list[OutdatedComponentRow]:
    if not isinstance(merged, dict):
        return []
    plugs = merged.get("plugins")
    if not isinstance(plugs, dict) or not plugs:
        return []
    rows: list[OutdatedComponentRow] = []
    for name, pval in list(plugs.items())[:80]:
        pname = str(name).strip()
        if not pname:
            continue
        detail = _plugin_strings(pval)
        ver_m = re.search(r"\d+(?:\.\d+){1,3}[a-zA-Z0-9._-]*", detail)
        installed = ver_m.group(0) if ver_m else None
        if not detail.strip() and not installed:
            continue
        rows.append(
            OutdatedComponentRow(
                component=pname[:256],
                installed_version=installed,
                latest_stable="—",
                support_status="whatweb",
                cves=[],
                recommendation="Сверить версию с upstream и установить поддерживаемый релиз",
            )
        )
    return rows[:40]


def _outdated_from_nmap_sv(nmap_text: str) -> list[OutdatedComponentRow]:
    rows: list[OutdatedComponentRow] = []
    seen: set[str] = set()
    for line in (nmap_text or "").splitlines():
        m = _NMAP_SV_LINE_RE.match(line.strip())
        if not m:
            continue
        svc = m.group(1).strip()
        rest = m.group(2).strip()
        if not rest or not re.search(r"\d", rest):
            continue
        key = (svc + rest).lower()[:220]
        if key in seen:
            continue
        seen.add(key)
        ver_m = re.search(r"\d+(?:\.\d+){0,3}[a-zA-Z0-9._-]*", rest)
        installed = ver_m.group(0) if ver_m else None
        rows.append(
            OutdatedComponentRow(
                component=f"{svc} ({rest[:120]})"[:256],
                installed_version=installed,
                latest_stable="—",
                support_status="nmap -sV",
                cves=[],
                recommendation="Обновить сервис до исправленной версии (vendor/CVE)",
            )
        )
        if len(rows) >= 40:
            break
    return rows


def _walk_collect_searchsploit_text(obj: Any, acc: list[str]) -> None:
    if isinstance(obj, dict):
        tool = str(obj.get("tool") or "").lower()
        if "searchsploit" in tool or "exploitdb" in tool:
            for k in ("stdout", "stderr", "output", "raw_out", "result"):
                v = obj.get(k)
                if isinstance(v, str) and v.strip():
                    acc.append(v)
        for v in obj.values():
            _walk_collect_searchsploit_text(v, acc)
    elif isinstance(obj, list):
        for it in obj:
            _walk_collect_searchsploit_text(it, acc)


def _outdated_from_searchsploit_phase(phase_outputs: list[tuple[str, dict[str, Any] | None]]) -> list[OutdatedComponentRow]:
    chunks: list[str] = []
    for _ph, od in phase_outputs:
        if isinstance(od, dict):
            _walk_collect_searchsploit_text(od, chunks)
    text = "\n".join(chunks)
    if not text.strip():
        return []
    rows: list[OutdatedComponentRow] = []
    for line in text.splitlines():
        low = line.lower()
        if "searchsploit" not in low and "edb-id" not in low and "edb-" not in low:
            continue
        cves = sorted({m.group(0).upper() for m in _CVE_RE.finditer(line)})[:12]
        if not cves:
            continue
        rows.append(
            OutdatedComponentRow(
                component=_truncate(line.strip(), 200),
                installed_version=None,
                latest_stable="—",
                support_status="searchsploit",
                cves=cves,
                recommendation="Проверить публичный эксплойт и применить патч / компенсирующие меры",
                exploit_available=True,
            )
        )
    return rows[:24]


def _outdated_from_trivy_dependency_rows(
    deps: list[DependencyAnalysisRow],
    *,
    trivy_enabled: bool,
) -> list[OutdatedComponentRow]:
    if not trivy_enabled:
        return []
    rows: list[OutdatedComponentRow] = []
    for d in deps:
        if "trivy" not in (d.source or "").lower():
            continue
        blob = f"{d.package} {d.detail or ''} {d.version or ''}"
        cves = sorted({m.group(0).upper() for m in _CVE_RE.finditer(blob)})[:16]
        sev = (d.severity or "").lower()
        if not cves and sev not in ("critical", "high"):
            continue
        rec = (d.detail or "")[:500] or "Устранить по рекомендациям Trivy / поставщика ПО"
        rows.append(
            OutdatedComponentRow(
                component=d.package[:256],
                installed_version=d.version,
                latest_stable="—",
                support_status="trivy",
                cves=cves,
                recommendation=rec,
                exploit_available=bool(cves) and sev in ("critical", "high"),
            )
        )
    return rows[:80]


def _merge_outdated_rows(groups: list[list[OutdatedComponentRow]]) -> list[OutdatedComponentRow]:
    merged: dict[str, OutdatedComponentRow] = {}
    for group in groups:
        for r in group:
            key = f"{r.component.lower()}|{(r.installed_version or '').lower()}"
            if key not in merged:
                merged[key] = r
            else:
                cur = merged[key]
                cves = sorted(set(cur.cves) | set(r.cves))[:24]
                merged[key] = OutdatedComponentRow(
                    component=cur.component,
                    installed_version=cur.installed_version or r.installed_version,
                    latest_stable=cur.latest_stable if (cur.latest_stable or "") != "—" else r.latest_stable,
                    support_status=cur.support_status or r.support_status,
                    cves=cves,
                    recommendation=(cur.recommendation or r.recommendation)[:800],
                    exploit_available=bool(cur.exploit_available or r.exploit_available),
                )
    return list(merged.values())[:120]


def _assemble_outdated_components(
    *,
    findings: list[dict[str, Any]],
    ww_merged: dict[str, Any] | None,
    nmap_blob: str,
    phase_outputs: list[tuple[str, dict[str, Any] | None]],
    dependency_rows: list[DependencyAnalysisRow],
    trivy_enabled: bool,
) -> list[OutdatedComponentRow]:
    """VHQ-002 — merge findings, WhatWeb/nmap versions, searchsploit hints, optional Trivy rows."""
    return _merge_outdated_rows(
        [
            _outdated_from_findings(findings),
            _outdated_from_whatweb(ww_merged),
            _outdated_from_nmap_sv(nmap_blob),
            _outdated_from_searchsploit_phase(phase_outputs),
            _outdated_from_trivy_dependency_rows(dependency_rows, trivy_enabled=trivy_enabled),
        ]
    )


def _tech_entries_from_whatweb_merged(merged: dict[str, Any] | None) -> list[TechStackEntryModel]:
    if not isinstance(merged, dict):
        return []
    plugs = merged.get("plugins")
    if not isinstance(plugs, dict):
        return []
    out: list[TechStackEntryModel] = []
    for name, pval in sorted(plugs.items(), key=lambda x: str(x[0]).lower()):
        pname = str(name).strip()
        if not pname:
            continue
        detail = _plugin_strings(pval)
        ver_m = re.search(r"\d+(?:\.\d+){1,3}[a-zA-Z0-9._-]*", detail)
        installed = ver_m.group(0) if ver_m else None
        conf: float | None = None
        if isinstance(pval, dict):
            c = pval.get("certainty")
            if isinstance(c, str) and c.strip().isdigit():
                conf = min(1.0, max(0.0, int(c.strip()) / 100.0))
            elif isinstance(c, (int, float)):
                cv = float(c)
                conf = min(1.0, cv / 100.0) if cv > 1.0 else max(0.0, min(1.0, cv))
        out.append(
            TechStackEntryModel(
                technology=pname[:512],
                version=installed,
                confidence=conf,
            )
        )
    return out[:128]


def _structured_stack_effectively_empty(m: TechStackStructuredModel) -> bool:
    if m.entries:
        return False
    return not (
        (m.web_server or "").strip()
        or (m.os or "").strip()
        or (m.cms or "").strip()
        or m.frameworks
        or m.js_libraries
        or (m.ports_summary or "").strip()
        or (m.services_summary or "").strip()
    )


def _first_raw_json_dict_by_substr(
    raw_keys: list[tuple[str, str]],
    substr: str,
    *,
    fetch_bodies: bool,
) -> dict[str, Any] | None:
    if not fetch_bodies:
        return None
    sub = substr.lower()
    for key, _p in raw_keys:
        if sub not in key.lower():
            continue
        blob = _safe_download_raw(key)
        if not blob:
            continue
        text = _text_from_raw_bytes(blob)
        if not text or not text.strip().startswith("{"):
            continue
        try:
            val = json.loads(text.strip())
        except json.JSONDecodeError:
            continue
        if isinstance(val, dict):
            return val
    return None


def _build_robots_sitemap_merged(
    robots: RobotsTxtAnalysisModel,
    sitemap: SitemapAnalysisModel,
    raw_keys: list[tuple[str, str]],
    *,
    fetch_bodies: bool,
) -> RobotsSitemapMergedSummaryModel:
    base = RobotsSitemapMergedSummaryModel(
        robots_found=robots.found,
        sitemap_found=sitemap.found,
        security_txt_reachable=False,
        disallow_rule_count=robots.disallow_rule_count,
        allow_rule_count=robots.allow_rule_count,
        sitemap_url_count=sitemap.url_count,
        sensitive_path_hints=list(robots.sensitive_path_hints or [])[:24],
        notes_ru="",
    )
    jd = _first_raw_json_dict_by_substr(
        raw_keys,
        "recon_robots_sitemap_summary",
        fetch_bodies=fetch_bodies,
    )
    if not isinstance(jd, dict):
        return base
    rs = int(jd.get("robots_http_status") or 0)
    ss = int(jd.get("sitemap_http_status") or 0)
    st = int(jd.get("security_txt_http_status") or 0)
    sens = jd.get("sensitive_path_hints")
    sens_l = [str(x) for x in sens if isinstance(x, str)][:24] if isinstance(sens, list) else []
    return RobotsSitemapMergedSummaryModel(
        robots_found=base.robots_found or (200 <= rs < 500 if rs else False),
        sitemap_found=base.sitemap_found or (200 <= ss < 500 if ss else False),
        security_txt_reachable=bool(st and 200 <= st < 500),
        disallow_rule_count=int(jd.get("disallow_count") or base.disallow_rule_count),
        allow_rule_count=int(jd.get("allow_count") or base.allow_rule_count),
        sitemap_url_count=int(jd.get("sitemap_loc_count") or base.sitemap_url_count),
        sensitive_path_hints=sens_l or base.sensitive_path_hints,
        notes_ru="Сводка по robots.txt / sitemap / security.txt (HTTP fetch + разбор).",
    )


def _masked_emails_from_theharvester_raw(
    raw_keys: list[tuple[str, str]],
    *,
    fetch_bodies: bool,
) -> list[str]:
    if not fetch_bodies:
        return []
    acc: list[str] = []
    for key, _p in raw_keys:
        lowk = key.lower()
        if "theharvester" not in lowk:
            continue
        blob = _safe_download_raw(key)
        if not blob:
            continue
        text = _text_from_raw_bytes(blob)
        if not text:
            continue
        if "emails_masked" in lowk and text.strip().startswith("{"):
            try:
                jd = json.loads(text.strip())
            except json.JSONDecodeError:
                jd = None
            if isinstance(jd, dict):
                em = jd.get("emails_masked")
                if isinstance(em, list):
                    for item in em:
                        if isinstance(item, str) and item.strip():
                            acc.append(item.strip())
                    if len(acc) >= 64:
                        break
                    continue
        if _artifact_name_matches(key, _THEHARVESTER_KEY_HINTS):
            acc.extend(_extract_emails_from_text(text))
        if len(acc) >= 64:
            break
    return acc[:64]


def _ssl_surface_empty(s: SslTlsAnalysisModel) -> bool:
    return not any(
        [
            (s.issuer or "").strip(),
            (s.validity or "").strip(),
            s.protocols,
            s.weak_protocols,
            s.weak_ciphers,
            (s.hsts or "").strip(),
        ]
    )


def _phase_output_excerpt(data: dict[str, Any] | None, max_len: int = 1200) -> str:
    if not isinstance(data, dict) or not data:
        return ""
    try:
        text = json.dumps(data, ensure_ascii=False)
    except (TypeError, ValueError):
        text = str(data)
    return _truncate(text, max_len)


def _collect_leaked_emails(
    phase_outputs: list[tuple[str, dict[str, Any] | None]],
    recon: dict[str, Any] | None,
) -> list[str]:
    chunks: list[str] = []
    if isinstance(recon, dict):
        chunks.append(json.dumps(recon.get("whois") or {}, ensure_ascii=False)[:20000])
    for _ph, od in phase_outputs:
        if od:
            try:
                chunks.append(json.dumps(od, ensure_ascii=False)[:20000])
            except (TypeError, ValueError):
                chunks.append(str(od)[:20000])
    return _extract_emails_from_text("\n".join(chunks))


def _phases_executed_from_outputs(
    phase_outputs: list[tuple[str, dict[str, Any] | None]],
) -> list[str]:
    seen: list[str] = []
    for ph, _ in phase_outputs:
        p = (ph or "").strip()
        if not p or p in seen:
            continue
        seen.append(p)
    return seen


def _raw_keys_hint_flags(raw_artifact_keys: list[tuple[str, str]]) -> dict[str, bool]:
    keys_low = " ".join(k.lower() for k, _ in raw_artifact_keys)
    return {
        "has_whatweb": "whatweb" in keys_low,
        "has_robots": any(_artifact_name_matches(k, _ROBOTS_KEY_HINTS) for k, _ in raw_artifact_keys),
        "has_sitemap": any(_artifact_name_matches(k, _SITEMAP_KEY_HINTS) for k, _ in raw_artifact_keys),
        "has_tls": any(_artifact_name_matches(k, _TLS_ARTIFACT_HINTS) for k, _ in raw_artifact_keys),
        "has_harvester": "theharvester" in keys_low,
    }


def _tool_errors_summary_from_runs(
    tool_run_summaries: list[tuple[str, str]] | None,
    *,
    max_items: int = 48,
) -> list[dict[str, str]]:
    if not tool_run_summaries:
        return []
    bad_status = frozenset({"failed", "error", "timeout", "cancelled", "canceled", "aborted"})
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for name, status in tool_run_summaries:
        n = (name or "").strip()[:200]
        st = (status or "").strip().lower()
        if not n:
            continue
        if st not in bad_status:
            continue
        key = (n.lower(), st)
        if key in seen:
            continue
        seen.add(key)
        out.append({"tool": n, "status": st, "note": "tool_run_finished_non_success"})
        if len(out) >= max_items:
            break
    return out


def _envelope_completed() -> ValhallaSectionEnvelopeModel:
    return ValhallaSectionEnvelopeModel(status="completed", reason="")


def _envelope(
    status: ValhallaSectionCoverageStatus,
    reason: str,
) -> ValhallaSectionEnvelopeModel:
    return ValhallaSectionEnvelopeModel(status=status, reason=(reason or "").strip()[:2000])


def _compute_mandatory_sections_and_coverage(
    *,
    structured: TechStackStructuredModel,
    tech_table: list[TechStackTableRow],
    outdated: list[OutdatedComponentRow],
    ssl_out: SslTlsAnalysisModel,
    sec_hdr: SecurityHeadersAnalysisModel,
    robots: RobotsTxtAnalysisModel,
    sitemap: SitemapAnalysisModel,
    robots_sitemap_merged: RobotsSitemapMergedSummaryModel,
    final_emails: list[str],
    merged_http_headers: dict[str, dict[str, str]],
    deps: list[DependencyAnalysisRow],
    fetch_raw_bodies: bool,
    harvester_enabled: bool,
    trivy_enabled: bool,
    phase_outputs: list[tuple[str, dict[str, Any] | None]],
    raw_artifact_keys: list[tuple[str, str]],
    raw_hints: dict[str, bool],
    tool_run_summaries: list[tuple[str, str]] | None,
    feature_flags: dict[str, bool],
    fallback_messages: dict[str, str | None],
) -> tuple[ValhallaMandatorySectionsModel, ValhallaCoverageModel]:
    phases = _phases_executed_from_outputs(phase_outputs)
    tool_errs = _tool_errors_summary_from_runs(tool_run_summaries)

    # --- tech_stack_structured
    tech_empty = _structured_stack_effectively_empty(structured) and not tech_table
    if not tech_empty:
        tech_env = _envelope_completed()
    elif not fetch_raw_bodies and (raw_hints.get("has_whatweb") or phase_outputs):
        tech_env = _envelope(
            "partial",
            "Not scanned: INCLUDE_MINIO=false — тела raw-артефактов WhatWeb не загружались; "
            "реконструкция стека только из phase_outputs / recon_results.",
        )
    elif not phase_outputs and not fetch_raw_bodies:
        tech_env = _envelope(
            "not_executed",
            "Нет выходов фаз и отключена загрузка raw; tech stack не собирался.",
        )
    else:
        tech_env = _envelope(
            "no_data",
            (fallback_messages.get("tech_stack") or "Стек не определён: нет WhatWeb и недостаточно рекон-сигналов."),
        )

    # --- outdated_components
    if outdated:
        outd_env = _envelope_completed()
    elif trivy_enabled and not any("trivy" in (d.source or "").lower() for d in deps):
        outd_env = _envelope(
            "partial",
            "TRIVY_ENABLED=true, но строк Trivy в dependency_analysis нет; проверьте manifest-артефакты.",
        )
    elif not fetch_raw_bodies and any(
        _artifact_name_matches(k, _DEP_ARTIFACT_HINTS) for k, _ in raw_artifact_keys
    ):
        outd_env = _envelope(
            "partial",
            "Not scanned: INCLUDE_MINIO=false — JSON зависимостей из raw не загружался.",
        )
    else:
        outd_env = _envelope(
            "no_data",
            (
                fallback_messages.get("outdated")
                or "Нет сигналов устаревших компонентов (CVE/Trivy/searchsploit/версии)."
            ),
        )

    ssl_from_recon_only = bool(
        (ssl_out.issuer or ssl_out.validity)
        and not ssl_out.protocols
        and not ssl_out.weak_protocols
        and not ssl_out.weak_ciphers
        and not ssl_out.hsts
    )
    if not _ssl_surface_empty(ssl_out):
        ssl_env = _envelope_completed() if not ssl_from_recon_only else _envelope(
            "partial",
            "Есть данные сертификата из recon; полный TLS-скан (testssl/sslscan) отсутствует или не распарсен.",
        )
    elif not fetch_raw_bodies and raw_hints.get("has_tls"):
        ssl_env = _envelope(
            "not_executed",
            "Not scanned: INCLUDE_MINIO=false — TLS-артефакты есть в индексе, тела не загружались.",
        )
    else:
        ssl_env = _envelope(
            "no_data",
            (fallback_messages.get("ssl_tls") or "SSL/TLS: нет testssl/sslscan и нет данных сертификата."),
        )

    if sec_hdr.rows:
        sec_env = _envelope_completed()
    elif merged_http_headers:
        sec_env = _envelope(
            "partial",
            "Частичные заголовки в данных, но каноническая таблица security headers не построена.",
        )
    else:
        sec_env = _envelope(
            "no_data",
            (
                fallback_messages.get("security_headers")
                or "Нет карты http_headers в recon и вложенных заголовков в фазах."
            ),
        )

    rs_signal = (
        robots_sitemap_merged.robots_found
        or robots_sitemap_merged.sitemap_found
        or robots.found
        or sitemap.found
        or (robots_sitemap_merged.notes_ru or "").strip()
    )
    if robots.found or sitemap.found:
        rs_env = _envelope_completed()
    elif rs_signal and (robots_sitemap_merged.notes_ru or "").strip():
        rs_env = _envelope("partial", "Сводный JSON robots/sitemap; тела robots/sitemap могли быть не разобраны.")
    elif rs_signal:
        rs_env = _envelope_completed()
    elif not fetch_raw_bodies and (raw_hints.get("has_robots") or raw_hints.get("has_sitemap")):
        rs_env = _envelope(
            "not_executed",
            "Not scanned: INCLUDE_MINIO=false — robots/sitemap ключи есть, тела не загружались.",
        )
    else:
        rs_env = _envelope(
            "no_data",
            (fallback_messages.get("robots_sitemap") or "robots.txt и sitemap не получены."),
        )

    if final_emails:
        em_env = _envelope_completed()
    elif harvester_enabled:
        em_env = _envelope(
            "no_data",
            (fallback_messages.get("leaked_emails") or "theHarvester включён, маскированных email в данных нет."),
        )
    else:
        em_env = _envelope(
            "not_executed",
            "Not scanned: HARVESTER_ENABLED=false — целевой сбор email через theHarvester не выполнялся.",
        )

    mandatory = ValhallaMandatorySectionsModel(
        tech_stack_structured=tech_env,
        outdated_components=outd_env,
        ssl_tls_analysis=ssl_env,
        security_headers_analysis=sec_env,
        robots_sitemap_analysis=rs_env,
        leaked_emails=em_env,
    )
    sections_map: dict[str, dict[str, str]] = {}
    for sid in _MANDATORY_SECTION_IDS:
        env = getattr(mandatory, sid, None)
        if env is None:
            continue
        sections_map[sid] = {"status": env.status, "reason": env.reason}

    coverage = ValhallaCoverageModel(
        phases_executed=phases,
        feature_flags=dict(feature_flags),
        sections=sections_map,
        tool_errors_summary=tool_errs,
    )
    return mandatory, coverage


def build_valhalla_minimal_context_patch(
    *,
    phase_outputs: list[tuple[str, dict[str, Any] | None]],
    raw_artifact_keys: list[tuple[str, str]],
    fetch_raw_bodies: bool,
    harvester_enabled: bool,
    trivy_enabled: bool,
    tool_run_summaries: list[tuple[str, str]] | None,
) -> dict[str, Any]:
    """RPT-008 — fill mandatory_sections / coverage / robots_sitemap_analysis for HTML-only export."""
    structured = TechStackStructuredModel()
    tech_table: list[TechStackTableRow] = []
    outdated: list[OutdatedComponentRow] = []
    ssl_out = SslTlsAnalysisModel()
    sec_hdr = SecurityHeadersAnalysisModel()
    robots = RobotsTxtAnalysisModel()
    sitemap = SitemapAnalysisModel()
    merged_rs = RobotsSitemapMergedSummaryModel()
    deps: list[DependencyAnalysisRow] = []
    merged_http: dict[str, dict[str, str]] = {}
    raw_hints = _raw_keys_hint_flags(raw_artifact_keys)
    fb = {
        "tech_stack": None,
        "outdated": None,
        "ssl_tls": None,
        "security_headers": None,
        "robots_sitemap": None,
        "leaked_emails": None,
    }
    mandatory, coverage = _compute_mandatory_sections_and_coverage(
        structured=structured,
        tech_table=tech_table,
        outdated=outdated,
        ssl_out=ssl_out,
        sec_hdr=sec_hdr,
        robots=robots,
        sitemap=sitemap,
        robots_sitemap_merged=merged_rs,
        final_emails=[],
        merged_http_headers=merged_http,
        deps=deps,
        fetch_raw_bodies=fetch_raw_bodies,
        harvester_enabled=harvester_enabled,
        trivy_enabled=trivy_enabled,
        phase_outputs=phase_outputs,
        raw_artifact_keys=raw_artifact_keys,
        raw_hints=raw_hints,
        tool_run_summaries=tool_run_summaries,
        feature_flags={
            "HARVESTER_ENABLED": harvester_enabled,
            "TRIVY_ENABLED": trivy_enabled,
            "INCLUDE_MINIO": fetch_raw_bodies,
        },
        fallback_messages=fb,
    )
    rs_bundle = ValhallaRobotsSitemapAnalysisBundleModel(
        robots_txt=robots,
        sitemap=sitemap,
        merged=merged_rs,
    )
    return {
        "mandatory_sections": mandatory.model_dump(mode="json"),
        "coverage": coverage.model_dump(mode="json"),
        "robots_sitemap_analysis": rs_bundle.model_dump(mode="json"),
    }


def build_valhalla_report_context(
    *,
    tenant_id: str,
    scan_id: str,
    recon_results: dict[str, Any] | None,
    tech_profile: list[dict[str, Any]] | None,
    anomalies_structured: dict[str, Any] | None,
    raw_artifact_keys: list[tuple[str, str]],
    phase_outputs: list[tuple[str, dict[str, Any] | None]],
    phase_inputs: list[tuple[str, dict[str, Any] | None]],
    findings: list[dict[str, Any]],
    report_technologies: list[str] | None,
    fetch_raw_bodies: bool,
    tool_runs: list[tuple[str, dict[str, Any] | None]] | None = None,
    raw_artifact_types: list[str] | None = None,
    trivy_enabled: bool = False,
    harvester_enabled: bool = False,
    tool_run_summaries: list[tuple[str, str]] | None = None,
    extra_feature_flags: dict[str, bool] | None = None,
) -> ValhallaReportContext:
    """Assemble ValhallaReportContext from already-collected scan report inputs."""
    tid = (tenant_id or "").strip()
    sid = (scan_id or "").strip()

    recon_pipeline_summary: dict[str, Any] = {}
    if isinstance(recon_results, dict):
        cand = recon_results.get("recon_pipeline_summary")
        if isinstance(cand, dict):
            recon_pipeline_summary = cand

    robots, sitemap = _collect_robots_sitemap_from_keys(raw_artifact_keys, fetch_bodies=fetch_raw_bodies)
    robots_sitemap_merged = _build_robots_sitemap_merged(
        robots,
        sitemap,
        raw_artifact_keys,
        fetch_bodies=fetch_raw_bodies,
    )

    ports: list[int] | None = None
    for ph, od in phase_outputs:
        if (ph or "").lower() == "recon" and isinstance(od, dict):
            pr = od.get("ports")
            if isinstance(pr, list):
                ports = [int(x) for x in pr if isinstance(x, (int, float))]
            break

    nmap_blob = _nmap_text_from_phase_outputs(phase_outputs)
    what_candidates = _whatweb_roots_from_phase_outputs(phase_outputs) + _whatweb_roots_from_raw_keys(
        raw_artifact_keys,
        fetch_bodies=fetch_raw_bodies,
    )
    ww_merged = merge_whatweb_json_roots(what_candidates)
    base_tech: dict[str, Any]
    if ww_merged:
        base_tech = parse_whatweb_to_tech_stack(ww_merged)
    else:
        base_tech = {
            "web_server": "",
            "os": "",
            "cms": "",
            "frameworks": [],
            "js_libraries": [],
            "ports_summary": "",
            "services_summary": "",
        }
    structured = _dict_to_structured(base_tech)
    structured = _apply_recon_fallbacks_to_structured(
        structured,
        recon_results,
        tech_profile,
        report_technologies,
        ports,
        nmap_blob,
    )
    ww_entries = _tech_entries_from_whatweb_merged(ww_merged)
    if ww_entries:
        structured = structured.model_copy(update={"entries": ww_entries})
    structured_rows = _tech_rows_from_structured(structured)
    legacy_rows = _tech_rows_from_recon(recon_results, tech_profile, report_technologies, ports)
    tech_table = _merge_tech_stack_tables(structured_rows, legacy_rows, structured=structured)

    tls_blob = _latest_tls_blob_from_raw(raw_artifact_keys, fetch_bodies=fetch_raw_bodies)
    ssl_part = _ssl_from_recon_certs(recon_results)
    if tls_blob:
        merged = _ssl_from_testssl_json(tls_blob)
        ssl_out = SslTlsAnalysisModel(
            issuer=merged.issuer or ssl_part.issuer,
            validity=merged.validity or ssl_part.validity,
            protocols=(merged.protocols or ssl_part.protocols),
            weak_protocols=(merged.weak_protocols or ssl_part.weak_protocols),
            weak_ciphers=merged.weak_ciphers or ssl_part.weak_ciphers,
            hsts=merged.hsts or ssl_part.hsts,
        )
    else:
        ssl_out = ssl_part

    merged_http_headers = _http_headers_merged_from_recon_and_phases(recon_results, phase_outputs)
    sec_hdr = _security_headers_from_host_map(merged_http_headers)
    deps = _collect_dependency_rows(raw_artifact_keys, fetch_bodies=fetch_raw_bodies)
    outdated = _assemble_outdated_components(
        findings=findings,
        ww_merged=ww_merged,
        nmap_blob=nmap_blob,
        phase_outputs=phase_outputs,
        dependency_rows=deps,
        trivy_enabled=trivy_enabled,
    )
    risk_matrix = build_risk_matrix(findings)
    critical_vulns = _critical_vulns_from_findings(findings)

    threat_excerpt = ""
    threat_phase = "threat_modeling"
    for ph, od in phase_outputs:
        if (ph or "").lower() == threat_phase and od:
            tm = od.get("threat_model")
            if isinstance(tm, dict) and tm:
                threat_excerpt = _phase_output_excerpt(tm, 1500)
            else:
                threat_excerpt = _phase_output_excerpt(od, 1500)
            break

    api_hint = ""
    if tid and sid:
        api_hint = f"/api/v1/tenants/{tid}/scans/{sid}/phases/{threat_phase}"

    threat_ref = ThreatModelRefModel(
        phase=threat_phase,
        scan_id=sid,
        tenant_id=tid,
        excerpt=threat_excerpt,
        api_hint=api_hint,
    )

    exploit_chunks: list[str] = []
    for ph, od in phase_outputs:
        pl = (ph or "").lower()
        if pl in ("exploitation", "post_exploitation") and od:
            exploit_chunks.append(_phase_output_excerpt(od, 800))
    exploit_post_excerpt = _truncate("\n\n".join(exploit_chunks), 2500)

    emails = _collect_leaked_emails(phase_outputs, recon_results)
    emails.extend(
        _masked_emails_from_theharvester_raw(
            raw_artifact_keys,
            fetch_bodies=fetch_raw_bodies,
        )
    )
    if isinstance(anomalies_structured, dict):
        try:
            emails.extend(_extract_emails_from_text(json.dumps(anomalies_structured, ensure_ascii=False)))
        except (TypeError, ValueError):
            pass
    for _ph, inp in phase_inputs:
        if isinstance(inp, dict):
            try:
                emails.extend(_extract_emails_from_text(json.dumps(inp, ensure_ascii=False)[:20000]))
            except (TypeError, ValueError):
                pass

    seen_m: set[str] = set()
    final_emails: list[str] = []
    for e in emails:
        if e not in seen_m:
            seen_m.add(e)
            final_emails.append(e)
        if len(final_emails) >= 64:
            break

    appendix_tools = build_appendix_tools(
        tool_runs=tool_runs,
        phase_outputs=phase_outputs,
        raw_artifact_types=raw_artifact_types,
    )

    tech_stack_fallback_message: str | None = None
    if _structured_stack_effectively_empty(structured) and not tech_table:
        tech_stack_fallback_message = (
            "Стек технологий не определён автоматически: нет валидного вывода WhatWeb "
            "или недостаточно рекон-сигналов для заполнения таблицы."
        )

    ssl_tls_fallback_message: str | None = None
    if _ssl_surface_empty(ssl_out):
        ssl_tls_fallback_message = (
            "Данные SSL/TLS отсутствуют или не получены: для HTTPS ожидается вывод testssl.sh (JSON) "
            "или sslscan в сырых артефактах; для HTTP цели TLS-проверка не выполнялась. "
            "При необходимости проверьте политику VA и наличие testssl.sh в sandbox."
        )

    security_headers_fallback_message: str | None = None
    if not sec_hdr.rows and not merged_http_headers:
        security_headers_fallback_message = (
            "Анализ заголовков безопасности недоступен: нет карты http_headers в recon_results.json "
            "и не найдено вложенных заголовков в выходах фаз recon/vuln_analysis."
        )

    outdated_components_fallback_message: str | None = None
    if not outdated:
        has_trivy_rows = any("trivy" in (d.source or "").lower() for d in deps)
        if trivy_enabled and not has_trivy_rows:
            outdated_components_fallback_message = (
                "Trivy включён, но manifest'ы зависимостей не собраны или отчёт Trivy пуст; "
                "блок устаревших компонентов по SCA не заполнен (проверьте сбор артефактов и TRIVY_ENABLED)."
            )
        else:
            outdated_components_fallback_message = (
                "Явных сигналов устаревших компонентов (CVE, Trivy, searchsploit, версии из WhatWeb/nmap) "
                "в данных сканирования нет."
            )

    robots_sitemap_fallback_message: str | None = None
    if not robots_sitemap_merged.robots_found and not robots_sitemap_merged.sitemap_found:
        robots_sitemap_fallback_message = (
            "robots.txt и sitemap не получены или недоступны по HTTP; расширенный анализ поверхности "
            "по ним отсутствует."
        )

    leaked_emails_fallback_message: str | None = None
    if not final_emails:
        leaked_emails_fallback_message = (
            "Маскированные email-индикаторы не обнаружены. При HARVESTER_ENABLED=true theHarvester "
            "добавляет сигналы из stdout-артефактов; иначе возможны только косвенные совпадения в recon."
        )

    ff: dict[str, bool] = {
        "HARVESTER_ENABLED": bool(harvester_enabled),
        "TRIVY_ENABLED": bool(trivy_enabled),
        "INCLUDE_MINIO": bool(fetch_raw_bodies),
    }
    if extra_feature_flags:
        ff.update({str(k): bool(v) for k, v in extra_feature_flags.items()})

    raw_hints = _raw_keys_hint_flags(raw_artifact_keys)
    mandatory, coverage = _compute_mandatory_sections_and_coverage(
        structured=structured,
        tech_table=tech_table,
        outdated=outdated,
        ssl_out=ssl_out,
        sec_hdr=sec_hdr,
        robots=robots,
        sitemap=sitemap,
        robots_sitemap_merged=robots_sitemap_merged,
        final_emails=final_emails,
        merged_http_headers=merged_http_headers,
        deps=deps,
        fetch_raw_bodies=fetch_raw_bodies,
        harvester_enabled=harvester_enabled,
        trivy_enabled=trivy_enabled,
        phase_outputs=phase_outputs,
        raw_artifact_keys=raw_artifact_keys,
        raw_hints=raw_hints,
        tool_run_summaries=tool_run_summaries,
        feature_flags=ff,
        fallback_messages={
            "tech_stack": tech_stack_fallback_message,
            "outdated": outdated_components_fallback_message,
            "ssl_tls": ssl_tls_fallback_message,
            "security_headers": security_headers_fallback_message,
            "robots_sitemap": robots_sitemap_fallback_message,
            "leaked_emails": leaked_emails_fallback_message,
        },
    )
    rs_analysis_bundle = ValhallaRobotsSitemapAnalysisBundleModel(
        robots_txt=robots,
        sitemap=sitemap,
        merged=robots_sitemap_merged,
    )

    return ValhallaReportContext(
        robots_txt_analysis=robots,
        sitemap_analysis=sitemap,
        robots_sitemap_merged=robots_sitemap_merged,
        tech_stack_structured=structured,
        tech_stack_table=tech_table,
        tech_stack_fallback_message=tech_stack_fallback_message,
        ssl_tls_fallback_message=ssl_tls_fallback_message,
        security_headers_fallback_message=security_headers_fallback_message,
        outdated_components_fallback_message=outdated_components_fallback_message,
        robots_sitemap_fallback_message=robots_sitemap_fallback_message,
        leaked_emails_fallback_message=leaked_emails_fallback_message,
        outdated_components=outdated,
        leaked_emails=final_emails,
        ssl_tls_analysis=ssl_out,
        security_headers_analysis=sec_hdr,
        dependency_analysis=deps,
        threat_model=threat_ref,
        threat_model_excerpt=threat_ref.excerpt,
        threat_model_phase_link=threat_ref.api_hint,
        exploitation_post_excerpt=exploit_post_excerpt,
        risk_matrix=risk_matrix,
        critical_vulns=critical_vulns,
        appendix_tools=appendix_tools,
        mandatory_sections=mandatory,
        robots_sitemap_analysis=rs_analysis_bundle,
        coverage=coverage,
        recon_pipeline_summary=recon_pipeline_summary,
        xss_structured=build_xss_structured_rows_from_findings(findings),
    )
