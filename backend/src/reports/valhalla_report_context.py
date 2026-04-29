"""VHL-001 — Valhalla-tier structured context for reports (recon + raw artifacts + phases).

Safe defaults: empty lists / false / None. No secrets in logs; raw excerpts are capped.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import logging
import re
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.recon.vulnerability_analysis.active_scan.whatweb_va_adapter import (
    _plugin_strings,
    merge_whatweb_json_roots,
    parse_whatweb_stdout,
    parse_whatweb_text_fallback,
    parse_whatweb_to_tech_stack,
)
from src.reports.report_quality_gate import (
    build_active_injection_coverage,
    is_header_only_advisory_finding,
)
from src.storage.s3 import download_by_key

ValhallaSectionCoverageStatus = Literal[
    "completed",
    "completed_with_fallback",
    "partial",
    "parsed_from_fallback",
    "no_observed_items_after_parsing",
    "not_executed",
    "no_data",
    "not_assessed",
    "parser_error",
    "artifact_missing_body",  # tool/phase metadata or object keys exist, but no fetchable stdout/body
]

_MANDATORY_SECTION_IDS: tuple[str, ...] = (
    "tech_stack_structured",
    "outdated_components",
    "ssl_tls_analysis",
    "security_headers_analysis",
    "robots_sitemap_analysis",
    "leaked_emails",
    "port_exposure",
)

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
        "yarn_lock",
        "pnpm_lock",
        "manifest",
        "package_lock",
        "package_json",
        "package.json",
        "requirements",
        "poetry",
        "composer",
        "go.mod",
        "go_sum",
    }
)
_HTTP_HEADER_ARTIFACT_HINTS = frozenset(
    {"headers", "http_audit", "httpx", "nikto", "response", "raw_http", "curl"}
)
_EMAIL_FALLBACK_ARTIFACT_HINTS = frozenset(
    {"theharvester", "email", "contact", "html", "javascript", "js", "sitemap", "robots"}
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
    version: str = ""
    confidence: str = ""
    security_note: str = ""


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
    source: str = ""
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


class SslTlsTableRowModel(BaseModel):
    """VH-008 — one row for SSL/TLS results table (domain-level when recon ssl_certs exists)."""

    model_config = ConfigDict(extra="forbid")

    domain: str = ""
    cert_subject: str = ""
    issuer: str = ""
    dates: str = ""
    days_remaining: str = ""
    tls_1_0: str = ""
    tls_1_1: str = ""
    tls_1_2: str = ""
    tls_1_3: str = ""
    weak_ciphers: str = ""
    hsts: str = ""
    chain_issues: str = ""
    evidence_id: str = ""


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
    cvss_vector: str | None = None
    exploit_available: bool = False
    """Alias for legacy templates; use exploit_demonstrated for truth (VAL-003)."""
    exploit_demonstrated: bool = False
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


class PortExposureSummaryModel(BaseModel):
    """VH-003 — ports / services from nmap, naabu, recon list, and structured stack hints."""

    model_config = ConfigDict(extra="forbid")

    has_open_ports: bool = False
    open_port_hints: list[str] = Field(default_factory=list)
    services_summary: str = ""
    summary_text: str = ""
    data_sources: list[str] = Field(default_factory=list)
    has_naabu_hits: bool = False
    has_nmap_hits: bool = False
    has_recon_port_list: bool = False


class PortExposureTableRowModel(BaseModel):
    """Customer-facing port/service exposure row."""

    model_config = ConfigDict(extra="forbid")

    host: str = ""
    port: str = ""
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    source: str = ""
    confidence: str = ""
    exposure_note: str = ""


class LeakedEmailRowModel(BaseModel):
    """Customer-facing email/OSINT evidence row with masked addresses only."""

    model_config = ConfigDict(extra="forbid")

    email: str = ""
    source: str = ""
    context: str = ""
    risk: str = ""
    evidence_id: str = ""


class EvidenceInventoryRowModel(BaseModel):
    """VH-001 — customer-safe evidence list (no MinIO URLs, no raw JSON)."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    finding_or_section: str = ""
    source_tool: str = ""
    evidence_type: str = ""
    summary: str = ""
    timestamp: str = ""
    status: str = ""


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
    port_exposure: ValhallaSectionEnvelopeModel = Field(default_factory=ValhallaSectionEnvelopeModel)


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
    notes: str = ""
    notes_ru: str = Field(default="", description="Deprecated: backward-compat alias for notes.")

    @model_validator(mode="after")
    def _migrate_notes_ru(self) -> "RobotsSitemapMergedSummaryModel":
        """Copy legacy notes_ru → notes when notes is empty (backward compat)."""
        if not self.notes and self.notes_ru:
            self.notes = self.notes_ru
        return self


class ValhallaRobotsSitemapAnalysisBundleModel(BaseModel):
    """Single object for Jinja: robots + sitemap + merged summary (T6 naming)."""

    model_config = ConfigDict(extra="forbid")

    robots_txt: RobotsTxtAnalysisModel = Field(default_factory=RobotsTxtAnalysisModel)
    sitemap: SitemapAnalysisModel = Field(default_factory=SitemapAnalysisModel)
    merged: RobotsSitemapMergedSummaryModel = Field(default_factory=RobotsSitemapMergedSummaryModel)


class ScanMetadataModel(BaseModel):
    """ENH-V3 — Strix-style scan metadata for Valhalla report."""

    model_config = ConfigDict(extra="forbid")

    scan_mode: str = "standard"
    agents_spawned: int = 0
    categories_tested: list[str] = Field(default_factory=list)
    categories_not_tested: list[str] = Field(default_factory=list)
    skills_used: list[str] = Field(default_factory=list)
    noise_reduction_pct: float = 0.0
    owasp_coverage_pct: float = 0.0
    findings_total: int = 0
    findings_validated: int = 0
    findings_rejected: int = 0
    findings_deduplicated: int = 0


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
    leaked_email_rows: list[LeakedEmailRowModel] = Field(default_factory=list)
    ssl_tls_analysis: SslTlsAnalysisModel = Field(default_factory=SslTlsAnalysisModel)
    ssl_tls_table_rows: list[SslTlsTableRowModel] = Field(default_factory=list)
    security_headers_analysis: SecurityHeadersAnalysisModel = Field(
        default_factory=SecurityHeadersAnalysisModel
    )
    security_headers_table_rows: list[dict[str, Any]] = Field(default_factory=list)
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
    scan_metadata: ScanMetadataModel = Field(default_factory=ScanMetadataModel)
    wstg_coverage: dict[str, Any] | None = None
    test_limitations: list[dict[str, str]] | None = None
    valhalla_engagement_title: str = "Valhalla Automated Security Assessment"
    full_valhalla: bool = False
    port_exposure: PortExposureSummaryModel = Field(default_factory=PortExposureSummaryModel)
    port_exposure_table_rows: list[PortExposureTableRowModel] = Field(default_factory=list)
    evidence_inventory: list[EvidenceInventoryRowModel] = Field(default_factory=list)
    tool_health_summary: list[dict[str, Any]] = Field(default_factory=list)
    wstg_execution_degraded: bool = False
    wstg_coverage_zero_executed: bool = False
    #: SCA / Trivy transparency (VHL — URL-only vs filesystem vs image)
    sca_mode: str = "none"
    trivy_run_status: str = "not_applicable"
    sca_manifest_count: int = 0
    sca_artifact_count: int = 0
    #: Placeholder for active injection coverage (Phase 2: scheduler + parsers). Safe default.
    active_injection_coverage: dict[str, Any] = Field(default_factory=dict)


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


def _artifact_type_from_raw_key(key: str) -> str:
    """Extract artifact_type from ``{timestamp}_{artifact_type}.{ext}`` raw object keys."""
    basename = key.rsplit("/", 1)[-1] if "/" in key else key
    name_no_ext = basename.rsplit(".", 1)[0] if "." in basename else basename
    parts = name_no_ext.split("_", 2)
    if len(parts) >= 3:
        return parts[2]
    return name_no_ext


def _tool_name_from_raw_key(key: str) -> str | None:
    at = _artifact_type_from_raw_key(key)
    if not at.startswith("tool_"):
        return None
    body = at[len("tool_") :]
    for stream_marker in ("_stdout", "_stderr", "_meta"):
        idx = body.find(stream_marker)
        if idx > 0:
            body = body[:idx]
            break
    for sep in ("_scan_", "_celery_", "_cand_", "_http_audit_"):
        if sep in body:
            body = body.split(sep, 1)[0]
            break
    name = body.strip("_")
    return name[:200] if name else None


def _raw_artifact_stream_kind(key: str) -> Literal["stdout", "stderr", "meta"] | None:
    parts = _artifact_type_from_raw_key(key).split("_")
    if "stdout" in parts:
        return "stdout"
    if "stderr" in parts:
        return "stderr"
    if parts and parts[-1] == "meta":
        return "meta"
    return None


def _first_stderr_note(text: str) -> str:
    for line in (text or "").splitlines():
        s = line.strip()
        if s:
            return _truncate(s, 180)
    return "stderr_nonempty"


def _raw_tool_issues_from_artifacts(
    raw_artifact_keys: list[tuple[str, str]],
    *,
    fetch_bodies: bool,
    max_items: int = 48,
) -> list[dict[str, str]]:
    """Infer failed/empty tool attempts from raw stdout/stderr/meta artifacts.

    DB tool_run status can be green even when a sandboxed binary produced empty stdout
    and only stderr/meta. Valhalla coverage should make that visible instead of
    presenting the related data section as neutral ``no_data``.
    """
    if not fetch_bodies:
        return []
    state: dict[str, dict[str, Any]] = {}
    for key, _phase in raw_artifact_keys:
        tool = _tool_name_from_raw_key(key)
        kind = _raw_artifact_stream_kind(key)
        if not tool or not kind:
            continue
        cur = state.setdefault(
            tool,
            {
                "stdout_seen": False,
                "stdout_nonempty": False,
                "stderr_note": "",
                "error_reason": "",
                "exit_code": None,
            },
        )
        blob = _safe_download_raw(key)
        if blob is None:
            continue
        text = _text_from_raw_bytes(blob) or ""
        if kind == "stdout":
            cur["stdout_seen"] = True
            cur["stdout_nonempty"] = bool(text.strip())
        elif kind == "stderr":
            if text.strip() and not cur.get("stderr_note"):
                cur["stderr_note"] = _first_stderr_note(text)
        elif kind == "meta" and text.strip().startswith("{"):
            try:
                meta = json.loads(text)
            except json.JSONDecodeError:
                meta = {}
            if isinstance(meta, dict):
                err = meta.get("error_reason")
                if isinstance(err, str) and err.strip():
                    cur["error_reason"] = err.strip()[:160]
                ec = meta.get("exit_code")
                with contextlib.suppress(TypeError, ValueError):
                    cur["exit_code"] = int(ec) if ec is not None else None

    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for tool, info in sorted(state.items()):
        exit_code = info.get("exit_code")
        exit_bad = isinstance(exit_code, int) and exit_code != 0
        error_reason = str(info.get("error_reason") or "").strip()
        stderr_note = str(info.get("stderr_note") or "").strip()
        stdout_seen = bool(info.get("stdout_seen"))
        stdout_nonempty = bool(info.get("stdout_nonempty"))
        if not (error_reason or exit_bad or (stderr_note and stdout_seen and not stdout_nonempty)):
            continue
        key = tool.lower()
        if key in seen:
            continue
        seen.add(key)
        if error_reason:
            status = "failed"
            note = f"raw_meta_error:{error_reason}"
        elif exit_bad:
            status = "failed"
            note = f"raw_meta_exit_code:{exit_code}"
        else:
            status = "no_output"
            note = "stderr_nonempty_with_empty_stdout"
        if stderr_note:
            note = f"{note}; stderr:{stderr_note}"
        out.append({"tool": tool, "status": status, "note": _truncate(note, 240)})
        if len(out) >= max_items:
            break
    return out


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
    masked_local = local[0] + "***" if len(local) <= 2 else local[0] + "***" + local[-1]
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


# Filename / artifact_type fragments treated like stdout-equivalent bodies (JSON/XML/tool logs).
_RAW_ARTIFACT_JSONISH_KEY_FRAGMENTS: tuple[str, ...] = (
    ".json",
    ".xml",
    "whatweb",
    "testssl",
    "sslscan",
    "sslyze",
    "tlsx",
    "nikto",
    "nmap",
    "naabu",
    "masscan",
    "trivy",
    "httpx",
    "http_audit",
    "wfuzz",
    "ffuf",
    "nuclei",
    "gobuster",
    "feroxbuster",
    "wpscan",
    "osv",
    "sarif",
    "semgrep",
    "pip_audit",
    "npm_audit",
    "safety",
)


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


def _artifact_non_empty_body_for_needles(
    raw_artifact_keys: list[tuple[str, str]],
    fetch_bodies: bool,
    needles: tuple[str, ...],
    *,
    require_stdoutish: bool = True,
) -> bool:
    """True when at least one raw object for ``needles`` downloads to non-empty text (stdout/result, not metadata-only)."""
    if not fetch_bodies or not raw_artifact_keys or not needles:
        return False
    for key, _ph in raw_artifact_keys:
        low = key.lower()
        if any(n in low for n in needles):
            if "stderr" in low and "_stdout" not in low:
                continue
            if low.endswith("_meta.txt") or low.rsplit("/", 1)[-1].endswith("_meta.txt"):
                continue
            if require_stdoutish and "stdout" not in low and "output" not in low:
                if not any(x in low for x in _RAW_ARTIFACT_JSONISH_KEY_FRAGMENTS):
                    continue
            blob = _safe_download_raw(key)
            if not blob:
                continue
            if (_text_from_raw_bytes(blob) or "").strip():
                return True
    return False


def raw_artifact_has_non_empty_body_for_needles(
    raw_artifact_keys: list[tuple[str, str]],
    fetch_bodies: bool,
    needles: tuple[str, ...],
    *,
    require_stdoutish: bool = True,
) -> bool:
    """Public helper for tests / callers: true when a matching raw object has a non-empty text body."""
    return _artifact_non_empty_body_for_needles(
        raw_artifact_keys,
        fetch_bodies,
        needles,
        require_stdoutish=require_stdoutish,
    )


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
_NAABU_LINE_RE = re.compile(r"^([^\s:\[\]]+):(\d+)", re.IGNORECASE)


def _raw_has_port_scan_artifact_keys(raw_artifact_keys: list[tuple[str, str]]) -> bool:
    for k, _ in raw_artifact_keys:
        kl = k.lower()
        if any(x in kl for x in ("nmap", "naabu", "masscan")):
            return True
    return False


def _naabu_text_from_raw_keys(
    raw_artifact_keys: list[tuple[str, str]],
    *,
    fetch_bodies: bool,
) -> str:
    if not fetch_bodies:
        return ""
    chunks: list[str] = []
    for key, _ in raw_artifact_keys:
        kl = key.lower()
        if "naabu" not in kl:
            continue
        if "stdout" not in kl and "output" not in kl and "result" not in kl:
            continue
        blob = _safe_download_raw(key)
        if not blob:
            continue
        t = _text_from_raw_bytes(blob) or ""
        if t.strip():
            chunks.append(t[: _MAX_TECH_MERGE])
    merged = "\n".join(chunks)
    if len(merged) > _MAX_TECH_MERGE:
        return merged[: _MAX_TECH_MERGE - 1] + "…"
    return merged


def _port_hints_from_naabu(text: str) -> list[str]:
    out: list[str] = []
    for line in (text or "").splitlines():
        m = _NAABU_LINE_RE.match(line.strip())
        if m:
            out.append(f"{m.group(2)}/tcp (naabu)")
    return out[:64]


def _build_port_exposure_summary(
    *,
    nmap_blob: str,
    ports: list[int] | None,
    structured: TechStackStructuredModel,
    raw_artifact_keys: list[tuple[str, str]],
    fetch_bodies: bool,
    target_hint: str = "",
    tls_observed: bool = False,
    http_observed: bool = False,
) -> PortExposureSummaryModel:
    sources: list[str] = []
    hints: list[str] = []
    nmap_hits = bool(_NMAP_OPEN_LINE_RE.search(nmap_blob or ""))
    if nmap_hits:
        sources.append("nmap")
    for line in (nmap_blob or "").splitlines():
        if _NMAP_OPEN_LINE_RE.search(line):
            hints.append(line.strip()[:256])
    naabu_t = _naabu_text_from_raw_keys(raw_artifact_keys, fetch_bodies=fetch_bodies)
    naabu_ports = _port_hints_from_naabu(naabu_t)
    if naabu_ports:
        sources.append("naabu")
        hints.extend(naabu_ports)
    has_recon = False
    if ports:
        has_recon = True
        sources.append("recon phase output")
        hints.extend(f"{int(p)}/tcp" for p in sorted({int(x) for x in ports if isinstance(x, (int, float))})[:48])
    ps = (structured.ports_summary or "").strip()
    ss = (structured.services_summary or "").strip()
    if ps or ss:
        sources.append("fingerprinting / recon merge")
    parsed_target = urlparse(target_hint if "://" in target_hint else f"//{target_hint}")
    scheme = (parsed_target.scheme or "").lower()
    host_from_target = parsed_target.hostname or (target_hint.split("/", 1)[0] if target_hint else "")
    raw_key_names = " ".join(k.lower() for k, _p in raw_artifact_keys)
    http_artifact_observed = any(
        token in raw_key_names
        for token in (
            "http",
            "headers",
            "security_headers",
            "whatweb",
            "nikto",
            "robots",
            "sitemap",
            "url_history",
            "head_spider",
        )
    )
    tls_artifact_observed = any(token in raw_key_names for token in ("testssl", "sslscan", "tls", "openssl"))
    https_confirmed = tls_observed or http_observed or http_artifact_observed or tls_artifact_observed
    http_confirmed = http_observed or http_artifact_observed
    if not hints and host_from_target:
        if scheme == "https" and https_confirmed:
            sources.append("HTTPS artifact fallback")
            hints.append("443/tcp open (confirmed by collected HTTPS/HTTP artifact)")
        elif scheme == "http" and http_confirmed:
            sources.append("HTTP artifact fallback")
            hints.append("80/tcp open (confirmed by HTTP response artifact)")
    elif host_from_target and scheme == "https" and https_confirmed and not any("443/" in h for h in hints):
        sources.append("HTTPS artifact fallback")
        hints.append("443/tcp open (confirmed by collected HTTPS/HTTP artifact)")
    elif host_from_target and scheme == "http" and http_confirmed and not any("80/" in h for h in hints):
        sources.append("HTTP artifact fallback")
        hints.append("80/tcp open (confirmed by HTTP response artifact)")
    summary_bits = [x for x in (ps, ss, _services_summary_from_nmap_text(nmap_blob)) if (x or "").strip()]
    summary_text = "; ".join(summary_bits)[:2000] if summary_bits else ""
    if not summary_text and hints:
        summary_text = "Open port signals: " + ", ".join(hints[:16])
    has_open = bool(hints) or nmap_hits or has_recon or bool(ps) or bool(ss)
    return PortExposureSummaryModel(
        has_open_ports=has_open,
        open_port_hints=sorted({h for h in hints if h}, key=str)[:48],
        services_summary=_services_summary_from_nmap_text(nmap_blob)[:_MAX_TECH_MERGE],
        summary_text=summary_text,
        data_sources=sorted(set(sources)),
        has_naabu_hits=bool(naabu_ports),
        has_nmap_hits=nmap_hits,
        has_recon_port_list=has_recon,
    )


def _guess_tool_from_finding(f: dict[str, Any]) -> str:
    blob = f"{f.get('title', '')} {f.get('description', '')}".lower()
    for needle, label in (
        ("nuclei", "Nuclei"),
        ("zap", "OWASP ZAP"),
        ("burp", "Burp"),
        ("nikto", "Nikto"),
        ("sqlmap", "sqlmap"),
        ("nmap", "nmap"),
        ("ffuf", "ffuf"),
    ):
        if needle in blob:
            return label
    et = f.get("evidence_type")
    if isinstance(et, str) and et.strip():
        return et.strip()[:120]
    return "pipeline / scanner"


def build_evidence_inventory_rows(
    findings: list[dict[str, Any]],
    *,
    ssl_tls: SslTlsAnalysisModel,
    security_headers: SecurityHeadersAnalysisModel,
    tech_stack: list[TechStackTableRow] | None = None,
    port_exposure: PortExposureSummaryModel | None = None,
    port_rows: list[PortExposureTableRowModel] | None = None,
    outdated_components: list[OutdatedComponentRow] | None = None,
    leaked_email_rows: list[LeakedEmailRowModel] | None = None,
) -> list[EvidenceInventoryRowModel]:
    from src.reports.report_quality_gate import score_evidence_quality

    rows: list[EvidenceInventoryRowModel] = []
    n = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        n += 1
        evq = score_evidence_quality(f)
        status = {
            "strong": "verified",
            "moderate": "collected",
            "weak": "limited",
            "none": "insufficient",
        }.get(evq, "unknown")
        refs = f.get("evidence_refs")
        refs_list = [str(x) for x in refs[:3] if str(x).strip()] if isinstance(refs, list) else []
        poc = f.get("proof_of_concept")
        poc_bits: list[str] = []
        if isinstance(poc, dict):
            for key in ("request_method", "request_url", "response_status", "validation_status"):
                val = poc.get(key)
                if val:
                    poc_bits.append(f"{key}={str(val)[:120]}")
        summary_bits = []
        if refs_list:
            summary_bits.append("Refs: " + "; ".join(refs_list))
        if poc_bits:
            summary_bits.append("PoC: " + "; ".join(poc_bits))
        if not summary_bits:
            summary_bits.append("Finding evidence metadata parsed; raw storage paths omitted.")
        created = f.get("created_at")
        ts = str(created)[:40] if created is not None else "—"
        rows.append(
            EvidenceInventoryRowModel(
                evidence_id=f"EV-{n:04d}",
                finding_or_section=str(f.get("title") or f.get("id") or "Finding")[:500],
                source_tool=_guess_tool_from_finding(f),
                evidence_type=str(f.get("evidence_type") or "scanner / VA output")[:200],
                summary=_truncate(" ".join(summary_bits), 500),
                timestamp=ts,
                status=status,
            )
        )
    if tech_stack:
        n += 1
        sample = "; ".join(
            f"{r.category}: {r.name}{' ' + r.version if r.version else ''}"
            for r in tech_stack[:6]
            if r.name
        )
        rows.append(
            EvidenceInventoryRowModel(
                evidence_id=f"EV-{n:04d}",
                finding_or_section="Technology stack",
                source_tool="WhatWeb / HTTP artifacts / recon",
                evidence_type="Technology fingerprint",
                summary=_truncate(sample or "Technology rows parsed from collected artifacts.", 500),
                timestamp="—",
                status="collected",
            )
        )
    if not _ssl_surface_empty(ssl_tls):
        n += 1
        sm_parts = []
        if ssl_tls.issuer:
            sm_parts.append(f"Certificate issuer: {ssl_tls.issuer}")
        if ssl_tls.validity:
            sm_parts.append(f"Validity: {ssl_tls.validity}")
        if ssl_tls.protocols:
            sm_parts.append("TLS protocols observed: " + ", ".join(ssl_tls.protocols[:4]))
        if ssl_tls.hsts:
            sm_parts.append(f"HSTS: {ssl_tls.hsts}")
        sm = "; ".join(sm_parts)
        rows.append(
            EvidenceInventoryRowModel(
                evidence_id=f"EV-{n:04d}",
                finding_or_section="SSL/TLS",
                source_tool="testssl.sh / sslscan / recon",
                evidence_type="TLS configuration",
                summary=_truncate((sm or "TLS section populated")[:500], 500),
                timestamp="—",
                status="collected",
            )
        )
    if security_headers.rows:
        n += 1
        rows.append(
            EvidenceInventoryRowModel(
                evidence_id=f"EV-{n:04d}",
                finding_or_section="HTTP security headers",
                source_tool="recon / httpx / nikto",
                evidence_type="Response headers",
                summary=_truncate(
                    f"HTTP response headers parsed; rows={len(security_headers.rows)}; "
                    f"missing={', '.join(security_headers.missing_recommended[:8]) or 'none observed'}",
                    500,
                ),
                timestamp="—",
                status="collected",
            )
        )
    if port_rows or (port_exposure and port_exposure.has_open_ports):
        n += 1
        port_summary = "; ".join(
            f"{r.port}/{r.protocol} {r.state} {r.service}".strip()
            for r in (port_rows or [])[:8]
        )
        if not port_summary and port_exposure:
            port_summary = port_exposure.summary_text or "; ".join(port_exposure.open_port_hints[:8])
        rows.append(
            EvidenceInventoryRowModel(
                evidence_id=f"EV-{n:04d}",
                finding_or_section="Port exposure",
                source_tool="Nmap / Naabu / recon fallback",
                evidence_type="Port/service observation",
                summary=_truncate(port_summary or "Open-port signals parsed.", 500),
                timestamp="—",
                status="collected",
            )
        )
    if outdated_components:
        n += 1
        comp_summary = "; ".join(
            f"{r.component}{' ' + r.installed_version if r.installed_version else ''}"
            for r in outdated_components[:8]
        )
        rows.append(
            EvidenceInventoryRowModel(
                evidence_id=f"EV-{n:04d}",
                finding_or_section="Component inventory / SCA",
                source_tool="Trivy / manifests / fingerprints",
                evidence_type="Component/version inventory",
                summary=_truncate(comp_summary or "Component inventory parsed.", 500),
                timestamp="—",
                status="collected",
            )
        )
    if leaked_email_rows is not None:
        n += 1
        if leaked_email_rows:
            email_summary = f"Masked emails parsed: {len(leaked_email_rows)}; sample={leaked_email_rows[0].email}"
            status = "collected"
        else:
            email_summary = "Email-capable sources parsed; no email-like values observed."
            status = "no_observed_items"
        rows.append(
            EvidenceInventoryRowModel(
                evidence_id=f"EV-{n:04d}",
                finding_or_section="Email / OSINT",
                source_tool="theHarvester / fallback artifacts",
                evidence_type="Masked email observation",
                summary=_truncate(email_summary, 500),
                timestamp="—",
                status=status,
            )
        )
    return rows


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


def _split_component_version(value: str) -> tuple[str, str]:
    raw = (value or "").strip()
    if not raw:
        return "", ""
    m = re.search(r"(?P<name>[A-Za-z][A-Za-z0-9 ._+-]{1,80}?)[/\s]+(?P<ver>\d+(?:\.\d+){1,4}[A-Za-z0-9._+-]*)", raw)
    if not m:
        return raw, ""
    name = m.group("name").strip(" -/")
    ver = m.group("ver").strip()
    return name or raw, ver


def _tech_stack_note_for_category(category: str, source: str) -> str:
    cat = (category or "").lower()
    src = (source or "").lower()
    if cat in {"cdn_waf", "hosting_provider", "reverse_proxy"}:
        return "Edge or hosting marker only; origin application stack is not confirmed."
    if "header" in src or "robots" in src or "sitemap" in src or "html" in src:
        return "Fingerprint from passive artifact; verify before stack-specific remediation."
    if cat in {"ports", "services"}:
        return "Exposure signal only; do not infer closed ports without a full scan."
    return "Parsed technology signal; verify version before treating it as authoritative."


def _tech_rows_from_structured(model: TechStackStructuredModel) -> list[TechStackTableRow]:
    rows: list[TechStackTableRow] = []
    if model.web_server.strip():
        name, version = _split_component_version(model.web_server[:512])
        rows.append(
            TechStackTableRow(
                category="web_server",
                name=name[:512],
                detail="",
                source="tech_stack.structured",
                version=version,
                confidence="medium",
                security_note=_tech_stack_note_for_category("web_server", "tech_stack.structured"),
            )
        )
    if model.os.strip():
        rows.append(
            TechStackTableRow(
                category="os",
                name=model.os[:512],
                detail="",
                source="tech_stack.structured",
                confidence="medium",
                security_note=_tech_stack_note_for_category("os", "tech_stack.structured"),
            )
        )
    if model.cms.strip():
        name, version = _split_component_version(model.cms[:512])
        rows.append(
            TechStackTableRow(
                category="cms",
                name=name[:512],
                detail="",
                source="tech_stack.structured",
                version=version,
                confidence="medium",
                security_note=_tech_stack_note_for_category("cms", "tech_stack.structured"),
            )
        )
    for f in model.frameworks:
        name, version = _split_component_version(f[:512])
        rows.append(
            TechStackTableRow(
                category="framework",
                name=name[:512],
                detail="",
                source="tech_stack.structured",
                version=version,
                confidence="medium",
                security_note=_tech_stack_note_for_category("framework", "tech_stack.structured"),
            )
        )
    for j in model.js_libraries:
        name, version = _split_component_version(j[:512])
        rows.append(
            TechStackTableRow(
                category="javascript",
                name=name[:512],
                detail="",
                source="tech_stack.structured",
                version=version,
                confidence="medium",
                security_note=_tech_stack_note_for_category("javascript", "tech_stack.structured"),
            )
        )
    if model.ports_summary.strip():
        rows.append(
            TechStackTableRow(
                category="ports",
                name=model.ports_summary[:512],
                detail="",
                source="tech_stack.structured",
                confidence="medium",
                security_note=_tech_stack_note_for_category("ports", "tech_stack.structured"),
            )
        )
    if model.services_summary.strip():
        rows.append(
            TechStackTableRow(
                category="services",
                name="nmap (open ports / services)",
                detail=_truncate(model.services_summary, 1024),
                source="nmap.summary",
                confidence="medium",
                security_note=_tech_stack_note_for_category("services", "nmap.summary"),
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

    def add_row(
        category: str,
        name: str,
        detail: str = "",
        source: str = "",
        confidence: str = "medium",
    ) -> None:
        key = (category, name[:256], detail[:256])
        if key in seen:
            return
        seen.add(key)
        clean_name, version = _split_component_version(name[:512])
        rows.append(
            TechStackTableRow(
                category=category[:128],
                name=clean_name[:512] or "—",
                detail=detail[:1024],
                source=source[:256],
                version=version,
                confidence=confidence,
                security_note=_tech_stack_note_for_category(category, source),
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


def _add_unique_tech_row(
    rows: list[TechStackTableRow],
    seen: set[tuple[str, str]],
    *,
    category: str,
    name: str,
    detail: str,
    source: str,
    confidence: str,
    version: str = "",
) -> None:
    val = (name or "").strip()
    if not val:
        return
    clean_name, detected_version = _split_component_version(val)
    key = (category.lower().strip(), clean_name.lower().strip()[:200])
    if key in seen:
        return
    seen.add(key)
    rows.append(
        TechStackTableRow(
            category=category[:128],
            name=clean_name[:512],
            detail=detail[:1024],
            source=source[:256],
            version=(version or detected_version)[:128],
            confidence=confidence,
            security_note=_tech_stack_note_for_category(category, source),
        )
    )


def _cookie_names_from_header(raw: str) -> list[str]:
    names: list[str] = []
    for part in re.split(r",\s*(?=[^;,=]+=\S)", raw or ""):
        first = part.split(";", 1)[0].strip()
        if "=" not in first:
            continue
        name = first.split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name[:120])
    return names[:16]


def _tech_rows_from_http_and_urls(
    http_headers: dict[str, dict[str, str]],
    robots: RobotsTxtAnalysisModel,
    sitemap: SitemapAnalysisModel,
    raw_artifact_keys: list[tuple[str, str]],
    *,
    fetch_bodies: bool,
) -> list[TechStackTableRow]:
    rows: list[TechStackTableRow] = []
    seen: set[tuple[str, str]] = set()

    for host, hdrs in list(http_headers.items())[:32]:
        hdetail = str(host)[:256]
        server = str(hdrs.get("server") or "").strip()
        if server:
            low = server.lower()
            category = "web_server"
            if "cloudflare" in low:
                category = "cdn_waf"
            elif "vercel" in low or "netlify" in low:
                category = "hosting_provider"
            _add_unique_tech_row(
                rows,
                seen,
                category=category,
                name=server,
                detail=hdetail,
                source="HTTP response header: Server",
                confidence="medium" if category == "web_server" else "high",
            )
        powered = str(hdrs.get("x-powered-by") or "").strip()
        if powered:
            _add_unique_tech_row(
                rows,
                seen,
                category="backend_framework",
                name=powered,
                detail=hdetail,
                source="HTTP response header: X-Powered-By",
                confidence="medium",
            )
        via = str(hdrs.get("via") or "").strip()
        if via:
            _add_unique_tech_row(
                rows,
                seen,
                category="reverse_proxy",
                name=via,
                detail=hdetail,
                source="HTTP response header: Via",
                confidence="medium",
            )
        served = str(hdrs.get("x-served-by") or "").strip()
        if served:
            _add_unique_tech_row(
                rows,
                seen,
                category="hosting_provider",
                name=served,
                detail=hdetail,
                source="HTTP response header: X-Served-By",
                confidence="low",
            )
        if any(k.startswith("cf-") or k == "cf-ray" for k in hdrs):
            _add_unique_tech_row(
                rows,
                seen,
                category="cdn_waf",
                name="Cloudflare",
                detail=hdetail,
                source="HTTP response headers: CF-* marker",
                confidence="high",
            )
        if any("vercel" in k or "vercel" in str(v).lower() for k, v in hdrs.items()):
            _add_unique_tech_row(
                rows,
                seen,
                category="hosting_provider",
                name="Vercel",
                detail=hdetail,
                source="HTTP response headers: Vercel marker",
                confidence="medium",
            )
        if any("netlify" in k or "netlify" in str(v).lower() for k, v in hdrs.items()):
            _add_unique_tech_row(
                rows,
                seen,
                category="hosting_provider",
                name="Netlify",
                detail=hdetail,
                source="HTTP response headers: Netlify marker",
                confidence="medium",
            )
        cookies = _cookie_names_from_header(str(hdrs.get("set-cookie") or ""))
        for cname in cookies:
            lowc = cname.lower()
            if lowc.startswith("__next") or "next-auth" in lowc:
                _add_unique_tech_row(
                    rows,
                    seen,
                    category="frontend_framework",
                    name="Next.js / NextAuth cookie marker",
                    detail=cname,
                    source="Set-Cookie name",
                    confidence="low",
                )
            elif lowc == "phpsessid":
                _add_unique_tech_row(
                    rows,
                    seen,
                    category="backend_framework",
                    name="PHP session",
                    detail=cname,
                    source="Set-Cookie name",
                    confidence="low",
                )
            elif "laravel" in lowc:
                _add_unique_tech_row(
                    rows,
                    seen,
                    category="backend_framework",
                    name="Laravel session",
                    detail=cname,
                    source="Set-Cookie name",
                    confidence="low",
                )

    url_chunks: list[str] = []
    url_chunks.extend(robots.disallowed_paths_sample or [])
    url_chunks.extend(robots.allow_paths_sample or [])
    url_chunks.extend(robots.sitemap_hints or [])
    url_chunks.extend(sitemap.sample_urls or [])

    raw_text_chunks: list[str] = []
    if fetch_bodies:
        for key, _phase in raw_artifact_keys[:200]:
            lowk = key.lower()
            if not any(tok in lowk for tok in ("html", "body", "response", ".js", "javascript")):
                continue
            blob = _safe_download_raw(key)
            if not blob:
                continue
            text = _text_from_raw_bytes(blob)
            if not text:
                continue
            raw_text_chunks.append(text[:12000])
            if len(raw_text_chunks) >= 8:
                break
    joined = "\n".join(url_chunks + raw_text_chunks)
    low_joined = joined.lower()
    if "/_next/" in low_joined or "__next_data__" in low_joined:
        _add_unique_tech_row(
            rows,
            seen,
            category="frontend_framework",
            name="Next.js",
            detail="/_next/ or __NEXT_DATA__ marker",
            source="robots/sitemap/HTML/JS artifact",
            confidence="medium",
        )
        _add_unique_tech_row(
            rows,
            seen,
            category="frontend_framework",
            name="React",
            detail="Inferred from Next.js marker",
            source="framework marker",
            confidence="low",
        )
    if "/_nuxt/" in low_joined or "__nuxt" in low_joined:
        _add_unique_tech_row(
            rows,
            seen,
            category="frontend_framework",
            name="Nuxt.js",
            detail="/_nuxt/ marker",
            source="robots/sitemap/HTML/JS artifact",
            confidence="medium",
        )
    if "wp-content" in low_joined or "wp-includes" in low_joined:
        _add_unique_tech_row(
            rows,
            seen,
            category="cms",
            name="WordPress",
            detail="wp-content/wp-includes marker",
            source="robots/sitemap/HTML/JS artifact",
            confidence="medium",
        )
    gen_match = re.search(
        r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']",
        joined,
        re.IGNORECASE,
    )
    if gen_match:
        _add_unique_tech_row(
            rows,
            seen,
            category="cms",
            name=gen_match.group(1).strip(),
            detail="HTML meta generator",
            source="HTML body artifact",
            confidence="medium",
        )
    jquery = re.search(r"jquery[-.]((?:\d+\.){1,3}\d+)[^/\"']*\.js", joined, re.IGNORECASE)
    if jquery:
        _add_unique_tech_row(
            rows,
            seen,
            category="javascript_library",
            name="jQuery",
            version=jquery.group(1),
            detail="script path marker",
            source="HTML/JS artifact",
            confidence="medium",
        )
    if re.search(r"/assets/(?:index|app)[-.][A-Za-z0-9_-]+\.js", joined):
        _add_unique_tech_row(
            rows,
            seen,
            category="javascript_bundle",
            name="Bundled frontend JavaScript",
            detail="/assets/index*.js or /assets/app*.js marker",
            source="robots/sitemap/HTML artifact",
            confidence="low",
        )
    return rows[:200]


def _apply_tech_marker_rows_to_structured(
    model: TechStackStructuredModel,
    marker_rows: list[TechStackTableRow],
) -> TechStackStructuredModel:
    if not marker_rows:
        return model
    m = model.model_copy(deep=True)

    def add_unique(seq: list[str], value: str) -> None:
        v = value.strip()
        if v and v not in seq:
            seq.append(v[:512])

    for row in marker_rows:
        cat = row.category.lower()
        name = row.name.strip()
        if not name:
            continue
        if cat == "web_server" and not m.web_server:
            m.web_server = name[:1024]
        elif cat == "cms" and not m.cms:
            m.cms = name[:1024]
        elif cat in {"frontend_framework", "backend_framework", "framework", "hosting_provider", "cdn_waf"}:
            add_unique(m.frameworks, name)
        elif cat in {"javascript_library", "javascript_bundle", "javascript"}:
            add_unique(m.js_libraries, name)
    m.frameworks = m.frameworks[:64]
    m.js_libraries = m.js_libraries[:64]
    return m


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
            ) and len(weak_proto) < 32:
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


_TESTSSL_PROTOCOL_RE = re.compile(
    r"(SSLv[23]|TLSv?\s*1\.[0-3]|TLS\s*1\.[0-3])\s+(offered|not offered|enabled|disabled|accepted|rejected)",
    re.IGNORECASE,
)
_TESTSSL_WEAK_PROTOS = frozenset({"sslv2", "sslv3", "tls 1.0", "tls 1.1", "tls1.0", "tls1.1"})
_TESTSSL_VULN_MARKERS = (
    "BEAST", "POODLE", "Heartbleed", "ROBOT", "DROWN",
    "LOGJAM", "FREAK", "SWEET32", "Lucky13",
)
_TESTSSL_CIPHER_RE = re.compile(
    r"(TLS_\w+|ECDHE-\w+|DHE-\w+|AES\w+|RC4-\w+)",
    re.IGNORECASE,
)
_TESTSSL_WEAK_CIPHER_TOKENS = ("rc4", "des", "null", "export")


def _parse_testssl_text_output(stdout: str) -> SslTlsAnalysisModel:
    """Parse testssl/sslscan/openssl/nmap TLS text when JSON/XML output is unavailable."""
    protocols: list[str] = []
    weak_protocols: list[str] = []
    weak_ciphers: list[str] = []
    issuer: str | None = None
    validity: str | None = None
    hsts: str | None = None

    xml_issuer = re.search(r"<issuer>\s*([^<]+)\s*</issuer>", stdout, re.IGNORECASE)
    if xml_issuer:
        issuer = xml_issuer.group(1).strip()[:512]
    xml_not_before = re.search(r"<not-valid-before>\s*([^<]+)\s*</not-valid-before>", stdout, re.IGNORECASE)
    xml_not_after = re.search(r"<not-valid-after>\s*([^<]+)\s*</not-valid-after>", stdout, re.IGNORECASE)
    if xml_not_before and xml_not_after:
        validity = f"{xml_not_before.group(1).strip()[:120]} - {xml_not_after.group(1).strip()[:120]}"
    elif xml_not_after:
        validity = xml_not_after.group(1).strip()[:256]
    for xml_proto, label in (
        ("ssl2", "SSLv2"),
        ("ssl3", "SSLv3"),
        ("tls10", "TLS 1.0"),
        ("tls11", "TLS 1.1"),
        ("tls12", "TLS 1.2"),
        ("tls13", "TLS 1.3"),
    ):
        if re.search(rf"<[^>]*(?:protocol|type)=[\"']{xml_proto}[\"'][^>]*(?:enabled|status)=[\"'](?:1|true|accepted)[\"']", stdout, re.IGNORECASE):
            protocols.append(label)
            if label.lower().replace(" ", "") in _TESTSSL_WEAK_PROTOS or label.lower() in _TESTSSL_WEAK_PROTOS:
                weak_protocols.append(label)
    for m in re.finditer(r"sslversion=[\"'](SSLv[23]|TLSv1\.[0-3]|TLS\s*1\.[0-3])[\"']", stdout, re.IGNORECASE):
        proto = m.group(1).replace("TLSv", "TLS ")
        if proto not in protocols:
            protocols.append(proto)
        if proto.lower().replace(" ", "") in _TESTSSL_WEAK_PROTOS or proto.lower() in _TESTSSL_WEAK_PROTOS:
            weak_protocols.append(proto)

    for m in _TESTSSL_PROTOCOL_RE.finditer(stdout):
        proto = m.group(1).strip().replace("TLSv", "TLS ")
        status = m.group(2).strip().lower()
        if status in {"offered", "enabled", "accepted"}:
            protocols.append(proto)
            if proto.lower().replace(" ", "") in _TESTSSL_WEAK_PROTOS or proto.lower() in _TESTSSL_WEAK_PROTOS:
                weak_protocols.append(proto)

    for proto in ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"):
        for pm in re.finditer(rf"\b{re.escape(proto)}\b", stdout, re.IGNORECASE):
            snip = stdout[pm.start() : min(len(stdout), pm.end() + 80)].lower()
            if any(word in snip for word in ("disabled", "not offered", "rejected", "no ")):
                continue
            normalized = proto.replace("TLSv", "TLS ")
            if normalized not in protocols:
                protocols.append(normalized)
            if normalized.lower().replace(" ", "") in _TESTSSL_WEAK_PROTOS and normalized not in weak_protocols:
                weak_protocols.append(normalized)
            break

    cn_match = re.search(r"CN\s*=\s*([^\s,]+)", stdout)
    if cn_match:
        issuer = cn_match.group(1).strip()[:512]

    issuer_match = re.search(r"(?:Issuer|issuer=|i:)\s*:?\s*(.+)", stdout)
    if issuer_match:
        issuer = issuer_match.group(1).strip()[:512]

    not_before = re.search(r"(?:Not Before|notBefore=|Not valid before)\s*:?\s*(.+)", stdout, re.IGNORECASE)
    not_after = re.search(r"(?:Not After|notAfter=|Not valid after)\s*:?\s*(.+)", stdout, re.IGNORECASE)
    if not_before and not_after:
        validity = f"{not_before.group(1).strip()[:120]} - {not_after.group(1).strip()[:120]}"
    elif not_after:
        validity = not_after.group(1).strip()[:256]

    hsts_match = re.search(r"Strict.Transport.Security[:\s]+(.+)", stdout, re.IGNORECASE)
    if hsts_match:
        hsts = _truncate(hsts_match.group(1).strip(), 500)
    else:
        hsts_header_match = re.search(r"strict-transport-security\s*:\s*(.+)", stdout, re.IGNORECASE)
        if hsts_header_match:
            hsts = _truncate(hsts_header_match.group(1).strip(), 500)

    vuln_ciphers_seen: set[str] = set()
    for vuln in _TESTSSL_VULN_MARKERS:
        vuln_re = re.compile(rf"{vuln}\s*[\(:]?\s*(VULNERABLE|not vulnerable|OK)", re.IGNORECASE)
        vm = vuln_re.search(stdout)
        if vm and vm.group(1).strip().lower() == "vulnerable":
            vuln_ciphers_seen.add(vuln)

    cipher_set: set[str] = set()
    for cm in _TESTSSL_CIPHER_RE.finditer(stdout):
        cipher = cm.group(1)
        cipher_set.add(cipher)
        if any(tok in cipher.lower() for tok in _TESTSSL_WEAK_CIPHER_TOKENS):
            weak_ciphers.append(cipher)

    cipher_match = re.search(r"(?:Cipher|Selected cipher)\s*:?\s*([A-Z0-9_-]+)", stdout, re.IGNORECASE)
    if cipher_match:
        cipher = cipher_match.group(1).strip()
        if any(tok in cipher.lower() for tok in _TESTSSL_WEAK_CIPHER_TOKENS):
            weak_ciphers.append(cipher)

    if vuln_ciphers_seen:
        for v in sorted(vuln_ciphers_seen):
            weak_ciphers.append(f"VULN:{v}")

    return SslTlsAnalysisModel(
        issuer=issuer,
        validity=validity,
        protocols=protocols[:32],
        weak_protocols=weak_protocols[:32],
        weak_ciphers=weak_ciphers[:48],
        hsts=hsts,
    )


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


def _ssl_from_testssl_text_artifacts(
    raw_keys: list[tuple[str, str]],
    *,
    fetch_bodies: bool,
) -> SslTlsAnalysisModel | None:
    """B1 fallback: parse testssl plain-text stdout when JSON is unavailable."""
    if not fetch_bodies:
        return None
    for key, _p in raw_keys:
        if not _artifact_name_matches(key, _TLS_ARTIFACT_HINTS):
            continue
        blob = _safe_download_raw(key)
        if not blob:
            continue
        text = _text_from_raw_bytes(blob)
        if not text or not text.strip():
            continue
        if _json_dict_from_tls_artifact_text(text) is not None:
            continue
        result = _parse_testssl_text_output(text)
        if not _ssl_surface_empty(result):
            logger.info(
                "ssl_tls_text_fallback_used",
                extra={"event": "ssl_tls_text_fallback_used", "key_suffix": key[-64:]},
            )
            return result
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
            keys_low = {str(x).lower() for x in hs}
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
    # VDF-003 — canonical security header rows used by customer-facing Valhalla tables.
    canonical = (
        ("content-security-policy", "Content-Security-Policy"),
        ("strict-transport-security", "Strict-Transport-Security"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("x-frame-options", "X-Frame-Options"),
        ("referrer-policy", "Referrer-Policy"),
        ("permissions-policy", "Permissions-Policy"),
        ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy"),
        ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy"),
        ("cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy"),
    )
    missing: set[str] = set()
    for host, hdrs in list(http_headers.items())[:32]:
        lower_map = dict(hdrs)
        hstr = str(host)[:256]
        for low_name, display in canonical:
            sample = str(lower_map.get(low_name) or "").strip()
            if not sample:
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
    miss_sorted = sorted(missing)
    summary = None
    if miss_sorted:
        summary = "Missing recommended headers: " + ", ".join(miss_sorted[:12])
    return SecurityHeadersAnalysisModel(
        rows=rows[:500],
        missing_recommended=miss_sorted[:24],
        summary=summary,
    )


_SEC_HDR_NAMES_CANONICAL = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
)

_SEC_HDR_DISPLAY_BY_LOW = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
    "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy",
}


def _canonical_security_header_name(raw: str) -> str | None:
    s = re.sub(r"[^a-z0-9-]+", "-", (raw or "").strip().lower()).strip("-")
    if not s:
        return None
    aliases = {
        "csp": "content-security-policy",
        "content-security-policy-report-only": "content-security-policy",
        "xfo": "x-frame-options",
        "xcto": "x-content-type-options",
        "hsts": "strict-transport-security",
        "coop": "cross-origin-opener-policy",
        "corp": "cross-origin-resource-policy",
        "coep": "cross-origin-embedder-policy",
    }
    if s in aliases:
        return aliases[s]
    return s if s in _SEC_HDR_NAMES_CANONICAL else None


def _extract_missing_security_headers_from_text(text: str) -> list[str]:
    blob = text or ""
    low = blob.lower()
    found: list[str] = []

    def add(name: str | None) -> None:
        if name and name not in found:
            found.append(name)

    for m in re.finditer(r"\bmissing\s*:\s*([^\n.;]+)", blob, re.IGNORECASE):
        for part in re.split(r"[,/|]+|\band\b", m.group(1), flags=re.IGNORECASE):
            add(_canonical_security_header_name(part))

    if "missing" in low or "absent" in low or "not set" in low:
        for low_name, display in _SEC_HDR_DISPLAY_BY_LOW.items():
            if low_name in low or display.lower() in low:
                add(low_name)
    return found


def _security_headers_from_findings(findings: list[dict[str, Any]]) -> SecurityHeadersAnalysisModel:
    rows: list[dict[str, Any]] = []
    missing: list[str] = []
    seen_rows: set[tuple[str, str]] = set()
    for f in findings[:500]:
        if not isinstance(f, dict):
            continue
        parts: list[str] = []
        for key in ("title", "name", "description", "evidence", "proof", "applicability_notes"):
            v = f.get(key)
            if isinstance(v, str) and v.strip():
                parts.append(v)
        poc = f.get("proof_of_concept")
        if isinstance(poc, dict):
            with contextlib.suppress(TypeError, ValueError):
                parts.append(json.dumps(poc, ensure_ascii=False)[:4000])
        blob = "\n".join(parts)
        blob_low = blob.lower()
        if "security" not in blob_low and "header" not in blob_low:
            continue
        missing_names = _extract_missing_security_headers_from_text(blob)
        if (
            not missing_names
            and "header" in blob_low
            and any(word in blob_low for word in ("missing", "incomplete", "absent", "not set"))
        ):
            missing_names = [
                "content-security-policy",
                "strict-transport-security",
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
                "permissions-policy",
            ]
        if not missing_names:
            continue
        host = str(
            f.get("affected_url")
            or f.get("affected_asset")
            or f.get("url")
            or f.get("target")
            or "finding_evidence"
        )[:256]
        for low_name in missing_names:
            display = _SEC_HDR_DISPLAY_BY_LOW.get(low_name, low_name)
            row_key = (host, low_name)
            if row_key in seen_rows:
                continue
            seen_rows.add(row_key)
            if low_name not in missing:
                missing.append(low_name)
            rows.append(
                {
                    "host": host,
                    "header": display,
                    "present": False,
                    "value_sample": "missing (finding evidence)",
                }
            )
    if not rows:
        return SecurityHeadersAnalysisModel()
    miss_sorted = sorted(missing)
    return SecurityHeadersAnalysisModel(
        rows=rows[:500],
        missing_recommended=miss_sorted[:24],
        summary="Missing recommended headers: " + ", ".join(miss_sorted[:12]) + " (from finding evidence)",
    )

_NIKTO_MISSING_HDR_RE = re.compile(
    r"(?:Missing|absent|not set)[^:]*:\s*([\w-]+)",
    re.IGNORECASE,
)
_NIKTO_HDR_PRESENT_RE = re.compile(
    r"(X-Frame-Options|X-Content-Type-Options|Content-Security-Policy"
    r"|Strict-Transport-Security|Referrer-Policy|Permissions-Policy"
    r"|Cross-Origin-Opener-Policy|Cross-Origin-Resource-Policy"
    r"|Cross-Origin-Embedder-Policy)\s*(?:header\s+(?:is\s+)?(?:set|present|found))",
    re.IGNORECASE,
)


def _security_headers_from_security_headers_result(
    phase_outputs: list[tuple[str, dict[str, Any] | None]],
    recon: dict[str, Any] | None,
) -> dict[str, dict[str, str]]:
    """B3-primary: extract http headers map from ARGUS-002 SecurityHeadersResult stored in recon/phases."""
    header_maps: dict[str, dict[str, str]] = {}

    def _try_extract(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        for key in ("security_headers", "security_headers_result"):
            shr = obj.get(key)
            if not isinstance(shr, dict):
                continue
            host = str(shr.get("target") or "unknown")[:256]
            found = shr.get("headers_found")
            if isinstance(found, dict) and found:
                inner: dict[str, str] = {}
                for hname, hval in found.items():
                    inner[str(hname).strip().lower()] = str(hval).strip()
                if inner:
                    header_maps[host] = inner
            all_resp = shr.get("all_response_headers")
            if isinstance(all_resp, dict) and all_resp and host not in header_maps:
                inner2: dict[str, str] = {}
                for hname, hval in all_resp.items():
                    inner2[str(hname).strip().lower()] = str(hval).strip()
                if inner2:
                    header_maps[host] = inner2

    if isinstance(recon, dict):
        _try_extract(recon)
        rps = recon.get("recon_pipeline_summary")
        if isinstance(rps, dict):
            _try_extract(rps)
    for _ph, od in phase_outputs:
        if isinstance(od, dict):
            _try_extract(od)
    return header_maps


def _security_headers_from_nikto_stdout(
    raw_keys: list[tuple[str, str]],
    *,
    fetch_bodies: bool,
) -> dict[str, dict[str, str]]:
    """B3-fallback1: extract header presence/absence from nikto text stdout."""
    if not fetch_bodies:
        return {}
    for key, _p in raw_keys:
        lowk = key.lower()
        if "nikto" not in lowk:
            continue
        blob = _safe_download_raw(key)
        if not blob:
            continue
        text = _text_from_raw_bytes(blob)
        if not text:
            continue
        hdrs: dict[str, str] = {}
        for m in _NIKTO_MISSING_HDR_RE.finditer(text):
            hname = _canonical_security_header_name(m.group(1))
            if hname:
                hdrs[hname] = ""
        for m in _NIKTO_HDR_PRESENT_RE.finditer(text):
            hname = m.group(1).strip().lower()
            hdrs[hname] = "present (nikto)"
        if hdrs:
            logger.info(
                "sec_headers_nikto_fallback_used",
                extra={"event": "sec_headers_nikto_fallback_used", "key_suffix": key[-64:]},
            )
            return {"nikto_target": hdrs}
    return {}


def _security_headers_from_whatweb_stdout(
    ww_merged: dict[str, Any] | None,
) -> dict[str, dict[str, str]]:
    """B3-fallback2: extract header hints from whatweb merged plugins."""
    if not isinstance(ww_merged, dict):
        return {}
    plugs = ww_merged.get("plugins")
    if not isinstance(plugs, dict):
        return {}
    hdrs: dict[str, str] = {}
    header_plugin_map = {
        "Strict-Transport-Security": "strict-transport-security",
        "X-Frame-Options": "x-frame-options",
        "X-XSS-Protection": "x-xss-protection",
        "X-Content-Type-Options": "x-content-type-options",
    }
    for pname, low_name in header_plugin_map.items():
        pd = plugs.get(pname)
        if isinstance(pd, dict):
            strs = _plugin_strings(pd)
            hdrs[low_name] = strs[0] if strs else "present (whatweb)"
        elif isinstance(pd, str) and pd.strip():
            hdrs[low_name] = pd.strip()
    if hdrs:
        logger.info(
            "sec_headers_whatweb_fallback_used",
            extra={"event": "sec_headers_whatweb_fallback_used"},
        )
        return {"whatweb_target": hdrs}
    return {}


def _security_headers_from_raw_http_responses(
    raw_keys: list[tuple[str, str]],
    *,
    fetch_bodies: bool,
) -> dict[str, dict[str, str]]:
    """B3-fallback3: extract headers from raw HTTP response dumps in artifacts."""
    if not fetch_bodies:
        return {}
    http_header_re = re.compile(r"^([\w-]+):\s*(.+)$", re.MULTILINE)
    for key, _p in raw_keys:
        lowk = key.lower()
        if not any(
            tok in lowk
            for tok in (
                "response",
                "headers",
                "http_resp",
                "http_audit",
                "curl",
                "httpx",
                "nikto",
                "whatweb",
            )
        ):
            continue
        blob = _safe_download_raw(key)
        if not blob:
            continue
        text = _text_from_raw_bytes(blob)
        if not text:
            continue
        hdrs: dict[str, str] = {}
        if not re.search(r"^HTTP/\d(?:\.\d)?\s+\d{3}", text[:8192], re.MULTILINE | re.IGNORECASE):
            continue
        for m in http_header_re.finditer(text[:8192]):
            hname = m.group(1).strip().lower()
            hval = m.group(2).strip()
            if hname and hval:
                hdrs[hname] = hval[:500]
        if hdrs:
            logger.info(
                "sec_headers_raw_http_fallback_used",
                extra={"event": "sec_headers_raw_http_fallback_used", "key_suffix": key[-64:]},
            )
            return {"raw_http_target": hdrs}
    return {}


def _dependency_rows_from_artifact_json(val: Any, source_key: str) -> list[DependencyAnalysisRow]:
    out: list[DependencyAnalysisRow] = []
    if isinstance(val, list):
        for item in val[:200]:
            if not isinstance(item, dict):
                continue
            nested_vulns = item.get("Vulnerabilities") or item.get("vulnerabilities")
            if isinstance(nested_vulns, list):
                out.extend(_dependency_rows_from_artifact_json(nested_vulns, source_key))
                continue
            pkg = str(item.get("package") or item.get("PkgName") or item.get("name") or "").strip()
            ver = (
                item.get("version")
                or item.get("InstalledVersion")
                or item.get("installed_version")
                or item.get("installedVersion")
            )
            sev = item.get("severity") or item.get("Severity")
            detail = (
                item.get("detail")
                or item.get("Title")
                or item.get("VulnerabilityID")
                or item.get("description")
            )
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
        package_name = val.get("name")
        if isinstance(package_name, str) and package_name.strip():
            version = val.get("version")
            out.append(
                DependencyAnalysisRow(
                    package=package_name[:256],
                    version=str(version)[:64] if version is not None else None,
                    severity=None,
                    source=source_key[-120:],
                    detail="package manifest",
                )
            )
        for block_name in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps = val.get(block_name)
            if isinstance(deps, dict):
                for pkg, ver in list(deps.items())[:300]:
                    out.append(
                        DependencyAnalysisRow(
                            package=str(pkg)[:256],
                            version=str(ver)[:64] if ver is not None else None,
                            severity=None,
                            source=source_key[-120:],
                            detail=block_name,
                        )
                    )
        findings = val.get("findings")
        if isinstance(findings, list):
            out.extend(_dependency_rows_from_artifact_json(findings, source_key))
        results = val.get("Results") or val.get("results")
        if isinstance(results, list):
            out.extend(_dependency_rows_from_artifact_json(results, source_key))
        vulns = val.get("vulnerabilities") or val.get("Vulnerabilities")
        if isinstance(vulns, list):
            out.extend(_dependency_rows_from_artifact_json(vulns, source_key))
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
        stripped = (text or "").strip()
        if not stripped or not stripped.startswith(("{", "[")):
            continue
        try:
            val = json.loads(stripped)
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
    if f.get("exploit_demonstrated") is True:
        return True
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
    return bool(_CVE_RE.search(blob) and re.search(r"\b(exploit|proof.of.concept|poc|metasploit|weaponized)\b", blob, re.IGNORECASE))


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


def _validation_is_validated(f: dict[str, Any]) -> bool:
    st = str(f.get("validation_status") or "").strip().lower()
    if st == "validated":
        return True
    poc = f.get("proof_of_concept")
    if isinstance(poc, dict):
        pst = str(poc.get("validation_status") or "").strip().lower()
        if pst == "validated":
            return True
    return False


def _evidence_is_strong(f: dict[str, Any]) -> bool:
    q = str(f.get("evidence_quality") or "").strip().lower()
    if q == "strong":
        return True
    poc = f.get("proof_of_concept")
    if isinstance(poc, dict):
        return str(poc.get("evidence_quality") or "").strip().lower() == "strong"
    return False


def _critical_vuln_include(f: dict[str, Any]) -> bool:
    """VAL-003: Critical tier only for true criticals with validated + strong + demonstrated exploit; never header-only."""
    if is_header_only_advisory_finding(f):
        return False
    if f.get("exploit_demonstrated") is not True:
        poc0 = f.get("proof_of_concept")
        if not (isinstance(poc0, dict) and poc0.get("exploit_demonstrated") is True):
            return False
    if not _validation_is_validated(f):
        return False
    if not _evidence_is_strong(f):
        return False
    sev = _normalize_severity_label(f.get("severity"))
    _cr = f.get("cvss_score") if f.get("cvss_score") is not None else f.get("cvss")
    cvss = float(_cr) if isinstance(_cr, (int, float)) else None
    is_critical_sev = sev == "critical"
    is_cvss_9_plus = cvss is not None and cvss >= 9.0
    if not (is_critical_sev or is_cvss_9_plus):
        return False
    return True


def _critical_vulns_from_findings(findings: list[dict[str, Any]]) -> list[CriticalVulnRefModel]:
    """VAL-003 — Critical severity or CVSS ≥ 9, validated, strong evidence, exploit demonstrated; excludes header-only."""
    out: list[CriticalVulnRefModel] = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        if not _critical_vuln_include(f):
            continue
        fid = _finding_id_for_risk(f, i)
        title = str(f.get("title") or "").strip() or "—"
        _cr = f.get("cvss_score") if f.get("cvss_score") is not None else f.get("cvss")
        cvss = float(_cr) if isinstance(_cr, (int, float)) else None
        desc = str(f.get("description") or "").strip()
        short = _truncate(desc, 280) if desc else ""
        sev = _normalize_severity_label(f.get("severity"))
        cvss_vec = _cvss_vector_string(f)
        ed = f.get("exploit_demonstrated")
        poc2 = f.get("proof_of_concept")
        if ed is not True and isinstance(poc2, dict) and poc2.get("exploit_demonstrated") is True:
            ed = True
        ed_bool = ed is True
        out.append(
            CriticalVulnRefModel(
                vuln_id=fid,
                title=title[:500],
                description=short,
                cvss=cvss,
                cvss_vector=cvss_vec,
                exploit_available=ed_bool,
                exploit_demonstrated=ed_bool,
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
                source=support or "finding",
                recommendation="Track patches; remediate vulnerable versions per advisory",
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
                source="whatweb",
                recommendation="Verify version against upstream and install a supported release",
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
                source="nmap -sV",
                recommendation="Update service to a patched version (vendor/CVE)",
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
                source="searchsploit",
                recommendation="Verify public exploit and apply patch / compensating controls",
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
        rec = (d.detail or "")[:500] or "Remediate per Trivy / vendor recommendations"
        rows.append(
            OutdatedComponentRow(
                component=d.package[:256],
                installed_version=d.version,
                latest_stable="—",
                support_status="trivy",
                cves=cves,
                source=d.source or "trivy",
                recommendation=rec,
                exploit_available=bool(cves) and sev in ("critical", "high"),
            )
        )
    return rows[:80]


def _outdated_from_dependency_inventory(deps: list[DependencyAnalysisRow]) -> list[OutdatedComponentRow]:
    rows: list[OutdatedComponentRow] = []
    seen: set[str] = set()
    for d in deps[:300]:
        package = (d.package or "").strip()
        if not package:
            continue
        key = f"{package.lower()}|{(d.version or '').lower()}"
        if key in seen:
            continue
        seen.add(key)
        blob = f"{d.package} {d.detail or ''} {d.version or ''}"
        cves = sorted({m.group(0).upper() for m in _CVE_RE.finditer(blob)})[:16]
        rows.append(
            OutdatedComponentRow(
                component=package[:256],
                installed_version=d.version,
                latest_stable="—",
                support_status=d.severity or "inventory parsed",
                cves=cves,
                source=d.source,
                recommendation=(
                    "No vulnerability advisory was parsed for this component; validate with SCA before treating it as current."
                    if not cves
                    else "Remediate according to the referenced advisory or fixed version."
                ),
                exploit_available=False,
            )
        )
        if len(rows) >= 80:
            break
    return rows


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
                source=cur.source or r.source,
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
            _outdated_from_dependency_inventory(dependency_rows),
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
        notes="",
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
        notes="Summary of robots.txt / sitemap / security.txt (HTTP fetch + parsing).",
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


_HARVESTER_NOISE_LOCALS = frozenset({
    "noreply", "no-reply", "admin", "example", "test", "info",
    "support", "postmaster", "hostmaster", "webmaster", "abuse",
})


def _parse_harvester_emails(stdout: str) -> list[str]:
    """Extract and mask email addresses from theHarvester text stdout."""
    found: set[str] = set()
    for m in _EMAIL_RE.finditer(stdout):
        email = m.group(0).lower()
        local = email.split("@")[0]
        if local in _HARVESTER_NOISE_LOCALS:
            continue
        found.add(email)
    return [_mask_email(e) for e in sorted(found)][:64]


def _emails_from_harvester_phase_outputs(
    phase_outputs: list[tuple[str, dict[str, Any] | None]],
) -> list[str]:
    """B4 fallback: walk phase outputs for theHarvester tool results with stdout text."""
    acc: list[str] = []
    for _ph, od in phase_outputs:
        if not isinstance(od, dict):
            continue
        _walk_extract_harvester_emails(od, acc)
        if len(acc) >= 64:
            break
    return acc[:64]


def _walk_extract_harvester_emails(obj: Any, acc: list[str]) -> None:
    if isinstance(obj, dict):
        tool = str(obj.get("tool") or "").lower()
        if "harvester" in tool or "theharvester" in tool:
            for key in ("stdout", "raw_out", "output", "result"):
                text = obj.get(key)
                if isinstance(text, str) and text.strip():
                    acc.extend(_parse_harvester_emails(text))
                    return
        em_list = obj.get("emails") or obj.get("emails_masked")
        if isinstance(em_list, list):
            for item in em_list[:64]:
                if isinstance(item, str) and item.strip() and "@" in item:
                    acc.append(_mask_email(item.strip()))
        for v in obj.values():
            _walk_extract_harvester_emails(v, acc)
            if len(acc) >= 64:
                return
    elif isinstance(obj, list):
        for it in obj[:200]:
            _walk_extract_harvester_emails(it, acc)
            if len(acc) >= 64:
                return


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


def _parse_cert_not_after(not_after: str) -> datetime | None:
    raw = (not_after or "").strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _days_remaining_label(not_after: str) -> str:
    dt = _parse_cert_not_after(not_after)
    if dt is None:
        return "—"
    d = dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
    days = (d - datetime.now(UTC)).days
    if days < 0:
        return "expired"
    return str(max(days, 0))


def _join_weak(lines: list[str] | None, cap: int = 8) -> str:
    if not lines:
        return "—"
    return _truncate("; ".join(lines[:cap]), 1200)


def _tls_version_cell(proto_blobs: list[str], version: str) -> str:
    b = " ".join(proto_blobs or []).lower()
    if not b.strip() and not proto_blobs:
        return "n/a"
    needles = {
        "1.0": ("tls1.0", "tls 1.0", "tls1_0", "ssl3", "1.0"),
        "1.1": ("tls1.1", "tls 1.1", "tls1_1", "1.1"),
        "1.2": ("tls1.2", "tls 1.2", "tls1_2", "1.2"),
        "1.3": ("tls1.3", "tls 1.3", "tls1_3", "1.3"),
    }
    for needle in needles.get(version, ()):
        if needle in b:
            snip = b[max(0, b.find(needle) - 24) : b.find(needle) + 40]
            if "not" in snip and "offer" in snip:
                return "no"
            return "yes (see scan)"
    return "unknown"


def _header_row_risk_rec(header_display: str, present: bool) -> tuple[str, str]:
    h = (header_display or "").lower()
    if present:
        return "low", "Maintain header values during releases; re-test after framework upgrades."
    if "content-security-policy" in h or h.strip() == "csp":
        return "medium", "Add a strict Content-Security-Policy using nonces or hashes; avoid unsafe-inline for scripts when feasible."
    if "frame" in h:
        return "medium", "Set X-Frame-Options DENY/SAMEORIGIN or CSP frame-ancestors to mitigate clickjacking."
    if "content-type" in h:
        return "low", "Set X-Content-Type-Options: nosniff."
    if "strict-transport" in h or "hsts" in h:
        return "medium", "Enable HSTS for HTTPS; use includeSubDomains when all subdomains are HTTPS-ready; preload only with operational commitment."
    if "referrer" in h:
        return "low", "Set Referrer-Policy to match privacy requirements."
    if "xss-protection" in h:
        return "low", "Do not rely on X-XSS-Protection; prefer CSP. Remove or leave disabled per browser policy."
    if "permissions" in h:
        return "low", "Set Permissions-Policy to disable unused powerful browser features."
    return "low", "Configure this response header in line with application architecture."


def build_ssl_tls_table_rows(
    recon: dict[str, Any] | None,
    ssl_out: SslTlsAnalysisModel,
    *,
    target_hint: str = "",
) -> list[SslTlsTableRowModel]:
    """VH-008 — rows from ``ssl_certs`` + aggregate testssl fields."""
    proto_lines = list(ssl_out.protocols or []) + list(ssl_out.weak_protocols or [])
    weak_joined = _join_weak(list(ssl_out.weak_ciphers or []), 8)
    rows_out: list[SslTlsTableRowModel] = []
    n = 0
    if isinstance(recon, dict):
        certs = recon.get("ssl_certs")
        if isinstance(certs, dict) and certs:
            for host, lst in list(certs.items())[:48]:
                if not isinstance(lst, list):
                    continue
                for c in lst[:2]:
                    if not isinstance(c, dict):
                        continue
                    n += 1
                    cn = str(c.get("common_name") or "").strip()
                    sans = c.get("subject_alternative_names")
                    subj = cn
                    if isinstance(sans, list) and sans:
                        subj = f"{cn} / SAN: {', '.join(str(x) for x in sans[:6])}" if cn else ", ".join(
                            str(x) for x in sans[:8]
                        )
                    nb = str(c.get("validity_not_before") or "").strip()
                    na = str(c.get("validity_not_after") or "").strip()
                    dates = f"{nb} — {na}" if nb and na else (na or nb or "—")
                    iss = str(c.get("issuer") or "").strip() or "—"
                    hsts_v = (ssl_out.hsts or "—")[:500]
                    rows_out.append(
                        SslTlsTableRowModel(
                            domain=_truncate(str(host), 512),
                            cert_subject=_truncate(subj or "—", 500),
                            issuer=_truncate(iss, 500),
                            dates=_truncate(dates, 500),
                            days_remaining=_days_remaining_label(na),
                            tls_1_0=_tls_version_cell(proto_lines, "1.0"),
                            tls_1_1=_tls_version_cell(proto_lines, "1.1"),
                            tls_1_2=_tls_version_cell(proto_lines, "1.2"),
                            tls_1_3=_tls_version_cell(proto_lines, "1.3"),
                            weak_ciphers=weak_joined,
                            hsts=hsts_v,
                            chain_issues="not evaluated by parser",
                            evidence_id=f"EV-SSL-{n:04d}",
                        )
                    )
    if not rows_out and not _ssl_surface_empty(ssl_out):
        n = 1
        dom = (target_hint or "aggregated").strip()[:512] or "aggregated"
        rows_out.append(
            SslTlsTableRowModel(
                domain=dom,
                cert_subject="—",
                issuer=(ssl_out.issuer or "—")[:500],
                dates=(ssl_out.validity or "—")[:500],
                days_remaining="—",
                tls_1_0=_tls_version_cell(proto_lines, "1.0"),
                tls_1_1=_tls_version_cell(proto_lines, "1.1"),
                tls_1_2=_tls_version_cell(proto_lines, "1.2"),
                tls_1_3=_tls_version_cell(proto_lines, "1.3"),
                weak_ciphers=weak_joined,
                hsts=(ssl_out.hsts or "—")[:500],
                chain_issues="not evaluated by parser",
                evidence_id=f"EV-SSL-{n:04d}",
            )
        )
    return rows_out


def build_security_headers_table_rows(sec: SecurityHeadersAnalysisModel) -> list[dict[str, Any]]:
    """VH-008 — customer columns for headers matrix."""
    out: list[dict[str, Any]] = []
    for i, r in enumerate(sec.rows or [], start=1):
        if not isinstance(r, dict):
            continue
        host = str(r.get("host") or "—")[:500]
        hdr = str(r.get("header") or "—")
        present = bool(r.get("present"))
        obs = str(r.get("value_sample") or "")
        if not obs:
            obs = "—" if not present else "header present (value may be long)"
        risk, rec = _header_row_risk_rec(hdr, present)
        out.append(
            {
                "url": host,
                "header": hdr,
                "status": "present" if present else "missing",
                "observed": _truncate(obs, 500),
                "risk": risk,
                "recommendation": rec,
                "evidence_id": f"EV-HDR-{i:04d}",
            }
        )
    return out


_PORT_DETAILED_RE = re.compile(
    r"^(?P<port>\d+)/(?:tcp|udp)\s+(?P<state>open|filtered|closed)\s*(?P<service>\S+)?\s*(?P<version>.*)$",
    re.IGNORECASE,
)
_PORT_HINT_RE = re.compile(r"(?P<port>\d+)/(?:tcp|udp)", re.IGNORECASE)


def _host_from_target_hint(target_hint: str) -> str:
    raw = (target_hint or "").strip()
    if not raw:
        return "target"
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or raw.split("/", 1)[0] or "target")[:512]


def build_port_exposure_table_rows(
    port_data: PortExposureSummaryModel,
    *,
    target_hint: str = "",
) -> list[PortExposureTableRowModel]:
    rows: list[PortExposureTableRowModel] = []
    host = _host_from_target_hint(target_hint)
    seen: set[tuple[str, str, str]] = set()

    def add(
        *,
        port: str,
        protocol: str = "tcp",
        state: str = "open",
        service: str = "",
        version: str = "",
        source: str = "",
        confidence: str = "medium",
        note: str = "",
    ) -> None:
        p = str(port).strip()
        if not p:
            return
        key = (host, p, protocol)
        if key in seen:
            return
        seen.add(key)
        rows.append(
            PortExposureTableRowModel(
                host=host,
                port=p[:16],
                protocol=protocol[:16],
                state=state[:32],
                service=service[:128],
                version=version[:256],
                source=source[:256],
                confidence=confidence,
                exposure_note=note[:500]
                or "Observed open-service signal; do not infer other ports are closed unless a full scan completed.",
            )
        )

    for hint in port_data.open_port_hints or []:
        text = str(hint).strip()
        m = _PORT_DETAILED_RE.match(text)
        if m:
            add(
                port=m.group("port"),
                state=m.group("state").lower(),
                service=(m.group("service") or ""),
                version=(m.group("version") or ""),
                source="nmap" if "nmap" in (port_data.data_sources or []) else "port scan artifact",
                confidence="high" if port_data.has_nmap_hits else "medium",
            )
            continue
        mh = _PORT_HINT_RE.search(text)
        if mh:
            src = "naabu" if "naabu" in text.lower() else "recon/fallback"
            service = "https" if mh.group("port") == "443" else "http" if mh.group("port") == "80" else ""
            add(
                port=mh.group("port"),
                service=service,
                source=src,
                confidence="medium" if src != "recon/fallback" else "low",
                note=text,
            )

    if not rows and port_data.summary_text:
        for p in sorted(set(_PORT_HINT_RE.findall(port_data.summary_text)))[:32]:
            add(port=str(p), source="summary text", confidence="low")
    return rows[:128]


def build_leaked_email_rows(emails: list[str]) -> list[LeakedEmailRowModel]:
    rows: list[LeakedEmailRowModel] = []
    for idx, email in enumerate(emails[:64], start=1):
        rows.append(
            LeakedEmailRowModel(
                email=email,
                source="OSINT / HTML / recon artifacts",
                context="Masked email-like value parsed from collected ARGUS artifacts.",
                risk="May support targeted phishing or reconnaissance; no mailbox compromise was demonstrated.",
                evidence_id=f"EV-EMAIL-{idx:04d}",
            )
        )
    return rows


def _phase_output_excerpt(data: dict[str, Any] | None, max_len: int = 1200) -> str:
    if not isinstance(data, dict) or not data:
        return ""
    try:
        text = json.dumps(data, ensure_ascii=False)
    except (TypeError, ValueError):
        text = str(data)
    return _truncate(text, max_len)


def _format_threat_model_for_report(data: dict[str, Any], max_len: int = 2000) -> str:
    """VAL-008 — Human-readable lines; no raw JSON blob in the report body."""
    lines: list[str] = [
        "The following items are model hypotheses or scanner context labels — not independently validated in this run.",
    ]
    for k, v in list(data.items())[:40]:
        label = str(k).replace("_", " ")
        if isinstance(v, dict) and v:
            parts = [f"{ik}={_truncate(str(iv), 100)}" for ik, iv in list(v.items())[:12]]
            lines.append(f"• {label}: {', '.join(parts)}")
        elif isinstance(v, list):
            snip = ", ".join(_truncate(str(x), 80) for x in v[:10])
            lines.append(f"• {label}: {snip}")
        else:
            lines.append(f"• {label}: {_truncate(str(v), 500)}")
    return _truncate("\n".join(lines), max_len)


def _phased_output_narrative(od: dict[str, Any], max_len: int) -> str:
    """Shallow key/value narrative for non-threat phase blobs (avoids raw JSON dumps in PDF/HTML)."""
    if not od:
        return ""
    parts: list[str] = []
    for k, v in list(od.items())[:24]:
        if k == "threat_model" and isinstance(v, dict):
            continue
        label = str(k).replace("_", " ")
        if isinstance(v, (dict, list)):
            raw = json.dumps(v, ensure_ascii=False)
            parts.append(f"• {label}: {_truncate(raw, 400)}")
        else:
            parts.append(f"• {label}: {_truncate(str(v), 500)}")
    return _truncate("\n".join(parts), max_len)


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
        "has_headers": any(_artifact_name_matches(k, _HTTP_HEADER_ARTIFACT_HINTS) for k, _ in raw_artifact_keys),
        "has_dependency": any(_artifact_name_matches(k, _DEP_ARTIFACT_HINTS) for k, _ in raw_artifact_keys),
        "has_email_fallback": any(
            _artifact_name_matches(k, _EMAIL_FALLBACK_ARTIFACT_HINTS) for k, _ in raw_artifact_keys
        ),
        "has_ports": _raw_has_port_scan_artifact_keys(raw_artifact_keys),
    }


def _tool_errors_summary_from_runs(
    tool_run_summaries: list[tuple[str, str]] | None,
    *,
    raw_tool_issues: list[dict[str, str]] | None = None,
    max_items: int = 48,
) -> list[dict[str, str]]:
    bad_status = frozenset({"failed", "error", "timeout", "cancelled", "canceled", "aborted"})
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    row_by_key: dict[tuple[str, str], dict[str, str]] = {}
    if tool_run_summaries:
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
            row = {"tool": n, "status": st, "note": "tool_run_finished_non_success"}
            row_by_key[key] = row
            out.append(row)
            if len(out) >= max_items:
                return out
    if raw_tool_issues:
        for row in raw_tool_issues:
            n = str(row.get("tool") or "").strip()[:200]
            st = str(row.get("status") or "").strip().lower()[:80]
            note = str(row.get("note") or "").strip()[:240]
            if not n or not st:
                continue
            key = (n.lower(), st)
            if key in seen:
                existing = row_by_key.get(key)
                if existing and note and note not in existing.get("note", ""):
                    old_note = existing.get("note") or ""
                    if old_note == "tool_run_finished_non_success":
                        existing["note"] = note
                    else:
                        existing["note"] = _truncate(f"{old_note}; {note}", 240)
                continue
            seen.add(key)
            out_row = {"tool": n, "status": st, "note": note or "raw_artifact_issue"}
            row_by_key[key] = out_row
            out.append(out_row)
            if len(out) >= max_items:
                break
    return out


def _tool_issue_present(
    raw_tool_issues: list[dict[str, str]],
    *needles: str,
) -> bool:
    if not raw_tool_issues:
        return False
    lowered = tuple(n.lower() for n in needles if n)
    for row in raw_tool_issues:
        tool = str(row.get("tool") or "").lower()
        if any(n in tool for n in lowered):
            return True
    return False


def _no_conclusion_tool_reason(tool_label: str) -> str:
    return (
        f"No conclusion can be drawn because {tool_label} execution failed. "
        "The related assessment domain is not assessed."
    )


_REPORT_SECTION_DATA_STATUSES = frozenset(
    {"completed", "completed_with_fallback", "partial", "parsed_from_fallback", "no_observed_items_after_parsing"}
)


def _tool_completed_present(
    tool_run_summaries: list[tuple[str, str]] | None,
    *needles: str,
) -> bool:
    ok_statuses = {"success", "succeeded", "completed", "complete", "ok", "finished", "done"}
    for name, status in tool_run_summaries or []:
        n = (name or "").lower()
        st = (status or "").lower().strip()
        if any(needle in n for needle in needles) and st in ok_statuses:
            return True
    return False


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
    security_headers_from_findings: bool,
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
    port_data: PortExposureSummaryModel,
) -> tuple[ValhallaMandatorySectionsModel, ValhallaCoverageModel]:
    phases = _phases_executed_from_outputs(phase_outputs)
    raw_tool_issues = _raw_tool_issues_from_artifacts(
        raw_artifact_keys,
        fetch_bodies=fetch_raw_bodies,
    )
    tool_errs = _tool_errors_summary_from_runs(
        tool_run_summaries,
        raw_tool_issues=raw_tool_issues,
    )
    has_dep_artifacts = any(_artifact_name_matches(k, _DEP_ARTIFACT_HINTS) for k, _ in raw_artifact_keys)
    whatweb_failed = _tool_issue_present(tool_errs, "whatweb")
    tls_failed = _tool_issue_present(tool_errs, "testssl", "sslscan", "sslyze", "tlsx")
    trivy_failed = _tool_issue_present(tool_errs, "trivy")
    header_tool_failed = _tool_issue_present(tool_errs, "nikto", "whatweb", "httpx")
    harvester_failed = _tool_issue_present(tool_errs, "harvester")
    port_scan_failed = _tool_issue_present(tool_errs, "nmap", "naabu", "masscan")
    whatweb_completed = _tool_completed_present(tool_run_summaries, "whatweb")
    tls_completed = _tool_completed_present(tool_run_summaries, "testssl", "sslscan", "sslyze", "tlsx")
    trivy_completed = _tool_completed_present(tool_run_summaries, "trivy", "safety", "pip", "npm")
    header_tool_completed = _tool_completed_present(tool_run_summaries, "nikto", "httpx", "whatweb")
    harvester_completed = _tool_completed_present(tool_run_summaries, "harvester")
    port_scan_completed = _tool_completed_present(tool_run_summaries, "nmap", "naabu", "masscan")

    whatweb_raw_body = _artifact_non_empty_body_for_needles(
        raw_artifact_keys, fetch_raw_bodies, ("whatweb", "http_audit", "httpx", "http_headers", "head_spider")
    )
    tls_raw_body = _artifact_non_empty_body_for_needles(
        raw_artifact_keys, fetch_raw_bodies, ("testssl", "sslscan", "sslyze", "tlsx", "openssl", "x509", "ssl_enum")
    )
    header_raw_body = _artifact_non_empty_body_for_needles(
        raw_artifact_keys,
        fetch_raw_bodies,
        ("nikto", "httpx", "http_audit", "headers", "curl", "raw_http", "response", "security_header"),
    )
    port_raw_body = _artifact_non_empty_body_for_needles(
        raw_artifact_keys, fetch_raw_bodies, ("nmap", "naabu", "masscan", "recon_open_ports", "deep_port", "port_scan")
    )
    trivy_raw_body = _artifact_non_empty_body_for_needles(
        raw_artifact_keys, fetch_raw_bodies, ("trivy", "safety", "npm_audit", "pip_audit", "osv")
    )

    # --- tech_stack_structured
    tech_empty = _structured_stack_effectively_empty(structured) and not tech_table
    if whatweb_failed and not tech_empty:
        tech_env = _envelope(
            "parsed_from_fallback",
            "WhatWeb execution failed, but fallback technology signals were reconstructed from other collected evidence. "
            "Treat the technology stack as incomplete.",
        )
    elif whatweb_failed:
        if not (raw_hints.get("has_whatweb") or whatweb_completed):
            tech_env = _envelope("not_assessed", _no_conclusion_tool_reason("WhatWeb"))
        elif fetch_raw_bodies and not whatweb_raw_body:
            tech_env = _envelope(
                "artifact_missing_body",
                "WhatWeb reports failure; stdout/body artifacts were empty or not stored for parsing.",
            )
        else:
            tech_env = _envelope(
                "parser_error",
                "WhatWeb stdout/body was available, but no technology rows were produced by the parser.",
            )
    elif not tech_empty:
        if raw_hints.get("has_whatweb") or whatweb_completed:
            tech_env = _envelope_completed()
        else:
            tech_env = _envelope(
                "parsed_from_fallback",
                "Technology stack parsed from HTTP headers, HTML/JS markers, robots/sitemap, or recon fallback data.",
            )
    elif raw_hints.get("has_whatweb") or whatweb_completed:
        if not fetch_raw_bodies:
            tech_env = _envelope(
                "artifact_missing_body",
                "WhatWeb execution metadata or object keys exist, but stdout/body artifacts were not fetched (INCLUDE_MINIO/stage download disabled or missing).",
            )
        elif not whatweb_raw_body:
            tech_env = _envelope(
                "artifact_missing_body",
                "WhatWeb execution metadata exists, but stdout/body artifact was not stored or is empty in object storage.",
            )
        else:
            tech_env = _envelope(
                "no_observed_items_after_parsing",
                "WhatWeb artifact body was stored, but no technology rows were reconstructed (parser produced zero rows).",
            )
    elif not fetch_raw_bodies and (raw_hints.get("has_whatweb") or phase_outputs):
        tech_env = _envelope(
            "partial",
            "INCLUDE_MINIO=false: WhatWeb raw artifact bodies were not fetched; "
            "stack reconstruction from phase_outputs / recon_results only.",
        )
    elif not phase_outputs and not fetch_raw_bodies:
        tech_env = _envelope(
            "not_executed",
            "No phase outputs and raw fetching disabled; tech stack was not collected.",
        )
    else:
        tech_env = _envelope(
            "no_data",
            (fallback_messages.get("tech_stack") or "Stack not identified: no WhatWeb output and insufficient recon signals."),
        )

    # --- outdated_components
    outdated_has_advisory = any(r.cves or "cve" in (r.recommendation or "").lower() for r in outdated)
    outdated_has_sca_source = any("trivy" in (r.source or r.support_status or "").lower() for r in outdated)
    if outdated:
        if outdated_has_advisory or outdated_has_sca_source:
            outd_env = _envelope_completed()
        else:
            outd_env = _envelope(
                "partial",
                "Component/version inventory was parsed, but no fixed-version advisory result was available in the artifacts.",
            )
    elif trivy_failed:
        if not (has_dep_artifacts or trivy_completed):
            outd_env = _envelope("not_assessed", _no_conclusion_tool_reason("Trivy/dependency scanner"))
        elif fetch_raw_bodies and not trivy_raw_body:
            outd_env = _envelope(
                "artifact_missing_body",
                "Trivy/SCA tool reported failure; dependency stdout/body artifacts were empty or not stored.",
            )
        else:
            outd_env = _envelope(
                "parser_error",
                "Trivy/SCA artifact bodies were present, but no component inventory rows were parsed.",
            )
    elif deps:
        outd_env = _envelope(
            "partial",
            "Dependency artifacts were parsed into component inventory, but no vulnerability advisory rows were produced.",
        )
    elif trivy_enabled and not any("trivy" in (d.source or "").lower() for d in deps):
        if has_dep_artifacts:
            outd_env = _envelope(
                "no_observed_items_after_parsing",
                "TRIVY_ENABLED=true and dependency/SCA artifacts exist, but no Trivy rows were parsed.",
            )
        else:
            outd_env = _envelope(
                "not_executed",
                "TRIVY_ENABLED=true, but no Trivy/SCA artifact, SBOM, lockfile, or dependency manifest was present for this run.",
            )
    elif not fetch_raw_bodies and has_dep_artifacts:
        outd_env = _envelope(
            "partial",
            "INCLUDE_MINIO=false: dependency artifacts are indexed, but raw bodies were not fetched.",
        )
    elif trivy_completed:
        if fetch_raw_bodies and not trivy_raw_body:
            outd_env = _envelope(
                "artifact_missing_body",
                "Trivy/SCA completed per tool metadata, but no non-empty Trivy/lockfile/SBOM body was stored for parsing.",
            )
        else:
            outd_env = _envelope(
                "no_observed_items_after_parsing",
                "SCA artifacts were present, but no dependency or CVE rows were produced after parsing (zero rows).",
            )
    else:
        outd_env = _envelope(
            "not_executed",
            (
                fallback_messages.get("outdated")
                or "No outdated component signals (CVE/Trivy/searchsploit/versions)."
            ),
        )

    ssl_from_recon_only = bool(
        (ssl_out.issuer or ssl_out.validity)
        and not ssl_out.protocols
        and not ssl_out.weak_protocols
        and not ssl_out.weak_ciphers
        and not ssl_out.hsts
    )
    if tls_failed and not _ssl_surface_empty(ssl_out):
        ssl_env = _envelope(
            "completed_with_fallback",
            "testssl/sslscan execution failed, but fallback TLS or certificate signals were reconstructed. "
            "Full TLS configuration remains inconclusive.",
        )
    elif tls_failed:
        if not (raw_hints.get("has_tls") or tls_completed):
            ssl_env = _envelope("not_assessed", _no_conclusion_tool_reason("testssl/sslscan"))
        elif fetch_raw_bodies and not tls_raw_body:
            ssl_env = _envelope(
                "artifact_missing_body",
                "TLS scanner failure; testssl/sslscan stdout/body was not stored or was empty.",
            )
        else:
            ssl_env = _envelope(
                "no_observed_items_after_parsing",
                "TLS tool produced output bodies, but no SSL/TLS table values were parsed from them.",
            )
    elif not _ssl_surface_empty(ssl_out):
        ssl_env = (
            _envelope_completed()
            if not ssl_from_recon_only
            else _envelope(
                "parsed_from_fallback",
                "Certificate data available from recon; cipher inventory was not available in parsed TLS artifacts.",
            )
        )
    elif raw_hints.get("has_tls") and fetch_raw_bodies:
        if not tls_raw_body:
            ssl_env = _envelope(
                "artifact_missing_body",
                "TLS-related object keys or execution metadata exist, but no non-empty testssl/sslscan/SSL stdout body is stored.",
            )
        else:
            ssl_env = _envelope(
                "no_observed_items_after_parsing",
                "TLS raw bodies were stored, but the pipeline did not reconstruct a parseable testssl/sslscan table.",
            )
    elif not fetch_raw_bodies and raw_hints.get("has_tls"):
        ssl_env = _envelope(
            "partial",
            "INCLUDE_MINIO=false: TLS artifacts exist in index, but bodies were not fetched.",
        )
    elif tls_completed:
        if fetch_raw_bodies and not tls_raw_body:
            ssl_env = _envelope(
                "artifact_missing_body",
                "TLS tool completed per metadata, but no TLS stdout/body artifact is available in storage to parse.",
            )
        else:
            ssl_env = _envelope(
                "no_observed_items_after_parsing",
                "TLS stdout/body exists, but SSL/TLS table values were not produced (zero rows after parsing).",
            )
    else:
        ssl_env = _envelope(
            "no_data",
            (fallback_messages.get("ssl_tls") or "SSL/TLS: no testssl/sslscan output and no certificate data."),
        )

    if sec_hdr.rows:
        if security_headers_from_findings and not merged_http_headers:
            sec_env = _envelope(
                "parsed_from_fallback",
                "Missing security headers were reconstructed from findings evidence; full response header map "
                "was not collected.",
            )
        else:
            sec_env = _envelope_completed()
    elif merged_http_headers:
        sec_env = _envelope(
            "parser_error",
            "Partial headers present in data, but canonical security headers table was not built.",
        )
    elif header_tool_failed:
        if not (raw_hints.get("has_headers") or raw_hints.get("has_whatweb") or header_tool_completed):
            sec_env = _envelope("not_assessed", _no_conclusion_tool_reason("Nikto/httpx/WhatWeb header-capable tool"))
        elif fetch_raw_bodies and not header_raw_body:
            sec_env = _envelope(
                "artifact_missing_body",
                "Header-related tools failed; nikto/httpx/response stdout or body artifacts were not stored or were empty.",
            )
        else:
            sec_env = _envelope(
                "no_observed_items_after_parsing",
                "Header tool output exists, but no security header table rows were produced from parsing.",
            )
    elif raw_hints.get("has_headers") and fetch_raw_bodies:
        if not header_raw_body:
            sec_env = _envelope(
                "artifact_missing_body",
                "Header-capable execution metadata or keys exist, but no non-empty raw HTTP/header stdout/body was stored.",
            )
        else:
            sec_env = _envelope(
                "no_observed_items_after_parsing",
                "HTTP header bodies were stored, but the canonical security headers table was not populated (zero rows).",
            )
    elif header_tool_completed:
        if fetch_raw_bodies and not header_raw_body:
            sec_env = _envelope(
                "artifact_missing_body",
                "Header-capable tools completed per metadata, but no nikto/httpx/response body was stored to build the table.",
            )
        else:
            sec_env = _envelope(
                "no_observed_items_after_parsing",
                "Header tool output was present, but no security header table rows were produced.",
            )
    else:
        sec_env = _envelope(
            "no_data",
            (
                fallback_messages.get("security_headers")
                or "No http_headers map in recon and no embedded headers in phase outputs."
            ),
        )

    rs_signal = (
        robots_sitemap_merged.robots_found
        or robots_sitemap_merged.sitemap_found
        or robots.found
        or sitemap.found
        or (robots_sitemap_merged.notes or "").strip()
    )
    if robots.found or sitemap.found:
        rs_env = _envelope_completed()
    elif rs_signal and (robots_sitemap_merged.notes or "").strip():
        rs_env = _envelope("partial", "Merged robots/sitemap JSON available; raw robots/sitemap bodies may not have been parsed.")
    elif rs_signal:
        rs_env = _envelope_completed()
    elif not fetch_raw_bodies and (raw_hints.get("has_robots") or raw_hints.get("has_sitemap")):
        rs_env = _envelope(
            "partial",
            "INCLUDE_MINIO=false: robots/sitemap keys exist, but bodies were not fetched.",
        )
    else:
        rs_env = _envelope(
            "no_data",
            (fallback_messages.get("robots_sitemap") or "robots.txt and sitemap were not retrieved."),
        )

    email_sources_exist = bool(
        raw_hints.get("has_harvester")
        or raw_hints.get("has_email_fallback")
        or phase_outputs
        or harvester_completed
    )
    if final_emails:
        em_env = (
            _envelope(
                "completed_with_fallback",
                "Email indicators were parsed from fallback artifacts after theHarvester execution issues.",
            )
            if harvester_failed
            else _envelope_completed()
        )
    elif harvester_enabled and harvester_failed:
        em_env = (
            _envelope(
                "no_observed_items_after_parsing",
                "theHarvester execution failed, but fallback ARGUS sources were parsed and no email-like values were observed.",
            )
            if email_sources_exist
            else _envelope("not_assessed", _no_conclusion_tool_reason("theHarvester"))
        )
    elif email_sources_exist:
        em_env = _envelope(
            "no_observed_items_after_parsing",
            "Email-capable OSINT or fallback sources were parsed; no email-like values were observed.",
        )
    elif harvester_enabled:
        em_env = _envelope(
            "not_executed",
            (fallback_messages.get("leaked_emails") or "theHarvester enabled, but no masked emails found in data."),
        )
    else:
        em_env = _envelope(
            "not_executed",
            "Not scanned: HARVESTER_ENABLED=false — targeted email collection via theHarvester was not performed.",
        )

    if port_scan_failed and port_data.has_open_ports:
        port_env = _envelope(
            "completed_with_fallback",
            "nmap/naabu/masscan execution failed, but fallback port or service signals were reconstructed. "
            "Full port exposure remains inconclusive.",
        )
    elif port_scan_failed:
        if not (raw_hints.get("has_ports") or port_scan_completed):
            port_env = _envelope("not_assessed", _no_conclusion_tool_reason("nmap/naabu/masscan"))
        elif fetch_raw_bodies and not port_raw_body:
            port_env = _envelope(
                "artifact_missing_body",
                "Port scanners failed; nmap/naabu/masscan stdout or structured output was not stored or is empty.",
            )
        else:
            port_env = _envelope(
                "no_observed_items_after_parsing",
                "Port scan output bodies were present, but no open-port rows were parsed (zero rows).",
            )
    elif port_data.has_open_ports:
        if any("fallback" in s.lower() for s in port_data.data_sources or []):
            port_env = _envelope(
                "parsed_from_fallback",
                "Port exposure was reconstructed from successful HTTP/HTTPS artifacts; no full closed-port conclusion is implied.",
            )
        else:
            port_env = _envelope_completed()
    elif _raw_has_port_scan_artifact_keys(raw_artifact_keys) and fetch_raw_bodies:
        if not port_raw_body:
            port_env = _envelope(
                "artifact_missing_body",
                "Port scan object keys or execution metadata exist, but nmap/naabu/masscan stdout/body is empty in storage.",
            )
        else:
            port_env = _envelope(
                "no_observed_items_after_parsing",
                "Port scan raw bodies are present, but no open ports or services were parsed in this pipeline.",
            )
    elif _raw_has_port_scan_artifact_keys(raw_artifact_keys) and not fetch_raw_bodies:
        port_env = _envelope(
            "partial",
            "Port scan object keys are listed, but raw bodies were not fetched; cannot parse open ports for this view.",
        )
    elif port_scan_completed:
        if fetch_raw_bodies and not port_raw_body:
            port_env = _envelope(
                "artifact_missing_body",
                "Port scan completed per tool metadata, but no port-scan stdout/structured body was stored to parse.",
            )
        else:
            port_env = _envelope(
                "no_observed_items_after_parsing",
                "Port scanner output was stored, but no port exposure rows were produced (zero rows).",
            )
    else:
        port_env = _envelope(
            "no_data",
            "No nmap/naabu/masscan open port signals in collected scan data.",
        )

    mandatory = ValhallaMandatorySectionsModel(
        tech_stack_structured=tech_env,
        outdated_components=outd_env,
        ssl_tls_analysis=ssl_env,
        security_headers_analysis=sec_env,
        robots_sitemap_analysis=rs_env,
        leaked_emails=em_env,
        port_exposure=port_env,
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
    port_empty = PortExposureSummaryModel()
    mandatory, coverage = _compute_mandatory_sections_and_coverage(
        structured=structured,
        tech_table=tech_table,
        outdated=outdated,
        ssl_out=ssl_out,
        sec_hdr=sec_hdr,
        security_headers_from_findings=False,
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
        port_data=port_empty,
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


def _dataclass_to_dict(obj: Any) -> dict[str, Any]:
    """Convert a dataclass instance to a plain dict (JSON-safe)."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    return dict(obj) if isinstance(obj, dict) else {}


def _finding_is_rate_limit_signal(f: dict[str, Any]) -> bool:
    blob = f"{f.get('title', '')} {f.get('description', '')} {f.get('evidence', '')}".lower()
    return bool(("rate" in blob and "limit" in blob) or "http 429" in blob or "too many requests" in blob)


def _tools_for_wstg_from_parsed_sections(
    *,
    base_tools: list[str],
    robots: RobotsTxtAnalysisModel,
    sitemap: SitemapAnalysisModel,
    tech_table: list[TechStackTableRow],
    ssl_out: SslTlsAnalysisModel,
    security_headers: SecurityHeadersAnalysisModel,
    port_data: PortExposureSummaryModel,
    emails: list[str],
    outdated: list[OutdatedComponentRow],
    deps: list[DependencyAnalysisRow],
    findings: list[dict[str, Any]],
) -> list[str]:
    tools: list[str] = list(base_tools)

    def add(name: str) -> None:
        if name and name.lower() not in {t.lower() for t in tools}:
            tools.append(name)

    if robots.found or sitemap.found:
        add("curl")
    if tech_table:
        add("whatweb")
    if not _ssl_surface_empty(ssl_out):
        add("testssl")
    if security_headers.rows:
        add("httpx")
        add("nikto")
    if port_data.has_open_ports:
        add("nmap")
    if emails:
        add("theharvester")
    if outdated or deps:
        add("trivy")
    if any(_finding_is_rate_limit_signal(f) for f in findings):
        add("rate_limit_signal")
    return tools


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
    scan_options: dict[str, Any] | None = None,
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

    if not ww_merged and fetch_raw_bodies:
        for key, _ph in raw_artifact_keys:
            lowk = key.lower()
            if "whatweb" not in lowk:
                continue
            if "stdout" in lowk or "output" in lowk or _artifact_name_matches(key, _WHATWEB_KEY_HINTS):
                blob = _safe_download_raw(key)
                if not blob:
                    continue
                text = _text_from_raw_bytes(blob)
                if not text or not text.strip():
                    continue
                parsed = parse_whatweb_text_fallback(text.strip())
                if parsed:
                    ww_merged = parsed
                    logger.info(
                        "whatweb_text_fallback_used",
                        extra={"event": "whatweb_text_fallback_used", "key_suffix": key[-64:]},
                    )
                    break

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

    if _ssl_surface_empty(ssl_out):
        text_ssl = _ssl_from_testssl_text_artifacts(raw_artifact_keys, fetch_bodies=fetch_raw_bodies)
        if text_ssl and not _ssl_surface_empty(text_ssl):
            ssl_out = SslTlsAnalysisModel(
                issuer=text_ssl.issuer or ssl_out.issuer,
                validity=text_ssl.validity or ssl_out.validity,
                protocols=text_ssl.protocols or ssl_out.protocols,
                weak_protocols=text_ssl.weak_protocols or ssl_out.weak_protocols,
                weak_ciphers=text_ssl.weak_ciphers or ssl_out.weak_ciphers,
                hsts=text_ssl.hsts or ssl_out.hsts,
            )

    merged_http_headers = _http_headers_merged_from_recon_and_phases(recon_results, phase_outputs)
    marker_rows = _tech_rows_from_http_and_urls(
        merged_http_headers,
        robots,
        sitemap,
        raw_artifact_keys,
        fetch_bodies=fetch_raw_bodies,
    )
    if marker_rows:
        structured = _apply_tech_marker_rows_to_structured(structured, marker_rows)
        structured_rows = _tech_rows_from_structured(structured)
        tech_table = _merge_tech_stack_tables(
            structured_rows + marker_rows,
            legacy_rows,
            structured=structured,
        )
    sec_hdr = _security_headers_from_host_map(merged_http_headers)
    security_headers_from_findings = False

    if not sec_hdr.rows:
        fallback_header_sources: list[dict[str, dict[str, str]]] = [
            _security_headers_from_security_headers_result(phase_outputs, recon_results),
            _security_headers_from_nikto_stdout(raw_artifact_keys, fetch_bodies=fetch_raw_bodies),
            _security_headers_from_whatweb_stdout(ww_merged),
            _security_headers_from_raw_http_responses(raw_artifact_keys, fetch_bodies=fetch_raw_bodies),
        ]
        for fb_map in fallback_header_sources:
            if fb_map:
                for host, hdrs in fb_map.items():
                    cur = merged_http_headers.get(host, {})
                    merged_http_headers[host] = {**cur, **hdrs}
                sec_hdr = _security_headers_from_host_map(merged_http_headers)
                if sec_hdr.rows:
                    break
    if merged_http_headers:
        header_marker_rows = _tech_rows_from_http_and_urls(
            merged_http_headers,
            robots,
            sitemap,
            raw_artifact_keys,
            fetch_bodies=False,
        )
        if header_marker_rows:
            structured = _apply_tech_marker_rows_to_structured(structured, header_marker_rows)
            structured_rows = _tech_rows_from_structured(structured)
            tech_table = _merge_tech_stack_tables(
                structured_rows + marker_rows + header_marker_rows,
                legacy_rows,
                structured=structured,
            )
    if not sec_hdr.rows:
        finding_headers = _security_headers_from_findings(findings)
        if finding_headers.rows:
            sec_hdr = finding_headers
            security_headers_from_findings = True

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
                threat_excerpt = _format_threat_model_for_report(tm, 2000)
            else:
                threat_excerpt = _phased_output_narrative(od, 1500)
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
        with contextlib.suppress(TypeError, ValueError):
            emails.extend(_extract_emails_from_text(json.dumps(anomalies_structured, ensure_ascii=False)))
    for _ph, inp in phase_inputs:
        if isinstance(inp, dict):
            with contextlib.suppress(TypeError, ValueError):
                emails.extend(_extract_emails_from_text(json.dumps(inp, ensure_ascii=False)[:20000]))

    if not emails:
        harvester_phase_emails = _emails_from_harvester_phase_outputs(phase_outputs)
        if harvester_phase_emails:
            emails.extend(harvester_phase_emails)
            logger.info(
                "emails_harvester_phase_fallback_used",
                extra={"event": "emails_harvester_phase_fallback_used", "count": len(harvester_phase_emails)},
            )
    if not emails and fetch_raw_bodies:
        for key, _p in raw_artifact_keys:
            lowk = key.lower()
            if not any(tok in lowk for tok in ("harvester", "theharvester", "email")):
                continue
            blob = _safe_download_raw(key)
            if not blob:
                continue
            text = _text_from_raw_bytes(blob)
            if not text:
                continue
            parsed_emails = _parse_harvester_emails(text)
            if parsed_emails:
                emails.extend(parsed_emails)
                logger.info(
                    "emails_raw_artifact_fallback_used",
                    extra={"event": "emails_raw_artifact_fallback_used", "key_suffix": key[-64:]},
                )
            if len(emails) >= 64:
                break

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
            "Technology stack table was not populated because no parseable WhatWeb, HTTP header, HTML/JS, "
            "robots/sitemap, or recon fingerprint signals were available."
        )

    ssl_tls_fallback_message: str | None = None
    if _ssl_surface_empty(ssl_out):
        ssl_tls_fallback_message = (
            "SSL/TLS table was not populated because no parseable testssl.sh, sslscan, nmap ssl-enum-ciphers, "
            "openssl, or certificate metadata was available for this report context."
        )

    security_headers_fallback_message: str | None = None
    if not sec_hdr.rows and not merged_http_headers:
        security_headers_fallback_message = (
            "HTTP security header table was not populated because no parseable response header map or raw "
            "HTTP response artifact was available."
        )

    outdated_components_fallback_message: str | None = None
    if not outdated:
        has_trivy_rows = any("trivy" in (d.source or "").lower() for d in deps)
        if trivy_enabled and not has_trivy_rows:
            outdated_components_fallback_message = (
                "SCA via Trivy was not applicable because no filesystem target, container image, SBOM, or "
                "dependency manifest bodies were available in this scan. For external URL-only tests, "
                "ARGUS may use JS/bundle heuristics instead of full Trivy filesystem scanning."
            )
        else:
            outdated_components_fallback_message = (
                "No explicit component advisory signals (CVE, Trivy, searchsploit, or versioned WhatWeb/nmap "
                "fingerprints) were parsed from scan data."
            )

    robots_sitemap_fallback_message: str | None = None
    if not robots_sitemap_merged.robots_found and not robots_sitemap_merged.sitemap_found:
        robots_sitemap_fallback_message = (
            "robots.txt and sitemap.xml were not present in the parsed report context; related surface "
            "analysis is limited."
        )

    leaked_emails_fallback_message: str | None = None
    if not final_emails:
        leaked_emails_fallback_message = (
            "No masked email indicators detected. With HARVESTER_ENABLED=true theHarvester "
            "adds signals from stdout artifacts; otherwise only indirect matches in recon are possible."
        )

    ff: dict[str, bool] = {
        "HARVESTER_ENABLED": bool(harvester_enabled),
        "TRIVY_ENABLED": bool(trivy_enabled),
        "INCLUDE_MINIO": bool(fetch_raw_bodies),
    }
    if extra_feature_flags:
        ff.update({str(k): bool(v) for k, v in extra_feature_flags.items()})

    target_guess = ""
    if isinstance(recon_results, dict):
        target_guess = str(
            recon_results.get("target_url")
            or recon_results.get("target_domain")
            or recon_results.get("target")
            or ""
        )
    if not target_guess and findings:
        t0 = findings[0] if isinstance(findings[0], dict) else {}
        target_guess = str(t0.get("affected_url") or t0.get("url") or t0.get("target") or "")

    port_data = _build_port_exposure_summary(
        nmap_blob=nmap_blob,
        ports=ports,
        structured=structured,
        raw_artifact_keys=raw_artifact_keys,
        fetch_bodies=fetch_raw_bodies,
        target_hint=target_guess,
        tls_observed=not _ssl_surface_empty(ssl_out),
        http_observed=bool(merged_http_headers or sec_hdr.rows),
    )

    raw_hints = _raw_keys_hint_flags(raw_artifact_keys)
    mandatory, coverage = _compute_mandatory_sections_and_coverage(
        structured=structured,
        tech_table=tech_table,
        outdated=outdated,
        ssl_out=ssl_out,
        sec_hdr=sec_hdr,
        security_headers_from_findings=security_headers_from_findings,
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
        port_data=port_data,
    )
    rs_analysis_bundle = ValhallaRobotsSitemapAnalysisBundleModel(
        robots_txt=robots,
        sitemap=sitemap,
        merged=robots_sitemap_merged,
    )

    from src.reports.wstg_coverage import (
        build_test_limitations as _build_test_limitations,
    )
    from src.reports.wstg_coverage import (
        build_wstg_coverage as _build_wstg_coverage,
    )

    finding_dicts = [f if isinstance(f, dict) else {} for f in findings]
    tools_executed_names = _tools_for_wstg_from_parsed_sections(
        base_tools=[at.name for at in appendix_tools if at.name],
        robots=robots,
        sitemap=sitemap,
        tech_table=tech_table,
        ssl_out=ssl_out,
        security_headers=sec_hdr,
        port_data=port_data,
        emails=final_emails,
        outdated=outdated,
        deps=deps,
        findings=finding_dicts,
    )
    wstg_result = _build_wstg_coverage(tools_executed_names, finding_dicts)
    try:
        wstg_pct = float(wstg_result.coverage_percentage)
    except (TypeError, ValueError):
        wstg_pct = 0.0
    wstg_cov_n = int(getattr(wstg_result, "covered", 0) or 0)
    wstg_partial_n = int(getattr(wstg_result, "partial", 0) or 0)
    wstg_total = int(getattr(wstg_result, "total_tests", 0) or 0)
    wstg_exec_degraded = wstg_pct < 70.0
    wstg_zero = wstg_total > 0 and wstg_cov_n == 0 and wstg_partial_n == 0
    from src.reports.report_quality_gate import evaluate_valhalla_engagement_title_and_full
    from src.reports.valhalla_tool_health import build_tool_health_summary_rows, tool_health_rows_to_jinja

    mstat: dict[str, str] = {}
    md_mand = mandatory.model_dump(mode="python")
    for sid in _MANDATORY_SECTION_IDS:
        ent = md_mand.get(sid) if isinstance(md_mand, dict) else None
        if isinstance(ent, dict):
            mstat[sid] = str(ent.get("status") or "")
    engagement_title, full_v = evaluate_valhalla_engagement_title_and_full(
        wstg_coverage_pct=wstg_pct,
        mandatory_section_status=mstat,
        findings=finding_dicts,
        tool_error_rows=coverage.tool_errors_summary,
    )

    ssl_tls_table_rows = build_ssl_tls_table_rows(
        recon_results if isinstance(recon_results, dict) else None,
        ssl_out,
        target_hint=target_guess,
    )
    security_headers_table_rows = build_security_headers_table_rows(sec_hdr)
    port_exposure_table_rows = build_port_exposure_table_rows(port_data, target_hint=target_guess)
    leaked_email_rows = build_leaked_email_rows(final_emails)
    evidence_inv = build_evidence_inventory_rows(
        finding_dicts,
        ssl_tls=ssl_out,
        security_headers=sec_hdr,
        tech_stack=tech_table,
        port_exposure=port_data,
        port_rows=port_exposure_table_rows,
        outdated_components=outdated,
        leaked_email_rows=leaked_email_rows,
    )
    th_jinja = tool_health_rows_to_jinja(
        build_tool_health_summary_rows(
            tool_run_summaries=tool_run_summaries,
            appendix_tool_names=[a.name for a in appendix_tools if a.name],
            raw_error_rows=coverage.tool_errors_summary,
            mandatory_section_status=mstat,
        )
    )

    scan_config_for_lim: dict[str, Any] = {}
    for _ph, inp in phase_inputs:
        if isinstance(inp, dict):
            scan_config_for_lim.update(inp)
            break

    scan_results_for_lim: dict[str, Any] = {}
    for _ph, od in phase_outputs:
        if isinstance(od, dict):
            if od.get("waf_detected") or od.get("wafw00f"):
                scan_results_for_lim["waf_detected"] = True
            if od.get("rate_limited") or od.get("rate_limiting_detected"):
                scan_results_for_lim["rate_limited"] = True
            if od.get("ssl_errors") or od.get("tls_errors"):
                scan_results_for_lim["ssl_errors"] = True

    test_lim = _build_test_limitations(scan_config_for_lim, scan_results_for_lim)

    sca_mode = "none"
    trivy_run_status = "not_applicable"
    if trivy_enabled:
        manifestish = 0
        trivyish = 0
        for key, _ in raw_artifact_keys:
            lk = key.lower()
            if any(
                m in lk
                for m in (
                    "package.json",
                    "package-lock",
                    "yarn.lock",
                    "pnpm-lock",
                    "requirements",
                    "poetry.lock",
                    "pipfile",
                    "pom.xml",
                    "build.gradle",
                    "go.mod",
                    "composer.lock",
                    "cargo.lock",
                    "dockerfile",
                    "container",
                )
            ):
                manifestish += 1
            if "trivy" in lk or "sbom" in lk or "cyclonedx" in lk or "spdx" in lk:
                trivyish += 1
        sca_manifest_count = manifestish
        sca_artifact_count = trivyish
        if manifestish == 0 and trivyish == 0:
            sca_mode = "url_js_fingerprint"
        elif trivyish and manifestish:
            sca_mode = "filesystem"
        elif trivyish:
            sca_mode = "container_image" if "docker" in str(phase_outputs).lower() else "sbom"
        else:
            sca_mode = "filesystem"
        trivy_run_status = "not_executed"
        _bad_tr = frozenset({"failed", "error", "timeout", "cancelled", "canceled"})
        saw_trivy = False
        for n, s in tool_run_summaries or []:
            if "trivy" not in (n or "").lower():
                continue
            saw_trivy = True
            if (s or "").lower() in _bad_tr:
                trivy_run_status = "failed"
                break
            trivy_run_status = "executed_with_findings" if outdated else "executed_no_findings"
        if trivyish and not saw_trivy and trivy_run_status == "not_executed":
            trivy_run_status = "executed_with_findings" if outdated else "executed_no_findings"
    else:
        sca_manifest_count = 0
        sca_artifact_count = 0
        trivy_run_status = "not_applicable"
        sca_mode = "none"

    active_injection_scan_options = dict(scan_options) if isinstance(scan_options, dict) else {}
    for ph, od in phase_outputs:
        if (ph or "").lower() != "vuln_analysis" or not isinstance(od, dict):
            continue
        phase_aic = od.get("active_injection_coverage")
        if isinstance(phase_aic, dict) and phase_aic:
            active_injection_scan_options["active_injection_coverage"] = phase_aic
            break

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
        leaked_email_rows=leaked_email_rows,
        ssl_tls_analysis=ssl_out,
        ssl_tls_table_rows=ssl_tls_table_rows,
        security_headers_analysis=sec_hdr,
        security_headers_table_rows=security_headers_table_rows,
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
        wstg_coverage=_dataclass_to_dict(wstg_result),
        test_limitations=test_lim,
        valhalla_engagement_title=engagement_title,
        full_valhalla=bool(full_v),
        port_exposure=port_data,
        port_exposure_table_rows=port_exposure_table_rows,
        evidence_inventory=evidence_inv,
        tool_health_summary=th_jinja,
        wstg_execution_degraded=wstg_exec_degraded,
        wstg_coverage_zero_executed=wstg_zero,
        sca_mode=sca_mode,
        trivy_run_status=trivy_run_status,
        sca_manifest_count=sca_manifest_count,
        sca_artifact_count=sca_artifact_count,
        active_injection_coverage=build_active_injection_coverage(findings, active_injection_scan_options),
    )
