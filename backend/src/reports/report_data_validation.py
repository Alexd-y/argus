"""RPT — Validate ``ReportData`` after build, before render/upload (T3)."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from src.reports.data_collector import executive_severity_totals_from_severity_strings
from src.reports.generators import ReportData
from src.reports.report_quality_gate import (
    cvss_conflict_reason,
    severity_cvss_band_mismatch_reason,
)

logger = logging.getLogger(__name__)

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

_REPORT_TIERS: frozenset[str] = frozenset({"midgard", "asgard", "valhalla"})

# Minimal Valhalla shape: keys present on ``ValhallaReportContext.model_dump()`` (VHL-001).
_VALHALLA_VC_REQUIRED_KEYS: frozenset[str] = frozenset(
    {
        "risk_matrix",
        "critical_vulns",
        "robots_txt_analysis",
        "sitemap_analysis",
        "ssl_tls_analysis",
        "ssl_tls_table_rows",
        "security_headers_analysis",
        "security_headers_table_rows",
        "tech_stack_table",
        "tech_stack_structured",
        "dependency_analysis",
        "outdated_components",
        "robots_sitemap_merged",
        "robots_sitemap_analysis",
        "leaked_emails",
        "mandatory_sections",
        "coverage",
        "full_valhalla",
        "evidence_inventory",
        "tool_health_summary",
    }
)


def _normalize_tier(tier: str | None) -> str:
    t = (tier or "").strip().lower()
    return t if t in _REPORT_TIERS else "midgard"


@dataclass
class ReportDataValidationResult:
    ok: bool
    reason_codes: list[str] = field(default_factory=list)


def report_validation_failure_payload(
    *,
    report_id: str,
    tenant_id: str,
    tier: str,
    reason_codes: list[str],
) -> dict[str, Any]:
    """Structured fields for JSON logging (no findings text, no HIBP notes)."""
    return {
        "event": "report_data_validation_failed",
        "report_id": report_id,
        "tenant_id": tenant_id,
        "tier": tier,
        "reason_codes": list(reason_codes),
    }


def log_report_validation_failure(payload: dict[str, Any]) -> None:
    logger.error(json.dumps(payload, ensure_ascii=False))


def validate_report_data(
    report_data: ReportData,
    *,
    tier: str | None = None,
    template_context: dict[str, Any] | None = None,
) -> ReportDataValidationResult:
    """
    Pre-render checks: severity totals vs findings, degenerate findings, HIBP sanity, Valhalla context.

    Policy: findings with empty title, empty description, and unknown/empty severity are rejected
    (``finding_unknown_empty``).
    """
    reasons: list[str] = []
    tier_norm = _normalize_tier(tier)

    expected = executive_severity_totals_from_severity_strings(f.severity for f in report_data.findings)
    sm = report_data.summary
    for key in ("critical", "high", "medium", "low", "info"):
        if int(getattr(sm, key, 0) or 0) != int(expected.get(key, 0)):
            reasons.append("severity_summary_mismatch")
            break

    for f in report_data.findings:
        title = (f.title or "").strip()
        desc = (f.description or "").strip()
        sev_raw = (f.severity or "").strip().lower()
        unknown_sev = not sev_raw or sev_raw == "unknown"
        if not title and not desc and unknown_sev:
            reasons.append("finding_unknown_empty")
            break
        conflict = cvss_conflict_reason(f)
        if conflict:
            reasons.append("finding_cvss_conflict")
        band = severity_cvss_band_mismatch_reason(f)
        if band:
            reasons.append("finding_severity_cvss_band_mismatch")
        has_poc = isinstance(getattr(f, "proof_of_concept", None), dict) and bool(
            getattr(f, "proof_of_concept", None)
        )
        has_refs = bool(getattr(f, "evidence_refs", None) or [])
        if sev_raw in {"high", "critical"} and not has_poc and not has_refs:
            reasons.append("finding_high_critical_without_evidence")
        confidence = str(getattr(f, "confidence", "") or "").lower()
        if confidence == "confirmed":
            validation_status = str(getattr(f, "validation_status", "") or "").lower()
            evidence_quality = str(getattr(f, "evidence_quality", "") or "").lower()
            if validation_status not in {"validated", "partially_validated"} or evidence_quality in {
                "none",
                "weak",
            }:
                reasons.append("finding_confirmed_without_strong_evidence")

    hibp = report_data.hibp_pwned_password_summary
    if isinstance(hibp, dict) and hibp:
        try:
            checks_run = max(0, int(hibp.get("checks_run") or 0))
            pwned = max(0, int(hibp.get("pwned_count") or 0))
            if "checks_attempted" in hibp and hibp["checks_attempted"] is not None:
                attempted = max(0, int(hibp["checks_attempted"]))
                if attempted < checks_run:
                    reasons.append("hibp_checks_attempted_lt_run")
                elif pwned > checks_run:
                    reasons.append("hibp_pwned_gt_checks_run")
            else:
                if pwned > checks_run:
                    reasons.append("hibp_pwned_gt_checks_run")
        except (TypeError, ValueError):
            reasons.append("hibp_coercion_failed")

    if tier_norm == "valhalla":
        ctx = template_context or {}
        vc = ctx.get("valhalla_context")
        if not isinstance(vc, dict):
            reasons.append("valhalla_context_missing")
        else:
            missing = sorted(k for k in _VALHALLA_VC_REQUIRED_KEYS if k not in vc)
            if missing:
                reasons.append("valhalla_context_incomplete")
            # Consistency: injection coverage vs findings
            inj_coverage = vc.get("active_injection_coverage") or {}
            families = inj_coverage.get("families") or {}
            for f in report_data.findings:
                f_type = (getattr(f, "type", "") or "").lower()
                f_title = (getattr(f, "title", "") or "").lower()
                f_desc = (getattr(f, "description", "") or "").lower()
                combined = f"{f_type} {f_title} {f_desc}"
                if "sql" in combined:
                    fam = families.get("sqli") or {}
                    if isinstance(fam, dict) and fam.get("status") == "not_assessed":
                        reasons.append("sqli_finding_but_injection_not_assessed")
                if "xss" in combined or "cross-site" in combined:
                    fam = families.get("xss") or {}
                    if isinstance(fam, dict) and fam.get("status") == "not_assessed":
                        reasons.append("xss_finding_but_injection_not_assessed")
            # Consistency: auth testing vs authz findings
            authenticated = vc.get("report_quality_gate", {}).get("authenticated", False) if isinstance(vc.get("report_quality_gate"), dict) else False
            if not authenticated:
                for f in report_data.findings:
                    f_title = (getattr(f, "title", "") or "").lower()
                    f_type = (getattr(f, "type", "") or "").lower()
                    combined = f"{f_type} {f_title}"
                    if any(kw in combined for kw in ("idor", "auth bypass", "role bypass", "authorization")):
                        reasons.append("authz_finding_without_authenticated_testing")
        scan_art = ctx.get("scan_artifacts")
        if not isinstance(scan_art, dict) or "status" not in scan_art:
            reasons.append("valhalla_scan_artifacts_meta_missing")

    uniq = list(dict.fromkeys(reasons))
    return ReportDataValidationResult(ok=len(uniq) == 0, reason_codes=uniq)


def pre_release_quality_warnings(
    report_data: ReportData,
    *,
    tier: str | None = None,
    template_context: dict[str, Any] | None = None,
    wstg_coverage_pct: float = 0.0,
) -> list[str]:
    """Point 18 — quality warnings (informational only, never blocks report release).
    
    Returns list of warning strings for operator review. Reports ALWAYS proceed.
    """
    reasons: list[str] = []
    tier_norm = _normalize_tier(tier)
    ctx = template_context or {}
    vc = ctx.get("valhalla_context")

    # WSTG < 100% but title says "full" pentest — informational only
    if wstg_coverage_pct < 100.0 and tier_norm == "valhalla":
        reasons.append("WARNING: WSTG coverage below 100% — use WRB-powered gap closure commands to cover missing tests")
    
    # High finding without VALIDATED evidence — flag for retest, never block
    for f in report_data.findings:
        sev = str(getattr(f, "severity", "") or "").lower()
        classif = str(getattr(f, "evidence_classification", "") or "").lower()
        if sev == "high" and classif != "validated":
            reasons.append("WARNING: High-severity finding without VALIDATED evidence — re-test with WRB-generated payloads")
            break
    
    # HIBP checks_run = 0 — flag for next scan, never block
    if tier_norm == "valhalla":
        hibp = report_data.hibp_pwned_password_summary
        if not isinstance(hibp, dict) or not hibp:
            reasons.append("WARNING: HIBP checks_run = 0 — schedule credential scan with authorized_password_samples_or_hashes")
        elif int(hibp.get("checks_run", 0) or 0) == 0:
            reasons.append("WARNING: HIBP checks_run = 0 — schedule credential scan with authorized_password_samples_or_hashes")
    
    # TLS parser empty — flag for retest, never block
    if vc:
        ssl_data = vc.get("ssl_tls_analysis")
        if isinstance(ssl_data, dict) and not ssl_data.get("protocols") and not ssl_data.get("issuer") and not ssl_data.get("evidence_id"):
            reasons.append("WARNING: TLS parser produced no results — re-run with testssl/sslscan/openssl fallback tools")
    
    # Port parser empty — flag for retest, never block
    if vc:
        port_data = vc.get("port_exposure")
        if isinstance(port_data, dict) and not port_data.get("has_open_ports") and not port_data.get("data_sources"):
            reasons.append("WARNING: Port exposure parser empty — re-run with nmap/naabu/httpx probes")
    
    # Headers table has artifact path instead of endpoint URL — fix, never block
    if vc:
        headers = vc.get("security_headers_table_rows") or []
        if isinstance(headers, list):
            for row in headers:
                if isinstance(row, dict) and "artifact" in str(row.get("header", row.get("url", ""))).lower():
                    reasons.append("WARNING: Headers table contains artifact path instead of endpoint URL — correct in next scan")
                    break
    
    # Tool commands/versions/artifact paths empty — flag, never block
    if vc:
        tool_health = vc.get("tool_health_summary") or []
        if isinstance(tool_health, list) and tool_health:
            for row in tool_health:
                if isinstance(row, dict):
                    if not row.get("tool_command") or not row.get("tool_version"):
                        reasons.append("WARNING: Tool health row has empty tool_command or tool_version — re-collect tool metadata")
                        break
    
    # Technology version fields empty without reason — flag, never block
    if vc:
        tech_stack = vc.get("tech_stack_table") or []
        if isinstance(tech_stack, list):
            for row in tech_stack:
                if isinstance(row, dict) and not row.get("version") and not row.get("version_reason"):
                    reasons.append("WARNING: Technology version field empty — re-run whatweb/wappalyzer/trivy for version detection")
                    break
    
    # AI/debug snippets in any AI section — strip, never block
    ai_sections = ctx.get("ai_sections") or {}
    if isinstance(ai_sections, dict):
        for key, text in ai_sections.items():
            if isinstance(text, str):
                from src.reports.report_quality_gate import detect_code_garbage
                garbage = detect_code_garbage(text)
                if garbage:
                    reasons.append(f"WARNING: Code/debug garbage detected in AI section '{key}' — auto-sanitized")
                    break
    
    # ANSI escape sequences in raw request/response — strip, never block
    for f in report_data.findings:
        poc = getattr(f, "proof_of_concept", {}) or {}
        if isinstance(poc, dict):
            raw_req = str(poc.get("raw_request", "") or "")
            raw_resp = str(poc.get("raw_response", "") or "")
            if _ANSI_ESCAPE_RE.search(raw_req) or _ANSI_ESCAPE_RE.search(raw_resp):
                reasons.append("WARNING: ANSI escape sequences in raw request/response — auto-sanitized")
                break
    
    return reasons


pre_release_blocking_gate = pre_release_quality_warnings  # backward compat alias — never blocks


_EXEC_SEV_SECTION_KEYS: frozenset[str] = frozenset(
    {"executive_summary", "executive_summary_valhalla"}
)

_SEV_PATTERNS_EN: list[tuple[str, str]] = [
    (r"\b(\d{1,4})\s+critical\b", "critical"),
    (r"\b(\d{1,4})\s+critically\b", "critical"),
    (r"\b(\d{1,4})\s+high[\s-]severity\b", "high"),
    (r"\b(\d{1,4})\s+medium\b", "medium"),
    (r"\b(\d{1,4})\s+low\b", "low"),
    (r"\b(\d{1,4})\s+informational\b", "info"),
    (r"\b(\d{1,4})\s+info\b", "info"),
]

# Backward compat: RU severity labels from legacy scanner tools that emit Russian output.
_SEV_PATTERNS_RU: list[tuple[str, str]] = [
    (r"\b(\d{1,4})\s+\u043a\u0440\u0438\u0442\u0438\u0447", "critical"),
    (r"\b(\d{1,4})\s+\u0432\u044b\u0441\u043e\u043a", "high"),
    (r"\b(\d{1,4})\s+\u0441\u0440\u0435\u0434\u043d", "medium"),
    (r"\b(\d{1,4})\s+\u043d\u0438\u0437\u043a", "low"),
]

# Combined for backward compat (used in quality gate text extraction).
_SEV_PATTERNS: list[tuple[str, str]] = _SEV_PATTERNS_EN + _SEV_PATTERNS_RU


def _int_totals_from_payload(payload: dict[str, Any]) -> dict[str, int]:
    raw = payload.get("executive_severity_totals")
    if not isinstance(raw, dict):
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    out: dict[str, int] = {}
    for k in ("critical", "high", "medium", "low", "info"):
        try:
            out[k] = max(0, int(raw.get(k) or 0))
        except (TypeError, ValueError):
            out[k] = 0
    return out


def _finding_count_from_payload(payload: dict[str, Any]) -> int:
    try:
        return max(0, int(payload.get("finding_count") or 0))
    except (TypeError, ValueError):
        return 0


def validate_executive_ai_text_against_payload(
    section_key: str,
    payload: dict[str, Any],
    text: str,
) -> tuple[bool, list[str]]:
    """
    T9 — Compare executive-summary prose counts to structured ``executive_severity_totals``,
    ``finding_count``, and HIBP aggregates. Conservative: only flags explicit numeric claims.
    """
    if section_key not in _EXEC_SEV_SECTION_KEYS:
        return True, []
    reasons: list[str] = []
    t = (text or "").strip()
    if not t:
        return True, []
    totals = _int_totals_from_payload(payload)
    tl = t.lower()

    mentioned: dict[str, list[int]] = {k: [] for k in totals}
    for pat, bucket in _SEV_PATTERNS:
        for m in re.finditer(pat, tl, flags=re.IGNORECASE):
            try:
                mentioned[bucket].append(int(m.group(1)))
            except (ValueError, IndexError):
                continue
    for bucket, nums in mentioned.items():
        if not nums:
            continue
        exp = totals[bucket]
        for n in nums:
            if n != exp:
                reasons.append("executive_ai_severity_count_mismatch")
                break
        if reasons:
            break

    fc = _finding_count_from_payload(payload)
    # EN labels; union with RU patterns for legacy scanner output support
    for m in re.finditer(r"\b(\d{1,4})\s+(?:findings?|vulnerabilit(?:y|ies)|уязвимост|находок)\b", tl, re.IGNORECASE):
        try:
            n = int(m.group(1))
        except ValueError:
            continue
        if n != fc:
            reasons.append("executive_ai_finding_count_mismatch")
            break

    hibp = payload.get("hibp_pwned_password_summary")
    hibp_context = "pwned" in tl or "hibp" in tl or "breach" in tl or "password" in tl
    if isinstance(hibp, dict) and hibp and hibp_context:
        try:
            pwned = max(0, int(hibp.get("pwned_count") or 0))
            checks = max(0, int(hibp.get("checks_run") or 0))
        except (TypeError, ValueError):
            pwned, checks = 0, 0
        for m in re.finditer(r"\b(\d{1,4})\s+pwned\b", tl):
            try:
                if int(m.group(1)) != pwned:
                    reasons.append("executive_ai_hibp_count_mismatch")
                    break
            except ValueError:
                continue
        if "executive_ai_hibp_count_mismatch" not in reasons:
            for m in re.finditer(
                r"\b(\d{1,4})\s+(?:of\s+)?(?:the\s+)?(\d{1,4})\s+(?:checked|checks|samples)\b",
                tl,
            ):
                try:
                    a, b = int(m.group(1)), int(m.group(2))
                except ValueError:
                    continue
                if (a, b) != (pwned, checks) and (a, b) != (checks, pwned):
                    reasons.append("executive_ai_hibp_count_mismatch")
                    break

    uniq = list(dict.fromkeys(reasons))
    return len(uniq) == 0, uniq


def grounded_executive_summary_fallback_text(payload: dict[str, Any]) -> str:
    """Safe replacement when generated executive text fails structured fact checks."""
    totals = _int_totals_from_payload(payload)
    fc = _finding_count_from_payload(payload)
    parts = [
        f"Structured results: {fc} finding(s) recorded. "
        f"Severity totals — critical: {totals['critical']}, high: {totals['high']}, "
        f"medium: {totals['medium']}, low: {totals['low']}, informational: {totals['info']}."
    ]
    hibp = payload.get("hibp_pwned_password_summary")
    if isinstance(hibp, dict) and hibp:
        try:
            pwned = max(0, int(hibp.get("pwned_count") or 0))
            checks = max(0, int(hibp.get("checks_run") or 0))
        except (TypeError, ValueError):
            pwned, checks = 0, 0
        parts.append(
            f" Credential sample checks (HIBP): {pwned} hit(s) in {checks} check(s) "
            "where sampling was performed."
        )
    parts.append(" Narrative aligned to verified metrics above.")
    return " ".join(parts)
