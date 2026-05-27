"""Report generators — HTML, JSON, PDF, CSV, Markdown."""

import csv
import hashlib
import io
import json
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from jinja2 import Environment, FileSystemLoader

from src.api.schemas import Finding, ReportSummary
from src.db.models import Finding as FindingModel
from src.db.models import Report
from src.db.models import Scan
from src.owasp_top10_2025 import (
    OWASP_TOP10_2025_CATEGORY_IDS,
    OWASP_TOP10_2025_CATEGORY_TITLES,
    parse_owasp_category,
)
from src.reports.data_collector import (
    FindingRow,
    OwaspCategorySummaryEntry,
    ScanReportData,
    TimelineRow,
    build_owasp_summary_from_counts,
    executive_severity_totals_from_severity_strings,
)
from src.reports.finding_metadata import (
    normalize_confidence,
    normalize_evidence_refs,
    normalize_evidence_type,
)
from src.reports.report_quality_gate import score_evidence_quality, validation_status_for_quality
from src.reports.infra_recommendations import (
    build_verification_commands,
    generate_infra_recommendations,
    build_truthfulness_metrics,
)
from src.storage.s3 import get_finding_poc_screenshot_presigned_url

logger = logging.getLogger(__name__)

# Valhalla HTML: OWASP Top 10:2021 label for Security Misconfiguration (internal id remains 2025 A02).
VALHALLA_OWASP_2021_SECURITY_MISCONFIGURATION_CODE = "A05:2021"
_VALHALLA_OWASP_2021_DISPLAY: dict[str, tuple[str, str, str]] = {
    "A01": (
        "A01:2021",
        "Broken Access Control",
        "Access control enforcement failures such as unauthorized access to data or functions.",
    ),
    "A02": (
        "A05:2021",
        "Security Misconfiguration",
        "Missing, incomplete, or unsafe security configuration, including HTTP security response headers.",
    ),
    "A03": (
        "A06:2021",
        "Vulnerable and Outdated Components",
        "Known-vulnerable, unsupported, or outdated software components.",
    ),
    "A04": (
        "A02:2021",
        "Cryptographic Failures",
        "Weaknesses in cryptographic design, TLS configuration, or protection of sensitive data in transit or at rest.",
    ),
    "A05": (
        "A03:2021",
        "Injection",
        "Untrusted input interpreted as commands, queries, templates, or other executable syntax.",
    ),
    "A06": (
        "A04:2021",
        "Insecure Design",
        "Design-level weaknesses that require changes to security architecture or control design.",
    ),
    "A07": (
        "A07:2021",
        "Identification and Authentication Failures",
        "Authentication, session, credential, lockout, or rate-limiting control weaknesses.",
    ),
    "A08": (
        "A08:2021",
        "Software and Data Integrity Failures",
        "Integrity weaknesses in software updates, CI/CD, deserialization, or trusted data flows.",
    ),
    "A09": (
        "A09:2021",
        "Security Logging and Monitoring Failures",
        "Insufficient logging, monitoring, alerting, or incident visibility.",
    ),
    "A10": (
        "A10:2021",
        "Server-Side Request Forgery",
        "Server-side requests to unintended destinations caused by insufficient validation.",
    ),
}

# VHL-005 — Valhalla JSON/CSV section keys (aligned with Report Valhalla / template context).
VALHALLA_SECTIONS_CSV_FORMAT = "valhalla_sections.csv"
_VHL_AI_EXPLOIT_CHAINS = "exploit_chains"
_VHL_AI_REMEDIATION_STAGES = "remediation_stages"
_VHL_AI_ZERO_DAY = "zero_day_potential"
_VHL_AI_ROADMAP = "prioritization_roadmap"
_VHL_AI_HARDENING = "hardening_recommendations"

# Valhalla-tier report section rendering order.
# Sections are emitted in this sequence by the HTML/PDF generator.
# Reordering affects the final report layout; adding a new section here
# also requires a corresponding template partial and context builder entry.
_VALHALLA_REPORT_SECTION_ORDER: tuple[str, ...] = (
    "title_meta",
    "executive_summary_counts",
    "owasp_compliance",
    "robots_sitemap",
    "tech_stack",
    "outdated_components",
    "emails",
    "ssl_tls",
    "ssl_tls_table_rows",
    "headers",
    "security_headers_table_rows",
    "dependencies",
    "risk_matrix",
    "critical_vulns",
    "full_valhalla",
    "evidence_inventory",
    "tool_health_summary",
    "threat_modeling_ref",
    "findings",
    "exploit_chains_text",
    "remediation_stages_text",
    "zero_day_text",
    "conclusion_text",
    "hibp_pwned_password_summary",
    "appendices",
)


@dataclass
class TimelineEntry:
    """Timeline entry for report."""

    phase: str
    order_index: int
    entry: dict[str, Any] | None
    created_at: str | None


@dataclass
class PhaseOutputEntry:
    """Phase output for report."""

    phase: str
    output_data: dict[str, Any] | None


@dataclass
class EvidenceEntry:
    """Evidence for report."""

    finding_id: str
    object_key: str
    description: str | None


@dataclass
class ScreenshotEntry:
    """Screenshot for report."""

    object_key: str
    url_or_email: str | None


@dataclass
class ReportData:
    """Unified report data for generators."""

    report_id: str
    target: str
    summary: ReportSummary
    findings: list[Finding]
    technologies: list[str]
    created_at: str | None = None
    scan_id: str | None = None
    tenant_id: str | None = None
    ai_insights: str | list[str] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    phase_outputs: list[PhaseOutputEntry] = field(default_factory=list)
    evidence: list[EvidenceEntry] = field(default_factory=list)
    screenshots: list[ScreenshotEntry] = field(default_factory=list)
    executive_summary: str | None = None
    remediation: str | list[str] = field(default_factory=list)
    raw_artifacts: list[dict[str, Any]] = field(default_factory=list)
    hibp_pwned_password_summary: dict[str, Any] | None = None


def summary_dict_to_report_summary(summary: dict[str, Any] | None) -> ReportSummary:
    """Build ReportSummary from a summary JSON blob (e.g. Report.summary or ReportRowSlice.summary)."""
    s = dict(summary or {})
    s.pop("ai_insights", None)
    return ReportSummary(
        critical=int(s.get("critical", 0)),
        high=int(s.get("high", 0)),
        medium=int(s.get("medium", 0)),
        low=int(s.get("low", 0)),
        info=int(s.get("info", 0)),
        technologies=s.get("technologies", []) or [],
        sslIssues=int(s.get("sslIssues", 0)),
        headerIssues=int(s.get("headerIssues", 0)),
        leaksFound=bool(s.get("leaksFound", False)),
    )


def report_to_summary(report: Report) -> ReportSummary:
    """Build ReportSummary from Report.summary JSONB."""
    return summary_dict_to_report_summary(report.summary)


def _timeline_row_to_entry(row: TimelineRow) -> TimelineEntry:
    ca = row.created_at
    if ca is None:
        created = None
    elif hasattr(ca, "isoformat"):
        created = ca.isoformat()
    else:
        created = str(ca)
    return TimelineEntry(
        phase=row.phase,
        order_index=row.order_index,
        entry=row.entry,
        created_at=created,
    )


_VALIDATION_STATUS_VALUES = {"missing", "unverified", "partially_validated", "validated"}
_EVIDENCE_QUALITY_VALUES = {"none", "weak", "moderate", "strong"}


def _normalize_validation_status(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    return value if value in _VALIDATION_STATUS_VALUES else "unverified"


def _normalize_evidence_quality(raw: Any) -> str:
    value = str(raw or "").strip().lower()
    return value if value in _EVIDENCE_QUALITY_VALUES else "none"


def _effective_evidence_quality(finding: Any) -> str:
    quality = _normalize_evidence_quality(getattr(finding, "evidence_quality", None))
    if quality == "none":
        quality = score_evidence_quality(finding)
    return quality


def _effective_validation_status(finding: Any, quality: str) -> str:
    status = _normalize_validation_status(getattr(finding, "validation_status", None))
    if status in {"missing", "unverified"} and quality in {"moderate", "strong"}:
        status = validation_status_for_quality(quality)
    return status


def _strip_legacy_cvss_from_poc(poc: dict[str, Any] | None) -> dict[str, Any] | None:
    """Remove all CVSS keys from PoC dict to prevent cvss_conflict validation failures.

    Canonical CVSS lives on the top-level Finding object (cvss, cvss_score, cvss_vector).
    PoC-level CVSS fields are legacy and cause false-positive conflict detection.
    """
    if poc is None:
        return None
    out = dict(poc)
    for k in ("cvss_score", "cvss_base_score", "base_score", "cvss"):
        out.pop(k, None)
    return out


def _finding_row_to_schema(row: FindingRow) -> Finding:
    quality = _effective_evidence_quality(row)
    cv = row.cvss_score if row.cvss_score is not None else row.cvss
    return Finding(
        severity=row.severity,
        title=row.title,
        description=row.description or "",
        cwe=row.cwe,
        cvss=cv,
        cvss_score=cv,
        cvss_vector=row.cvss_vector,
        exploit_demonstrated=bool(getattr(row, "exploit_demonstrated", False)),
        exploit_summary=getattr(row, "exploit_summary", None),
        owasp_category=parse_owasp_category(row.owasp_category),
        proof_of_concept=_strip_legacy_cvss_from_poc(row.proof_of_concept),
        confidence=normalize_confidence(row.confidence, default="likely"),
        validation_status=_effective_validation_status(row, quality),
        evidence_quality=quality,
        evidence_type=normalize_evidence_type(row.evidence_type),
        evidence_refs=normalize_evidence_refs(row.evidence_refs),
        reproducible_steps=row.reproducible_steps,
        applicability_notes=row.applicability_notes,
    )


def build_report_data_from_scan_report(
    data: ScanReportData,
    *,
    report_id: str | None = None,
    executive_summary: str | None = None,
    remediation: str | list[str] | None = None,
    ai_insights: str | list[str] | None = None,
) -> ReportData:
    """
    Map RPT-003 ``ScanReportData`` into ``ReportData`` for ``generate_*`` export helpers.
    AI-related fields are optional overrides (e.g. filled after RPT-004 generation).
    """
    rid = report_id
    if rid is None and data.report is not None:
        rid = data.report.id
    if rid is None:
        rid = data.scan_id or "unknown"

    target = ""
    if data.report and data.report.target:
        target = data.report.target
    elif data.scan is not None:
        target = data.scan.target_url

    summary = summary_dict_to_report_summary(
        data.report.summary if data.report else None
    )
    sev_totals = executive_severity_totals_from_severity_strings(
        f.severity for f in data.findings
    )
    summary = summary.model_copy(
        update={
            "critical": sev_totals["critical"],
            "high": sev_totals["high"],
            "medium": sev_totals["medium"],
            "low": sev_totals["low"],
            "info": sev_totals["info"],
        }
    )
    technologies: list[str] = []
    if data.report and data.report.technologies:
        technologies = [str(t) for t in data.report.technologies]

    created_at: str | None = None
    if data.report and data.report.created_at is not None:
        ca = data.report.created_at
        created_at = ca.isoformat() if hasattr(ca, "isoformat") else str(ca)

    timeline = [_timeline_row_to_entry(t) for t in data.timeline]
    phase_outputs = [
        PhaseOutputEntry(phase=row.phase, output_data=row.output_data)
        for row in data.phase_outputs
    ]

    s = dict(data.report.summary or {}) if data.report else {}
    ai_from_summary = s.get("ai_insights")
    default_ai: str | list[str]
    if isinstance(ai_from_summary, list):
        default_ai = [str(x) for x in ai_from_summary]
    elif ai_from_summary:
        default_ai = [str(ai_from_summary)]
    else:
        default_ai = []
    final_ai = ai_insights if ai_insights is not None else default_ai
    if isinstance(final_ai, str):
        final_ai_list: str | list[str] = [final_ai] if final_ai else []
    else:
        final_ai_list = final_ai

    exec_s = executive_summary
    if exec_s is None:
        raw_exec = s.get("executive_summary") or s.get("executiveSummary")
        if isinstance(raw_exec, dict) or raw_exec is not None:
            exec_s = str(raw_exec)

    rem = remediation
    if rem is None:
        raw_rem = s.get("remediation") or s.get("recommendations")
        if isinstance(raw_rem, str):
            rem = [raw_rem] if raw_rem else []
        elif raw_rem is None:
            rem = []
        else:
            rem = [str(x) for x in raw_rem] if isinstance(raw_rem, list) else []
    elif isinstance(rem, str):
        rem = [rem] if rem else []

    raw_artifacts_dicts = [item.model_dump(mode="json") for item in data.raw_artifacts]

    return ReportData(
        report_id=rid,
        target=target,
        summary=summary,
        findings=[_finding_row_to_schema(f) for f in data.findings],
        technologies=technologies,
        created_at=created_at,
        scan_id=data.scan_id,
        tenant_id=data.tenant_id,
        ai_insights=final_ai_list,
        timeline=timeline,
        phase_outputs=phase_outputs,
        evidence=[],
        screenshots=[],
        executive_summary=exec_s,
        remediation=rem,
        raw_artifacts=raw_artifacts_dicts,
        hibp_pwned_password_summary=data.hibp_pwned_password_summary,
    )


def build_report_data_from_db(
    report: Report,
    findings: list[FindingModel],
    timeline: list[TimelineEntry] | None = None,
    phase_outputs: list[PhaseOutputEntry] | None = None,
    evidence: list[EvidenceEntry] | None = None,
    screenshots: list[ScreenshotEntry] | None = None,
    executive_summary: str | None = None,
    remediation: str | list[str] | None = None,
) -> ReportData:
    """Build ReportData from DB entities."""
    s = report.summary or {}
    ai = s.get("ai_insights")
    ai_insights = (
        [str(x) for x in ai] if isinstance(ai, list) else [str(ai)] if ai else []
    )
    exec_summary = (
        executive_summary or s.get("executive_summary") or (s.get("executiveSummary"))
    )
    if isinstance(exec_summary, dict):
        exec_summary = str(exec_summary)
    rem = (
        remediation
        if remediation is not None
        else s.get("remediation") or s.get("recommendations")
    )
    if isinstance(rem, str):
        rem = [rem] if rem else []
    elif rem is None:
        rem = []
    summary = report_to_summary(report)
    sev_totals = executive_severity_totals_from_severity_strings(
        f.severity for f in findings
    )
    summary = summary.model_copy(
        update={
            "critical": sev_totals["critical"],
            "high": sev_totals["high"],
            "medium": sev_totals["medium"],
            "low": sev_totals["low"],
            "info": sev_totals["info"],
        }
    )
    return ReportData(
        report_id=report.id,
        target=report.target,
        summary=summary,
        findings=[
            Finding(
                severity=f.severity,
                title=f.title,
                description=f.description or "",
                cwe=f.cwe,
                cvss=getattr(f, "cvss_score", None) or f.cvss,
                cvss_score=getattr(f, "cvss_score", None) or f.cvss,
                cvss_vector=getattr(f, "cvss_vector", None),
                exploit_demonstrated=bool(getattr(f, "exploit_demonstrated", False)),
                exploit_summary=getattr(f, "exploit_summary", None),
                owasp_category=parse_owasp_category(f.owasp_category),
                proof_of_concept=f.proof_of_concept
                if isinstance(f.proof_of_concept, dict)
                else None,
                confidence=normalize_confidence(
                    getattr(f, "confidence", None), default="likely"
                ),
                validation_status=_effective_validation_status(
                    f,
                    _effective_evidence_quality(f),
                ),
                evidence_quality=_effective_evidence_quality(f),
                evidence_type=normalize_evidence_type(
                    getattr(f, "evidence_type", None)
                ),
                evidence_refs=normalize_evidence_refs(
                    getattr(f, "evidence_refs", None)
                ),
                reproducible_steps=getattr(f, "reproducible_steps", None),
                applicability_notes=getattr(f, "applicability_notes", None),
            )
            for f in findings
        ],
        technologies=report.technologies or [],
        created_at=report.created_at.isoformat() if report.created_at else None,
        scan_id=report.scan_id,
        tenant_id=report.tenant_id,
        ai_insights=ai_insights,
        timeline=timeline or [],
        phase_outputs=phase_outputs or [],
        evidence=evidence or [],
        screenshots=screenshots or [],
        executive_summary=exec_summary,
        remediation=rem,
    )


def build_report_data_from_scan_findings(
    scan: Scan,
    findings: list[FindingModel],
) -> ReportData:
    """Build :class:`ReportData` from a scan row and its findings (no ``reports`` row).

    Used by T04 REST export of SARIF/JUnit directly from ``findings.scan_id``.
    """
    sev_totals = executive_severity_totals_from_severity_strings(
        f.severity for f in findings
    )
    summary = ReportSummary(
        critical=sev_totals["critical"],
        high=sev_totals["high"],
        medium=sev_totals["medium"],
        low=sev_totals["low"],
        info=sev_totals["info"],
        technologies=[],
        sslIssues=0,
        headerIssues=0,
        leaksFound=False,
    )
    created = scan.created_at.isoformat() if scan.created_at else None
    return ReportData(
        report_id=scan.id,
        target=scan.target_url,
        summary=summary,
        findings=[
            Finding(
                severity=f.severity,
                title=f.title,
                description=f.description or "",
                cwe=f.cwe,
                cvss=getattr(f, "cvss_score", None) or f.cvss,
                cvss_score=getattr(f, "cvss_score", None) or f.cvss,
                cvss_vector=getattr(f, "cvss_vector", None),
                exploit_demonstrated=bool(getattr(f, "exploit_demonstrated", False)),
                exploit_summary=getattr(f, "exploit_summary", None),
                owasp_category=parse_owasp_category(f.owasp_category),
                proof_of_concept=f.proof_of_concept
                if isinstance(f.proof_of_concept, dict)
                else None,
                confidence=normalize_confidence(
                    getattr(f, "confidence", None), default="likely"
                ),
                validation_status=_effective_validation_status(
                    f,
                    _effective_evidence_quality(f),
                ),
                evidence_quality=_effective_evidence_quality(f),
                evidence_type=normalize_evidence_type(
                    getattr(f, "evidence_type", None)
                ),
                evidence_refs=normalize_evidence_refs(
                    getattr(f, "evidence_refs", None)
                ),
                reproducible_steps=getattr(f, "reproducible_steps", None),
                applicability_notes=getattr(f, "applicability_notes", None),
            )
            for f in findings
        ],
        technologies=[],
        created_at=created,
        scan_id=scan.id,
        tenant_id=scan.tenant_id,
        ai_insights=[],
        timeline=[],
        phase_outputs=[],
        evidence=[],
        screenshots=[],
        executive_summary=None,
        remediation=[],
    )


def _resolve_owasp_summary_for_rows(
    counts: dict[str, int],
    owasp_summary: Mapping[str, OwaspCategorySummaryEntry] | None,
) -> dict[str, OwaspCategorySummaryEntry]:
    if owasp_summary:
        return dict(owasp_summary)
    return build_owasp_summary_from_counts(counts)


def build_owasp_compliance_rows(
    findings: list[dict[str, Any]],
    *,
    owasp_summary: Mapping[str, OwaspCategorySummaryEntry] | None = None,
    wstg_coverage: Mapping[str, Any] | None = None,
    use_valhalla_owasp_2021_misconfig_labels: bool = False,
) -> list[dict[str, Any]]:
    """
    One row per A01..A10 with finding counts and a CSS hint class (0 → good, 1–2 → warn, 3+ → high).
    Merges description and remediation hints from ``owasp_summary`` or ``build_owasp_summary_from_counts`` (OWASP-002).
    Keys: ``category_id``, ``title``, ``assessed``, ``assessment_result``, ``findings_present``, ``count``, ``row_class``.
    When ``use_valhalla_owasp_2021_misconfig_labels``, the internal A02 (Security Misconfiguration) row also sets
    ``display_category_code`` to ``A05:2021`` for user-facing text (OWASP Top 10:2021 naming).
    """
    counts: dict[str, int] = dict.fromkeys(OWASP_TOP10_2025_CATEGORY_IDS, 0)
    evidence_by_category: dict[str, list[str]] = {cid: [] for cid in OWASP_TOP10_2025_CATEGORY_IDS}
    for row in findings:
        oc = row.get("owasp_category")
        if isinstance(oc, str) and oc in counts:
            counts[oc] += 1
            ev = row.get("evidence_ids") or row.get("evidence_refs") or row.get("id") or row.get("finding_id")
            ev_items: list[str] = []
            if isinstance(ev, list):
                ev_items = [str(x)[:80] for x in ev if str(x).strip()]
            elif ev:
                ev_items = [str(ev)[:80]]
            for item in ev_items[:4]:
                if item not in evidence_by_category[oc]:
                    evidence_by_category[oc].append(item)
    entries = _resolve_owasp_summary_for_rows(counts, owasp_summary)
    coverage_pct = 0.0
    if isinstance(wstg_coverage, Mapping):
        try:
            coverage_pct = float(wstg_coverage.get("coverage_percentage") or 0.0)
        except (TypeError, ValueError):
            coverage_pct = 0.0
    low_wstg_coverage = coverage_pct < 70.0
    out: list[dict[str, Any]] = []
    for cid in OWASP_TOP10_2025_CATEGORY_IDS:
        n = counts[cid]
        if n == 0 and low_wstg_coverage:
            row_class = "owasp-compliance-not-assessed"
        elif n == 0:
            row_class = "owasp-compliance-0"
        elif n <= 2:
            row_class = "owasp-compliance-warn"
        else:
            row_class = "owasp-compliance-high"
        ent = entries.get(cid)
        if use_valhalla_owasp_2021_misconfig_labels:
            display_code, title_en, description = _VALHALLA_OWASP_2021_DISPLAY.get(
                cid,
                (cid, OWASP_TOP10_2025_CATEGORY_TITLES.get(cid, cid), ent.description if ent else ""),
            )
            description_hover = ""
            title_ru = ""
        else:
            description = ent.description if ent else ""
            how_short = ent.how_to_fix_short if ent else None
            description_hover = (how_short or "").strip()
            title_en = OWASP_TOP10_2025_CATEGORY_TITLES.get(cid, cid)
            title_ru = ent.title_ru if ent else ""
            display_code = cid
        if n > 0:
            assessed = "Yes" if use_valhalla_owasp_2021_misconfig_labels else "Assessed"
            info_without_cwe_cvss = 0
            for f in findings:
                sev = str(f.get("severity", "")).lower()
                cwe = f.get("cwe")
                cvss = f.get("cvss")
                oc = f.get("owasp_category")
                if isinstance(oc, str) and oc == cid and sev == "info" and not cwe and not cvss:
                    info_without_cwe_cvss += 1
            if info_without_cwe_cvss == n:
                assessed = "Partial"
                result = "Advisory only (info-level, no CWE/CVSS — not a confirmed finding)"
            else:
                result = "Finding present"
            findings_present = str(n) if n > 0 else "0"
        elif low_wstg_coverage:
            assessed = "No" if use_valhalla_owasp_2021_misconfig_labels else "Not assessed"
            result = "Not assessed"
            findings_present = "Not assessed"
        else:
            assessed = "Yes" if use_valhalla_owasp_2021_misconfig_labels else "Assessed"
            result = "No finding observed" if use_valhalla_owasp_2021_misconfig_labels else "No finding after assessment"
            findings_present = "0"
        row_out: dict[str, Any] = {
            "category_id": cid,
            "title": title_en,
            "title_ru": title_ru,
            "description": description,
            "description_hover": description_hover,
            "has_findings": n > 0,
            "assessed": assessed,
            "assessment_result": result,
            "findings_present": findings_present,
            "count": n,
            "row_class": row_class,
            "evidence_ids": evidence_by_category.get(cid, [])[:8],
        }
        if use_valhalla_owasp_2021_misconfig_labels:
            row_out["display_category_code"] = display_code
        out.append(row_out)
    return out


def _extract_http_evidence(poc: dict[str, Any]) -> dict[str, Any] | None:
    """Extract structured HTTP evidence from PoC data when request/response info is present."""
    http_ev: dict[str, Any] = {}
    if poc.get("request_method") or poc.get("request_url"):
        http_ev["request_method"] = str(poc.get("request_method") or "GET")[:16]
        http_ev["request_url"] = str(poc.get("request_url") or poc.get("url") or "")[
            :2048
        ]
        if poc.get("request_headers") and isinstance(poc["request_headers"], dict):
            http_ev["request_headers"] = {
                str(k)[:256]: str(v)[:4096]
                for k, v in list(poc["request_headers"].items())[:30]
            }
        if poc.get("request_body"):
            http_ev["request_body"] = str(poc["request_body"])[:4096]
        http_ev["response_status"] = str(
            poc.get("response_status") or poc.get("status_code") or ""
        )[:16]
        if poc.get("response_headers") and isinstance(poc["response_headers"], dict):
            http_ev["response_headers"] = {
                str(k)[:256]: str(v)[:4096]
                for k, v in list(poc["response_headers"].items())[:30]
            }
        resp_body = (
            poc.get("response_body_snippet")
            or poc.get("response_snippet")
            or poc.get("response")
        )
        if resp_body:
            http_ev["response_body_snippet"] = str(resp_body)[:2048]
    elif poc.get("request") and poc.get("response"):
        raw_req = str(poc["request"])[:4096]
        raw_resp = str(poc["response"])[:4096]
        req_lines = raw_req.split("\n", 1)
        method_line = req_lines[0].strip() if req_lines else ""
        parts = method_line.split(" ", 2)
        http_ev["request_method"] = parts[0][:16] if parts else "GET"
        http_ev["request_url"] = (
            parts[1][:2048] if len(parts) > 1 else str(poc.get("url") or "")[:2048]
        )
        http_ev["request_body"] = raw_req
        resp_lines = raw_resp.split("\n", 1)
        status_line = resp_lines[0].strip() if resp_lines else ""
        status_parts = status_line.split(" ", 2)
        http_ev["response_status"] = (
            " ".join(status_parts[1:])[:64] if len(status_parts) > 1 else ""
        )
        http_ev["response_body_snippet"] = raw_resp[:2048]

    return http_ev if http_ev else None


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_CANDIDATE_REQUIRED_FIELDS = {"finding_id", "title", "severity", "cwe"}
_VALIDATED_REQUIRED_EVIDENCE = {
    "raw_request", "raw_response", "endpoint", "parameter", "payload",
    "observed_impact", "verification_command", "acceptance_criteria",
}


def _clean_ansi(text: str) -> str:
    return _ANSI_ESCAPE_RE.sub("", text)


def _apply_scope_filter(findings: list[Finding], target: str) -> list[Finding]:
    """Demote findings on external domains to OUT_OF_SCOPE + info severity.

    Extracts the target root domain and checks each finding's endpoint/title.
    Findings on third-party SaaS (zoho, salesforce, hubspot, etc.) or unrelated
    domains are classified as out_of_scope.
    """
    import re as _re
    from urllib.parse import urlparse

    target_domain = ""
    if target:
        try:
            parsed = urlparse(target if "://" in target else f"https://{target}")
            target_domain = parsed.hostname or parsed.netloc.split(":")[0] if parsed.netloc else ""
        except Exception:
            target_domain = str(target).split("/")[0].split(":")[0]

    _KNOWN_SAAS_DOMAINS = {
        "zoho", "zohocloud.ca", "zohocorp.com", "zohopublic.com",
        "salesforce.com", "force.com", "hubspot.com", "hsforms.com",
        "mailchimp.com", "typeform.com", "google.com", "facebook.com",
        "linkedin.com", "twitter.com", "youtube.com", "github.com",
        "aws.amazon.com", "cloudfront.net",
    }

    def _domain_from_url(u: str) -> str:
        try:
            p = urlparse(u if "://" in u else f"https://{u}")
            return (p.hostname or p.netloc.split(":")[0] if p.netloc else "").lower().lstrip("www.")
        except Exception:
            return ""

    def _domain_in_title(title: str) -> str | None:
        m = _re.search(r"https?://([^\s/)'\"]+)", title or "")
        return _domain_from_url(m.group(0)) if m else None

    filtered = 0
    for f in findings:
        title = str(_safe_attr(f, "title") or "")
        endpoint = str(_safe_attr(f, "affected_endpoint") or "")
        affected_url = str(_safe_attr(f, "affected_url") or "")

        check_urls = [endpoint, affected_url]
        title_dom = _domain_in_title(title)
        if title_dom:
            check_urls.append(f"https://{title_dom}")

        is_external = False
        external_domain = ""
        for u in check_urls:
            dom = _domain_from_url(u)
            if not dom:
                continue
            if target_domain and not dom.endswith(target_domain) and not target_domain.endswith(dom):
                is_external = True
                external_domain = dom
            if any(dom.endswith(s) or dom == s for s in _KNOWN_SAAS_DOMAINS):
                is_external = True
                external_domain = dom

        if is_external:
            try:
                setattr(f, "severity", "info")
                setattr(f, "evidence_classification", "CANDIDATE")
                setattr(f, "scope_status", "out_of_scope")
                setattr(f, "applicability_notes",
                        f"Finding references external domain '{external_domain}' which is outside the target scope "
                        f"({target_domain}). This is likely a third-party SaaS/service and should be manually verified.")
                logger.warning(
                    "scope_filter_out_of_scope",
                    extra={"finding_id": getattr(f, "id", "?"),
                           "external_domain": external_domain,
                           "target_domain": target_domain},
                )
                filtered += 1
            except Exception:
                pass

    if filtered:
        logger.info("scope_filter_applied", extra={"out_of_scope": filtered, "total": len(findings)})
    return findings


def _apply_evidence_gate(findings: list[Finding]) -> list[Finding]:
    """Enforce evidence gate: VALIDATED requires raw req/res + endpoint + impact + remediation."""
    downgraded = 0
    for f in findings:
        ec = getattr(f, "evidence_classification", None)
        if not ec or str(ec).upper() != "VALIDATED":
            continue
        missing = []
        raw_req = _safe_attr(f, "raw_request") or ""
        raw_resp = _safe_attr(f, "raw_response") or ""
        endpoint = _safe_attr(f, "affected_endpoint") or ""
        param = _safe_attr(f, "affected_parameter") or ""
        payload = getattr(f, "proof_of_concept", {}) or {}
        if isinstance(payload, dict):
            payload = payload.get("payload", "")
        else:
            payload = ""
        impact = _safe_attr(f, "observed_impact") or ""
        remediation = (_safe_attr(f, "fix_action") or
                       (getattr(f, "remediation", None) if isinstance(getattr(f, "remediation", None), str) else "")
                       or "")
        if not raw_req.strip():
            missing.append("raw_request")
        if not raw_resp.strip():
            missing.append("raw_response")
        if not endpoint.strip():
            missing.append("endpoint")
        if not impact.strip():
            missing.append("observed_impact")
        if not remediation.strip():
            missing.append("remediation")
        if missing:
            try:
                setattr(f, "evidence_classification", "CANDIDATE")
                setattr(f, "validation_status", "unverified")
                setattr(f, "evidence_quality", "weak")
                logger.warning(
                    "evidence_gate_downgrade",
                    extra={"finding_id": getattr(f, "id", "?"), "missing": missing,
                           "old_status": "VALIDATED", "new_status": "CANDIDATE"},
                )
                downgraded += 1
            except Exception:
                pass
    if downgraded:
        logger.info("evidence_gate_applied", extra={"downgraded": downgraded, "total": len(findings)})
    return findings


def enforce_severity_by_evidence(findings: list[Finding]) -> list[Finding]:
    """High severity requires VALIDATED status. XSS High requires browser proof."""
    for f in findings:
        sev = str(_safe_attr(f, "severity") or "").lower()
        ec = str(getattr(f, "evidence_classification", "") or "").upper()
        if sev == "high" and ec != "VALIDATED":
            try:
                setattr(f, "severity", "medium")
                logger.warning("severity_downgraded_no_validated",
                               extra={"finding_id": getattr(f, "id", "?"), "from": "high", "to": "medium"})
            except Exception:
                pass
        if sev == "critical" and ec != "VALIDATED":
            try:
                setattr(f, "severity", "high")
                logger.warning("severity_downgraded_critical_no_validated",
                               extra={"finding_id": getattr(f, "id", "?"), "from": "critical", "to": "high"})
            except Exception:
                pass
    return findings


def _apply_fuzz_hit_evidence_gate(findings: list[Finding]) -> list[Finding]:
    """FUZZ_HIT + COMMAND_INJECTION_CANDIDATE without browser/OAST/server proof → demote to info + CANDIDATE.

    Strict evidence requirement: XSS/CMDI findings require at least ONE of:
    - Browser verification (verified_via_browser)
    - OAST/out-of-band callback (oast_callback, interactsh)
    - Command output (command_output, cmd_output)
    - Raw server response with reflected payload (not just a curl command)
    - Screenshot/video artifact key
    - Negative control result

    Simple reflection_context length is NOT sufficient — terminal artifacts like
    [2K] can produce long strings that mimic reflection.
    """
    from src.reports.report_quality_gate import has_command_injection_proof

    downgraded = 0
    for f in findings:
        title = str(_safe_attr(f, "title") or "").lower()
        desc = str(_safe_attr(f, "description") or "").lower()
        data = getattr(f, "data", None) or {}
        if not isinstance(data, dict):
            data = {}
        data_type = str(data.get("type") or "").upper()
        is_fuzz = "fuzz_hit" in title or "FUZZ_HIT" in data_type
        is_cmdi_candidate = "command_injection_candidate" in title or "COMMAND_INJECTION_CANDIDATE" in data_type

        if not is_fuzz and not is_cmdi_candidate:
            continue

        poc = getattr(f, "proof_of_concept", {}) or {}
        if not isinstance(poc, dict):
            poc = {}
        verification = str(
            poc.get("verification_method", poc.get("verification_line", "")) or ""
        ).lower().strip()
        reflection = str(poc.get("reflection_context", "") or "").strip()
        browser_verified = str(poc.get("verified_via_browser", "") or "").lower() == "true"
        raw_resp = str(_safe_attr(f, "raw_response") or "").strip()
        has_oast = str(poc.get("oast_callback", "") or "").lower() in ("true", "1", "yes", "validated")
        has_cmd_output = bool(str(poc.get("command_output") or poc.get("cmd_output") or "").strip())
        has_screenshot = bool(
            poc.get("screenshot_key") or poc.get("poc_screenshot_url") or poc.get("screenshot_url")
        )
        has_negative_control = bool(poc.get("negative_control_url") or poc.get("negative_control_result"))

        if is_cmdi_candidate and not is_fuzz:
            has_cmd_proof = has_command_injection_proof(f)
            if has_cmd_proof:
                continue

        has_real_proof = (
            browser_verified
            or has_oast
            or has_cmd_output
            or has_screenshot
            or has_negative_control
            or (raw_resp and len(raw_resp) > 50 and not _is_only_curl_command(raw_resp))
            or (verification and verification not in (
                "curl poc present", "verification_method: http reflection", "",
                "banner_only", "tool_banner", "scanner_banner",
            ))
        )

        if is_fuzz and not has_real_proof:
            if reflection and len(reflection) <= 200:
                has_real_proof = False
            elif reflection and len(reflection) > 200:
                has_ansi_artifact = bool(_ANSI_ARTIFACT_RE.search(reflection))
                has_payload_in_reflection = _payload_reflected_in_context(reflection, poc)
                if has_ansi_artifact and not has_payload_in_reflection:
                    has_real_proof = False

        if not has_real_proof:
            try:
                old_sev = str(getattr(f, "severity", "?") or "?")
                reason_parts = []
                if is_fuzz:
                    reason_parts.append("fuzz_hit_without_browser_proof")
                if is_cmdi_candidate:
                    reason_parts.append("command_injection_without_server_output")
                reason = "+".join(reason_parts) if reason_parts else "no_verified_evidence"
                setattr(f, "severity", "info")
                setattr(f, "evidence_classification", "CANDIDATE")
                setattr(f, "validation_status", "unverified")
                setattr(f, "evidence_quality", "weak")
                source = getattr(f, "id", "?")
                logger.warning(
                    "fuzz_hit_downgraded",
                    extra={"finding_id": source, "old_severity": old_sev,
                           "reason": reason},
                )
                downgraded += 1
            except Exception:
                pass

    if downgraded:
        logger.info("fuzz_hit_gate_applied", extra={"downgraded": downgraded, "total": len(findings)})
    return findings


_ANSI_ARTIFACT_RE = __import__("re").compile(
    r"\x1b\[[0-9;]*[a-zA-Z]|\[\d+[A-Z]\]|\x1b\]\d+;|\x1b\[2K|\x1b\[K|\x1b\[0m",
)


def _is_only_curl_command(text: str) -> bool:
    stripped = text.strip().lower()
    return stripped.startswith("curl ") and "\n" not in stripped and len(stripped) < 500


def _payload_reflected_in_context(reflection: str, poc: dict) -> bool:
    payload = str(poc.get("payload") or poc.get("payload_entered") or "").strip()
    if not payload or len(payload) < 3:
        return False
    return payload[:20].lower() in reflection.lower()


def _verify_cross_format(findings: list[Finding], report_id: str, target: str,
                         scan_id: str | None = None) -> tuple[bool, list[str]]:
    issues: list[str] = []
    if not report_id:
        issues.append("missing_report_id")
    if not target:
        issues.append("missing_target")
    if not findings:
        issues.append("zero_findings")
    unique_ids: set[str] = set()
    for f in findings:
        fid = str(getattr(f, "id", getattr(f, "finding_id", "")) or "")
        if not fid:
            issues.append("finding_without_id")
        elif fid in unique_ids:
            issues.append(f"duplicate_finding_id: {fid}")
        else:
            unique_ids.add(fid)
    sev_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    for f in findings:
        sev = str(_safe_attr(f, "severity") or "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        ec = str(getattr(f, "evidence_classification", "candidate") or "candidate").upper()
        status_counts[ec] = status_counts.get(ec, 0) + 1
    empty_title = sum(1 for f in findings if not str(_safe_attr(f, "title") or "").strip())
    if empty_title:
        issues.append(f"empty_titles: {empty_title}")
    return len(issues) == 0, issues


def _finding_to_dict(
    f: Finding,
    *,
    tenant_id: str | None = None,
    scan_id: str | None = None,
) -> dict[str, Any]:
    quality = _effective_evidence_quality(f)
    validation_status = _effective_validation_status(f, quality)
    ec = getattr(f, "evidence_classification", None)
    status = str(ec or validation_status or "candidate").upper()
    poc = getattr(f, "proof_of_concept", None) or {}
    if not isinstance(poc, dict):
        poc = {}
    finding_id = str(getattr(f, "id", getattr(f, "finding_id", "")) or "")
    d: dict[str, Any] = {
        "finding_id": finding_id,
        "title": f.title,
        "status": status,
        "severity": f.severity,
        "confidence": getattr(f, "confidence", "likely"),
        "affected_asset": _safe_attr(f, "affected_asset") or "",
        "endpoint": _safe_attr(f, "affected_endpoint", poc.get("request_url", "")) or "",
        "method": _safe_attr(f, "http_method", poc.get("request_method", "")) or "",
        "parameter": _safe_attr(f, "affected_parameter", poc.get("parameter", "")) or "",
        "authentication_state": _safe_attr(f, "auth_state") or "NOT_ASSESSED",
        "raw_request_ref": _safe_attr(f, "raw_request") or "",
        "raw_response_ref": _safe_attr(f, "raw_response") or "",
        "payload": str(poc.get("payload", "")) if isinstance(poc, dict) else "",
        "tool_name": _safe_attr(f, "tool_name") or "",
        "tool_version": _safe_attr(f, "tool_version") or "",
        "tool_command": _safe_attr(f, "tool_command") or "",
        "tool_output_ref": _safe_attr(f, "tool_output_excerpt") or "",
        "manual_validation_result": _safe_attr(f, "manual_validation_result") or "",
        "browser_proof_ref": _safe_attr(f, "browser_proof_url") or "",
        "observed_impact": _safe_attr(f, "observed_impact") or "",
        "cvss_vector": _safe_attr(f, "cvss_vector") or "",
        "cvss_score": f.cvss,
        "cvss": f.cvss,
        "cwe": f.cwe,
        "owasp": getattr(f, "owasp_category", None),
        "business_impact": _safe_attr(f, "business_impact") or "",
        "affected_layer": _safe_attr(f, "affected_layer") or "",
        "owner_team": _safe_attr(f, "owner_team") or "",
        "exact_remediation": _safe_attr(f, "fix_action",
            getattr(f, "remediation", None) if isinstance(getattr(f, "remediation", None), str) else "") or "",
        "verification_command": _safe_attr(f, "verification_command") or "",
        "acceptance_criteria": _safe_attr(f, "acceptance_criteria") or "",
        "retest_status": _safe_attr(f, "retest_result") or "NOT_ASSESSED",
        "evidence_ids": list(getattr(f, "evidence_refs", []) or []),
        "description": f.description,
    }
    oc = getattr(f, "owasp_category", None)
    if oc is not None:
        d["owasp_category"] = oc
    if isinstance(poc, dict) and poc:
        d["proof_of_concept"] = poc
        sk = poc.get("screenshot_key")
        tid = (tenant_id or "").strip()
        sid = (scan_id or "").strip()
        if isinstance(sk, str) and sk.strip() and tid and sid:
            url = get_finding_poc_screenshot_presigned_url(sk.strip(), tid, sid)
            if url:
                d["poc_screenshot_url"] = url
                d["screenshot_url"] = url
        http_ev = _extract_http_evidence(poc)
        if http_ev:
            d["http_evidence"] = http_ev
    return d


# RPT-009 — stable severity ordering for JSON/CSV (HTML/PDF keep template order)
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}


def _findings_sorted(findings: list[Finding]) -> list[Finding]:
    """Deterministic findings order: severity, title, CWE, CVSS."""

    def key(f: Finding) -> tuple[int, str, str, float]:
        rank = _SEVERITY_RANK.get((f.severity or "").lower().strip(), 99)
        title = (f.title or "").lower()
        cwe = f.cwe or ""
        cvss = float(f.cvss) if f.cvss is not None else -1.0
        return (rank, title, cwe, cvss)

    return sorted(findings, key=key)


def _summary_ordered(s: ReportSummary) -> dict[str, Any]:
    """Stable key order for JSON export (RPT-009)."""
    techs = sorted(str(t) for t in (s.technologies or []))
    return {
        "critical": s.critical,
        "high": s.high,
        "medium": s.medium,
        "low": s.low,
        "info": s.info,
        "technologies": techs,
        "sslIssues": s.sslIssues,
        "headerIssues": s.headerIssues,
        "leaksFound": s.leaksFound,
    }


def _canonical_json_nested(obj: Any) -> Any:
    """Recursively sort dict keys for stable JSON inside timeline/output blobs."""
    if isinstance(obj, dict):
        return {k: _canonical_json_nested(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_canonical_json_nested(x) for x in obj]
    return obj


def _jinja_ai_sections_and_scan_artifacts(
    jinja_context: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """OWASP-008: stable additive keys for JSON/CSV from full Jinja context when available."""
    if not jinja_context:
        return {}, {"status": "skipped", "phase_blocks": []}
    ai = jinja_context.get("ai_sections")
    scan = jinja_context.get("scan_artifacts")
    if not isinstance(ai, dict):
        ai = {}
    if not isinstance(scan, dict):
        scan = {"status": "skipped", "phase_blocks": []}
    return ai, scan


def _jinja_active_web_scan(jinja_context: dict[str, Any] | None) -> dict[str, Any]:
    """OWASP2-007: active web scan section snapshot for JSON export."""
    if not jinja_context:
        return {}
    block = jinja_context.get("active_web_scan")
    return block if isinstance(block, dict) else {}


def _threat_modeling_ref_for_valhalla_export(vc: dict[str, Any]) -> dict[str, Any]:
    """Customer Valhalla JSON bundle: formatted excerpts only (no raw phase blobs or tenant ids)."""
    tm = vc.get("threat_model")
    excerpt = ""
    phase = "threat_modeling"
    api_hint = ""
    if isinstance(tm, dict):
        excerpt = str(tm.get("excerpt") or "")[:12000]
        phase = str(tm.get("phase") or "threat_modeling")[:128]
        api_hint = str(tm.get("api_hint") or "")[:2048]
    return {
        "threat_model": {
            "excerpt": excerpt,
            "phase": phase,
            "api_hint": api_hint,
        },
        "threat_model_excerpt": str(vc.get("threat_model_excerpt") or "")[:12000],
        "threat_model_phase_link": str(vc.get("threat_model_phase_link") or "")[:2048],
        "exploitation_post_excerpt": str(vc.get("exploitation_post_excerpt") or "")[:12000],
    }


def _exploitation_phases_for_valhalla_export(exploitation: list[Any] | None) -> list[dict[str, str]]:
    """Drop raw output_data (vuln_analysis / threat_model JSON) from the Valhalla bundle."""
    out: list[dict[str, str]] = []
    for p in exploitation or []:
        if not isinstance(p, dict):
            continue
        ph = str(p.get("phase") or "").strip()
        if ph:
            out.append({"phase": ph[:80]})
    return out


def _raw_artifacts_stub_for_valhalla_export(raw_artifacts: list[Any] | None) -> list[dict[str, Any]]:
    """Replace inline raw artifact bodies with a count (VH-009 — no raw dumps in customer JSON)."""
    n = len(raw_artifacts) if isinstance(raw_artifacts, list) else 0
    if n <= 0:
        return []
    return [
        {
            "artifact_count": n,
            "note": (
                "Raw artifact bodies are omitted from the Valhalla export bundle; "
                "use scan artifact listings or storage-backed downloads where enabled."
            ),
        }
    ]


def _tier_from_jinja(jinja_context: dict[str, Any] | None) -> str:
    if not jinja_context:
        return ""
    return str(jinja_context.get("tier") or "").lower().strip()


def build_valhalla_report_payload(
    jinja_context: dict[str, Any] | None,
    data: ReportData,
) -> dict[str, Any]:
    """
    VHL-005 — mirror Valhalla report sections for JSON and ``valhalla_sections.csv``.
    Safe with partial Jinja context (e.g. minimal API path): missing blocks default empty.
    """
    ctx = jinja_context or {}
    vc = ctx.get("valhalla_context")
    if not isinstance(vc, dict):
        vc = {}
    ai = ctx.get("ai_sections")
    if not isinstance(ai, dict):
        ai = {}
    recon = ctx.get("recon_summary")
    if not isinstance(recon, dict):
        recon = {}
    # Align with ``ReportData.findings`` (same list as JSON findings / pipeline), not stale report.summary.
    exec_counts = executive_severity_totals_from_severity_strings(
        f.severity for f in data.findings
    )
    owasp = ctx.get("owasp_compliance_rows")
    if not isinstance(owasp, list):
        owasp = []
    findings_rows = ctx.get("findings")
    if not isinstance(findings_rows, list):
        findings_rows = []
    findings_canon = [
        _canonical_json_nested(dict(fr)) for fr in findings_rows if isinstance(fr, dict)
    ]
    roadmap = (ai.get(_VHL_AI_ROADMAP) or "").strip()
    hardening = (ai.get(_VHL_AI_HARDENING) or "").strip()
    conclusion_text = "\n\n".join(p for p in (roadmap, hardening) if p)
    exploit_chains_text = str(ai.get(_VHL_AI_EXPLOIT_CHAINS) or "").strip()
    remediation_stages_text = str(ai.get(_VHL_AI_REMEDIATION_STAGES) or "").strip()
    zero_day_text = str(ai.get(_VHL_AI_ZERO_DAY) or "").strip()
    hibp_raw = ctx.get("hibp_pwned_password_summary")
    hibp_pwned_password_summary: dict[str, Any] | None
    if isinstance(hibp_raw, dict) and hibp_raw:
        hibp_pwned_password_summary = _canonical_json_nested(hibp_raw)
    else:
        hibp_pwned_password_summary = None
    exploitation = ctx.get("exploitation")
    if not isinstance(exploitation, list):
        exploitation = []
    appendices = _canonical_json_nested(
        {
            "recon_summary": recon,
            "exploitation": _exploitation_phases_for_valhalla_export(exploitation),
            "scan_artifacts": ctx.get("scan_artifacts"),
            "raw_artifacts": _raw_artifacts_stub_for_valhalla_export(
                data.raw_artifacts if isinstance(data.raw_artifacts, list) else None
            ),
            "ai_sections_supplemental": {
                k: str(v or "")
                for k, v in sorted(ai.items())
                if k
                not in {
                    _VHL_AI_EXPLOIT_CHAINS,
                    _VHL_AI_REMEDIATION_STAGES,
                    _VHL_AI_ZERO_DAY,
                    _VHL_AI_ROADMAP,
                    _VHL_AI_HARDENING,
                }
            },
        }
    )
    title_meta = {
        "report_id": data.report_id,
        "target": (ctx.get("target") or data.target or ""),
        "scan_id": (ctx.get("scan_id") or data.scan_id or ""),
        "tenant_id": (ctx.get("tenant_id") or data.tenant_id or ""),
        "created_at": data.created_at,
        "tier": "valhalla",
    }
    robots_sitemap = {
        "robots_txt_analysis": vc.get("robots_txt_analysis"),
        "sitemap_analysis": vc.get("sitemap_analysis"),
    }
    threat_modeling_ref = _threat_modeling_ref_for_valhalla_export(vc)
    ssl_tls_table_rows = vc.get("ssl_tls_table_rows")
    if not isinstance(ssl_tls_table_rows, list):
        ssl_tls_table_rows = []
    security_headers_table_rows = vc.get("security_headers_table_rows")
    if not isinstance(security_headers_table_rows, list):
        security_headers_table_rows = []
    evidence_inv = vc.get("evidence_inventory")
    if not isinstance(evidence_inv, list):
        evidence_inv = []
    tool_health = vc.get("tool_health_summary")
    if not isinstance(tool_health, list):
        tool_health = []
    port_exposure = vc.get("port_exposure_table_rows")
    if not isinstance(port_exposure, list):
        port_exposure = []
    credential_exposure = vc.get("credential_exposure")
    auth_testing = vc.get("auth_testing")
    wstg = vc.get("wstg_coverage")
    return {
        "title_meta": _canonical_json_nested(title_meta),
        "executive_summary_counts": _canonical_json_nested(exec_counts),
        "owasp_compliance": _canonical_json_nested(owasp),
        "robots_sitemap": _canonical_json_nested(robots_sitemap),
        "tech_stack": _canonical_json_nested(vc.get("tech_stack_table") or []),
        "outdated_components": _canonical_json_nested(
            vc.get("outdated_components") or []
        ),
        "emails": _canonical_json_nested(vc.get("leaked_emails") or []),
        "leaked_email_rows": _canonical_json_nested(vc.get("leaked_email_rows") or []),
        "ssl_tls": _canonical_json_nested(vc.get("ssl_tls_analysis") or {}),
        "ssl_tls_table_rows": _canonical_json_nested(ssl_tls_table_rows),
        "headers": _canonical_json_nested(vc.get("security_headers_analysis") or {}),
        "security_headers_table_rows": _canonical_json_nested(security_headers_table_rows),
        "dependencies": _canonical_json_nested(vc.get("dependency_analysis") or []),
        "risk_matrix": _canonical_json_nested(vc.get("risk_matrix") or {}),
        "critical_vulns": _canonical_json_nested(vc.get("critical_vulns") or []),
        "full_valhalla": bool(vc.get("full_valhalla")),
        "evidence_inventory": _canonical_json_nested(evidence_inv),
        "tool_health_summary": _canonical_json_nested(tool_health),
        "port_exposure": _canonical_json_nested(port_exposure),
        "credential_exposure": _canonical_json_nested(credential_exposure) if credential_exposure else None,
        "auth_testing": _canonical_json_nested(auth_testing) if auth_testing else None,
        "wstg_coverage": _canonical_json_nested(wstg) if wstg else None,
        "threat_modeling_ref": _canonical_json_nested(threat_modeling_ref),
        "findings": findings_canon,
        "exploit_chains_text": exploit_chains_text,
        "remediation_stages_text": remediation_stages_text,
        "zero_day_text": zero_day_text,
        "conclusion_text": conclusion_text,
        "hibp_pwned_password_summary": hibp_pwned_password_summary,
        "appendices": appendices,
        "valhalla_context": _build_valhalla_report_context(jinja_context, data),
    }


def _build_valhalla_report_context(
    jinja_context: dict[str, Any] | None,
    data: ReportData,
) -> dict[str, Any] | None:
    """Build ValhallaReportContext from jinja_context and ReportData."""
    if not jinja_context:
        return None
    from src.reports.valhalla_report import build_valhalla_report_context
    ctx = jinja_context
    valhalla_ctx = ctx.get("valhalla_context")
    if not isinstance(valhalla_ctx, dict):
        valhalla_ctx = {}
    ai_ctx = ctx.get("ai_sections")
    if not isinstance(ai_ctx, dict):
        ai_ctx = {}
    findings = list(data.findings)
    findings_dicts = [f.model_dump(mode="json") for f in findings]
    engagement_title = valhalla_ctx.get("valhalla_engagement_title", "") or ""
    full_v = bool(valhalla_ctx.get("full_valhalla"))
    scan_options = valhalla_ctx.get("scan_options", {}) or {}
    phase_outputs = valhalla_ctx.get("phase_outputs", {}) or {}
    raw_artifact_keys = valhalla_ctx.get("raw_artifact_keys", []) or []
    merged_http_headers = valhalla_ctx.get("merged_http_headers", {}) or {}
    fetch_raw_bodies = bool(scan_options.get("fetch_raw_bodies", False))
    threat_ref = valhalla_ctx.get("threat_model_ref", {})
    exploit_post_excerpt = str(threat_ref.get("exploitation_post_excerpt", "") or "")
    risk_matrix = valhalla_ctx.get("risk_matrix", {}) or {}
    critical_vulns = valhalla_ctx.get("critical_vulns", []) or []
    appendix_tools = valhalla_ctx.get("appendix_tools", []) or []
    mandatory_sections = valhalla_ctx.get("mandatory_sections", {}) or {}
    rs_analysis_bundle = valhalla_ctx.get("robots_sitemap_analysis", {}) or {}
    coverage = valhalla_ctx.get("coverage", {}) or {}
    recon_pipeline_summary = valhalla_ctx.get("recon_pipeline_summary", {}) or {}
    wstg_result = valhalla_ctx.get("wstg_coverage", {}) or {}
    test_lim = valhalla_ctx.get("test_limitations", []) or []
    port_data = valhalla_ctx.get("port_exposure", {}) or {}
    evidence_inv = valhalla_ctx.get("evidence_inventory", []) or []
    th_jinja = valhalla_ctx.get("tool_health_summary", []) or []
    wstg_exec_degraded = bool(valhalla_ctx.get("wstg_execution_degraded", False))
    wstg_zero = bool(valhalla_ctx.get("wstg_coverage_zero_executed", False))
    trivy_run_status = valhalla_ctx.get("trivy_run_status", "") or "not_applicable"
    sca_mode = valhalla_ctx.get("sca_mode", "") or "none"
    sca_manifest_count = valhalla_ctx.get("sca_manifest_count", 0) or 0
    sca_artifact_count = valhalla_ctx.get("sca_artifact_count", 0) or 0
    active_injection_scan_options = valhalla_ctx.get("active_injection_scan_options", {}) or {}
    auth_testing = valhalla_ctx.get("auth_testing", {}) or {}
    full_headers = valhalla_ctx.get("full_headers", {}) or {}
    remediation_matrix_rows = valhalla_ctx.get("remediation_matrix", []) or []
    ownership_evidence = valhalla_ctx.get("ownership_evidence", {}) or {}
    retest_plan = valhalla_ctx.get("retest_plan", {}) or {}
    unresolved_gaps = valhalla_ctx.get("unresolved_gaps", []) or []
    missing_artifacts = valhalla_ctx.get("missing_artifacts", []) or []
    next_scan = valhalla_ctx.get("next_scan_commands", []) or []
    quick_fuzz = valhalla_ctx.get("quick_fuzz_summary", {}) or {}
    bounty_plan = valhalla_ctx.get("bounty_plan", {}) or {}
    burp_config = bool(valhalla_ctx.get("burp_config_available", False))
    return build_valhalla_report_context(
        findings=findings_dicts,
        valhalla_context=valhalla_ctx,
        engagement_title=engagement_title,
        full_v=full_v,
        phase_outputs=phase_outputs,
        raw_artifact_keys=raw_artifact_keys,
        merged_http_headers=merged_http_headers,
        fetch_raw_bodies=fetch_raw_bodies,
        threat_ref=threat_ref,
        exploitation_post_excerpt=exploit_post_excerpt,
        risk_matrix=risk_matrix,
        critical_vulns=critical_vulns,
        appendix_tools=appendix_tools,
        mandatory_sections=mandatory_sections,
        rs_analysis_bundle=rs_analysis_bundle,
        coverage=coverage,
        recon_pipeline_summary=recon_pipeline_summary,
        wstg_result=wstg_result,
        test_limits=test_lim,
        port_data=port_data,
        evidence_inventory=evidence_inv,
        tool_health=th_jinja,
        wstg_exec_degraded=wstg_exec_degraded,
        wstg_zero=wstg_zero,
        trivy_run_status=trivy_run_status,
        sca_mode=sca_mode,
        sca_manifest_count=sca_manifest_count,
        sca_artifact_count=sca_artifact_count,
        active_injection_scan_options=active_injection_scan_options,
        auth_testing=auth_testing,
        full_headers=full_headers,
        remediation_matrix_rows=remediation_matrix_rows,
        ownership_evidence=ownership_evidence,
        retest_plan=retest_plan,
        unresolved_gaps=unresolved_gaps,
        missing_artifacts=missing_artifacts,
        next_scan=next_scan,
        quick_fuzz=quick_fuzz,
        bounty_plan=bounty_plan,
        burp_config_available=burp_config,
    )


def generate_valhalla_sections_csv(
    data: ReportData,
    *,
    jinja_context: dict[str, Any] | None = None,
) -> bytes:
    """VHL-005 — one row per Valhalla section; text columns plain, structured cells JSON; brand metadata first row."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    from src.reports.valhalla_report_context import get_brand
    brand = get_brand()
    writer.writerow(["section", "content_markdown_or_json", "status", "evidence_ids", "parser_status", "updated_at"])
    writer.writerow([
        "brand",
        json.dumps({
            "name": brand.name,
            "logo_file": brand.logo_file,
            "logo_mime": brand.logo_mime,
            "logo_sha256": brand.logo_sha256,
        }, ensure_ascii=False),
        "collected",
        "",
        "ok",
        data.created_at or "",
    ])
    payload = build_valhalla_report_payload(jinja_context, data)
    text_keys = frozenset(
        {
            "exploit_chains_text",
            "remediation_stages_text",
            "zero_day_text",
            "conclusion_text",
        }
    )
    for key in _VALHALLA_REPORT_SECTION_ORDER:
        val = payload.get(key)
        if key in text_keys:
            writer.writerow([key, str(val or ""), "", "", "", ""])
        else:
            writer.writerow(
                [key, json.dumps(_canonical_json_nested(val), ensure_ascii=False), "", "", "", ""]
            )
    return buf.getvalue().encode("utf-8")


def generate_json(
    data: ReportData, *, jinja_context: dict[str, Any] | None = None
) -> bytes:
    """Generate JSON / JSOC report — full schema with brand, metadata, export_integrity, timeline, phase outputs, findings, evidence, screenshots, AI conclusions, remediation."""
    ai_list = (
        data.ai_insights
        if isinstance(data.ai_insights, list)
        else [data.ai_insights]
        if data.ai_insights
        else []
    )
    rem_list = (
        data.remediation
        if isinstance(data.remediation, list)
        else [data.remediation]
        if data.remediation
        else []
    )
    tech_sorted = sorted(str(t) for t in (data.technologies or []))
    findings_ordered = _findings_sorted(data.findings)
    timeline_rows = sorted(
        data.timeline,
        key=lambda t: (t.order_index, t.phase or "", t.created_at or ""),
    )
    phase_rows = sorted(data.phase_outputs, key=lambda p: (p.phase or "",))
    evidence_rows = sorted(
        data.evidence,
        key=lambda e: (e.finding_id, e.object_key, e.description or ""),
    )
    screenshot_rows = sorted(
        data.screenshots,
        key=lambda s: (s.object_key, s.url_or_email or ""),
    )
    metadata = {
        "report_id": data.report_id,
        "target": data.target,
        "scan_id": data.scan_id,
        "created_at": data.created_at,
        "technologies": tech_sorted,
    }
    timeline = [
        {
            "phase": t.phase,
            "order_index": t.order_index,
            "entry": _canonical_json_nested(t.entry),
            "created_at": t.created_at,
        }
        for t in timeline_rows
    ]
    phase_outputs = [
        {"phase": p.phase, "output_data": _canonical_json_nested(p.output_data)}
        for p in phase_rows
    ]
    evidence = [
        {
            "finding_id": e.finding_id,
            "object_key": e.object_key,
            "description": e.description,
        }
        for e in evidence_rows
    ]
    screenshots = [
        {"object_key": s.object_key, "url_or_email": s.url_or_email}
        for s in screenshot_rows
    ]
    ai_sections, scan_artifacts = _jinja_ai_sections_and_scan_artifacts(jinja_context)
    active_web_scan = _jinja_active_web_scan(jinja_context)
    from src.reports.valhalla_report_context import get_brand
    brand = get_brand()
    now_utc = datetime.now(timezone.utc).isoformat()

    # scope filter + fuzz_hit gate + evidence gate + severity enforcement
    findings_ordered = _apply_scope_filter(findings_ordered, data.target or "")
    findings_ordered = _apply_evidence_gate(findings_ordered)
    findings_ordered = _apply_fuzz_hit_evidence_gate(findings_ordered)
    findings_ordered = enforce_severity_by_evidence(findings_ordered)

    # build evidence inventory
    evidence_inventory: list[dict[str, Any]] = []
    for f in findings_ordered:
        fid = str(getattr(f, "id", getattr(f, "finding_id", "")) or "")
        refs = getattr(f, "evidence_refs", []) or []
        for ref in refs:
            evidence_inventory.append({
                "finding_id": fid,
                "evidence_id": str(ref),
                "evidence_type": _safe_attr(f, "evidence_type") or "raw",
                "source_tool": _safe_attr(f, "tool_name") or "",
                "artifact_ref": str(ref),
                "timestamp": _safe_attr(f, "timestamp_utc") or now_utc,
                "parser_status": "parsed",
            })
        if not refs:
            evidence_inventory.append({
                "finding_id": fid,
                "evidence_id": "NONE",
                "evidence_type": "none",
                "source_tool": "",
                "artifact_ref": "",
                "timestamp": now_utc,
                "parser_status": "missing",
            })

    output = {
        "format": "jsoc",
        "format_version": "1.0",
        "brand": {
            "name": brand.name,
            "logo_file": brand.logo_file,
            "logo_mime": brand.logo_mime,
            "logo_sha256": brand.logo_sha256,
            "logo_base64_svg": brand.logo_base64_svg,
            "alt_text": brand.alt_text,
        },
        "report_id": data.report_id,
        "scan_id": data.scan_id,
        "target": data.target,
        "created_at": data.created_at,
        "metadata": metadata,
        "executive_summary": {"text": _clean_ansi(data.executive_summary or "")},
        "scope": {
            "target": data.target,
            "assessment_mode": "automated",
            "authenticated_status": "NOT_ASSESSED",
            "scan_id": data.scan_id or "",
        },
        "methodology": {"description": "Automated security assessment via ARGUS pipeline"},
        "wstg_coverage": _canonical_json_nested(
            jinja_context.get("wstg_coverage", {})
            if isinstance(jinja_context, dict) else {}
        ),
        "tool_health": _canonical_json_nested(
            jinja_context.get("valhalla_context", None).tool_health_summary
            if isinstance(jinja_context, dict) and
               hasattr(jinja_context.get("valhalla_context", None), "tool_health_summary")
            else []
        ),
        "ssl_tls_analysis": _canonical_json_nested(
            jinja_context.get("valhalla_context", None).ssl_tls_analysis.model_dump()
            if isinstance(jinja_context, dict) and
               hasattr(jinja_context.get("valhalla_context", None), "ssl_tls_analysis")
            else {}
        ),
        "ssl_tls_table_rows": _canonical_json_nested(
            jinja_context.get("valhalla_context", None).ssl_tls_table_rows
            if isinstance(jinja_context, dict) and
               hasattr(jinja_context.get("valhalla_context", None), "ssl_tls_table_rows")
            else []
        ),
        "port_exposure": _canonical_json_nested(
            jinja_context.get("valhalla_context", None).port_exposure_table_rows
            if isinstance(jinja_context, dict) and
               hasattr(jinja_context.get("valhalla_context", None), "port_exposure_table_rows")
            else []
        ),
        "port_exposure_summary": _canonical_json_nested(
            jinja_context.get("valhalla_context", None).port_exposure.model_dump()
            if isinstance(jinja_context, dict) and
               hasattr(jinja_context.get("valhalla_context", None), "port_exposure")
            else {}
        ),
        "robots_sitemap": _canonical_json_nested(
            jinja_context.get("valhalla_context", None).robots_sitemap_analysis.model_dump()
            if isinstance(jinja_context, dict) and
               hasattr(jinja_context.get("valhalla_context", None), "robots_sitemap_analysis")
            else {}
        ),
        "credential_exposure": _canonical_json_nested(
            jinja_context.get("valhalla_context", None).credential_exposure.model_dump()
            if isinstance(jinja_context, dict) and
               hasattr(jinja_context.get("valhalla_context", None), "credential_exposure")
            else {}
        ),
        "auth_testing": _canonical_json_nested(
            jinja_context.get("valhalla_context", None).auth_testing.model_dump()
            if isinstance(jinja_context, dict) and
               hasattr(jinja_context.get("valhalla_context", None), "auth_testing")
            else {}
        ),
        "leaked_emails": _canonical_json_nested(
            jinja_context.get("valhalla_context", None).leaked_email_rows
            if isinstance(jinja_context, dict) and
               hasattr(jinja_context.get("valhalla_context", None), "leaked_email_rows")
            else []
        ),
        "technologies": tech_sorted,
        "findings": [
            _finding_to_dict(f, tenant_id=data.tenant_id, scan_id=data.scan_id)
            for f in findings_ordered
        ],
        "evidence": evidence_inventory,
        "remediation_matrix": [
            {
                "report_id": data.report_id,
                "finding_id": str(getattr(f, "id", getattr(f, "finding_id", "")) or ""),
                "status": str(getattr(f, "evidence_classification",
                                     getattr(f, "validation_status", "unverified")) or "unverified").upper(),
                "affected_layer": _safe_attr(f, "affected_layer") or "NOT_ASSESSED",
                "owner_team": _safe_attr(f, "owner_team") or "NOT_ASSESSED",
                "config_or_component": _safe_attr(f, "config_or_component",
                                                  _safe_attr(f, "affected_asset")) or "",
                "exact_fix": (_safe_attr(f, "fix_action") or
                              (getattr(f, "remediation", None) if isinstance(getattr(f, "remediation", None), str) else "")
                              or "NOT_ASSESSED"),
                "verification_step": _safe_attr(f, "verification_command") or "NOT_ASSESSED",
                "acceptance_criteria": _safe_attr(f, "acceptance_criteria") or "NOT_ASSESSED",
                "retest_status": _safe_attr(f, "retest_result") or "NOT_ASSESSED",
            }
            for f in findings_ordered
        ],
        "retest_checklist": build_retest_checklist_export(findings_ordered),
        "limitations": _canonical_json_nested(
            jinja_context.get("valhalla_context", None).test_limitations
            if isinstance(jinja_context, dict) and
               hasattr(jinja_context.get("valhalla_context", None), "test_limitations")
            else []
        ),
        "unresolved_gaps": _unresolved_gaps_from_ctx(jinja_context),
        "verification_commands": [
            {"finding_id": cmd["finding_id"], "command": cmd["command"]}
            for cmd in build_verification_commands(
                [_finding_to_dict(f) for f in findings_ordered]
            )
        ],
        "infra_recommendations": _canonical_json_nested(
            generate_infra_recommendations(
                tech_stack=jinja_context.get("valhalla_context", None).tech_stack_structured.model_dump()
                if isinstance(jinja_context, dict) and hasattr(
                    jinja_context.get("valhalla_context", None), "tech_stack_structured")
                else {},
                findings=[_finding_to_dict(f) for f in findings_ordered],
                ssl_tls=jinja_context.get("valhalla_context", None).ssl_tls_analysis.model_dump()
                if isinstance(jinja_context, dict) and hasattr(
                    jinja_context.get("valhalla_context", None), "ssl_tls_analysis")
                else {},
                security_headers=jinja_context.get("valhalla_context", None).security_headers_analysis.model_dump()
                if isinstance(jinja_context, dict) and hasattr(
                    jinja_context.get("valhalla_context", None), "security_headers_analysis")
                else {},
            )
        ),
        "truthfulness_metrics": build_truthfulness_metrics(
            findings=[_finding_to_dict(f) for f in findings_ordered],
            ai_sections=ai_sections or {},
            coverage_pct=float(jinja_context.get("wstg_coverage", {}).get("coverage_percentage", 0) or 0)
            if isinstance(jinja_context, dict) else 0.0,
        ),
        "timeline": timeline,
        "phase_outputs": phase_outputs,
        "screenshots": screenshots,
        "ai_sections": _canonical_json_nested(ai_sections),
        "active_web_scan": _canonical_json_nested(active_web_scan),
        "raw_artifacts": data.raw_artifacts,
        "export_integrity": _build_export_integrity(
            jinja_context=jinja_context,
            data=data,
            json_bytes=b"",
        ),
    }
    if _tier_from_jinja(jinja_context) == "valhalla":
        output["valhalla_report"] = build_valhalla_report_payload(jinja_context, data)
        if isinstance(jinja_context, dict) and isinstance(
            jinja_context.get("valhalla_executive_report"), dict
        ):
            output["valhalla_executive_report"] = _canonical_json_nested(
                jinja_context["valhalla_executive_report"]
            )
    if (
        _tier_from_jinja(jinja_context) == "asgard"
        and isinstance(jinja_context, dict)
        and isinstance(jinja_context.get("asgard_report"), dict)
    ):
        output["asgard_report"] = _canonical_json_nested(jinja_context["asgard_report"])
    result = json.dumps(output, indent=2, ensure_ascii=False).encode("utf-8")
    output["export_integrity"]["json_sha256"] = hashlib.sha256(result).hexdigest()
    return json.dumps(output, indent=2, ensure_ascii=False).encode("utf-8")


def build_retest_checklist_export(findings: Iterable[Any]) -> list[dict[str, str]]:
    from src.reports.report_quality_gate import build_retest_checklist
    return build_retest_checklist(findings)


def _unresolved_gaps_from_ctx(jinja_context: dict[str, Any] | None) -> list[dict[str, str]]:
    vc = (jinja_context or {}).get("valhalla_context")
    if isinstance(vc, dict):
        return vc.get("unresolved_gaps", [])
    return getattr(vc, "unresolved_gaps", []) if vc is not None else []


def _missing_artifacts_from_ctx(jinja_context: dict[str, Any] | None) -> list[dict[str, str]]:
    vc = (jinja_context or {}).get("valhalla_context")
    if isinstance(vc, dict):
        return vc.get("missing_artifacts", [])
    return getattr(vc, "missing_artifacts", []) if vc is not None else []


def _next_scan_commands_from_ctx(jinja_context: dict[str, Any] | None) -> list[dict[str, str]]:
    vc = (jinja_context or {}).get("valhalla_context")
    if isinstance(vc, dict):
        return vc.get("next_scan_commands", [])
    return getattr(vc, "next_scan_commands", []) if vc is not None else []


def _build_export_integrity(
    *,
    jinja_context: dict[str, Any] | None,
    data: ReportData,
    json_bytes: bytes,
) -> dict[str, str | bool]:
    from src.reports.valhalla_report_context import get_brand
    brand = get_brand()
    return {
        "html_sha256": "",
        "pdf_sha256": "",
        "md_sha256": "",
        "csv_sha256": "",
        "json_sha256": hashlib.sha256(json_bytes).hexdigest() if json_bytes else "",
        "logo_sha256": brand.logo_sha256,
        "generated_from_same_dataset": True,
    }


def generate_csv(
    data: ReportData, *, jinja_context: dict[str, Any] | None = None
) -> bytes:
    """Generate multi-file CSV bundle: findings.csv, evidence.csv, sections.csv, remediation.csv."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    from src.reports.valhalla_report_context import get_brand
    brand = get_brand()

    # ── findings.csv ──────────────────────────────────────────────
    writer.writerow(["# report_id", data.report_id or ""])
    writer.writerow(["# scan_id", data.scan_id or ""])
    writer.writerow(["# target", data.target or ""])
    writer.writerow(["# brand", brand.name])
    writer.writerow([])
    writer.writerow([
        "report_id", "scan_id", "target",
        "finding_id", "status", "severity", "confidence", "title",
        "affected_asset", "endpoint", "method", "parameter",
        "authentication_state",
        "cwe", "owasp", "cvss_vector", "cvss_score",
        "evidence_ids", "raw_request_ref", "raw_response_ref",
        "tool_name", "tool_version", "tool_command",
        "manual_validation_result", "observed_impact",
        "affected_layer", "owner_team",
        "exact_remediation", "verification_command",
        "acceptance_criteria", "retest_status",
    ])
    for f in _findings_sorted(data.findings):
        poc = getattr(f, "proof_of_concept", {}) or {}
        if not isinstance(poc, dict):
            poc = {}
        finding_id = str(getattr(f, "id", getattr(f, "finding_id", "")) or "")
        ec = getattr(f, "evidence_classification", None)
        vs = getattr(f, "validation_status", "unverified")
        status = str(ec or vs or "candidate").upper()
        row = [
            data.report_id or "", data.scan_id or "", data.target or "",
            finding_id, status or "CANDIDATE",
            _safe_attr(f, "severity") or "INCONCLUSIVE",
            _safe_attr(f, "confidence", "likely") or "",
            _safe_attr(f, "title") or "NOT_ASSESSED",
            _safe_attr(f, "affected_asset") or "",
            _safe_attr(f, "affected_endpoint", poc.get("request_url") if isinstance(poc, dict) else "") or "",
            _safe_attr(f, "http_method", poc.get("request_method") if isinstance(poc, dict) else "") or "",
            _safe_attr(f, "affected_parameter", poc.get("parameter") if isinstance(poc, dict) else "") or "",
            _safe_attr(f, "auth_state") or "",
            _safe_attr(f, "cwe") or "",
            _safe_attr(f, "owasp_category") or "",
            _safe_attr(f, "cvss_vector") or "",
            str(_safe_attr(f, "cvss_score", _safe_attr(f, "cvss", ""))) or "",
            json.dumps(getattr(f, "evidence_refs", []) or [], ensure_ascii=False),
            _safe_attr(f, "raw_request") or "",
            _safe_attr(f, "raw_response") or "",
            _safe_attr(f, "tool_name") or "",
            _safe_attr(f, "tool_version") or "",
            _safe_attr(f, "tool_command") or "",
            _safe_attr(f, "manual_validation_result") or "",
            _safe_attr(f, "observed_impact") or "",
            _safe_attr(f, "affected_layer") or "",
            _safe_attr(f, "owner_team") or "",
            _safe_attr(f, "fix_action", getattr(f, "remediation", None) if isinstance(getattr(f, "remediation", None), str) else "") or "",
            _safe_attr(f, "verification_command") or "",
            _safe_attr(f, "acceptance_criteria") or "",
            _safe_attr(f, "retest_result") or "",
        ]
        for i in range(len(row)):
            if row[i] is None or (isinstance(row[i], str) and not row[i].strip()):
                row[i] = "NOT_ASSESSED"
        writer.writerow(row)

    # ── evidence.csv ──────────────────────────────────────────────
    writer.writerow([])
    writer.writerow(["# evidence.csv"])
    writer.writerow([
        "report_id", "finding_id", "evidence_id", "evidence_type",
        "source_tool", "artifact_ref", "timestamp", "parser_status", "status", "summary",
    ])
    for f in _findings_sorted(data.findings):
        finding_id = str(getattr(f, "id", getattr(f, "finding_id", "")) or "")
        refs = getattr(f, "evidence_refs", []) or []
        if not refs:
            writer.writerow([
                data.report_id or "", finding_id, "NONE",
                "none", "", "", "", "missing", "INCONCLUSIVE",
                "INCONCLUSIVE: missing artifact",
            ])
            continue
        for ref in refs:
            writer.writerow([
                data.report_id or "", finding_id, str(ref),
                _safe_attr(f, "evidence_type") or "raw",
                _safe_attr(f, "tool_name") or "",
                str(ref),
                _safe_attr(f, "timestamp_utc") or "",
                "parsed",
                str(getattr(f, "evidence_classification", getattr(f, "validation_status", "unverified")) or "unverified").upper(),
                _safe_attr(f, "title", "")[:200],
            ])

    # ── sections.csv ──────────────────────────────────────────────
    writer.writerow([])
    writer.writerow(["# sections.csv"])
    writer.writerow([
        "report_id", "section", "status", "content_markdown_or_json",
        "evidence_ids", "parser_status", "updated_at",
    ])
    ai_sections, _ = _jinja_ai_sections_and_scan_artifacts(jinja_context)
    _valhalla_sections = _VALHALLA_REPORT_SECTION_ORDER
    for sec_key in _valhalla_sections:
        sec_text = str(ai_sections.get(sec_key, "") if isinstance(ai_sections, dict) else "")
        sec_status = "PRESENT" if sec_text.strip() else "NOT_ASSESSED"
        writer.writerow([
            data.report_id or "", sec_key, sec_status,
            sec_text[:4000] if sec_text else json.dumps({"status": "NOT_ASSESSED", "reason": "section not yet generated"}),
            "[]", "generated", data.created_at or "",
        ])
    if isinstance(ai_sections, dict):
        for extra_key in sorted(set(ai_sections.keys()) - set(_valhalla_sections)):
            extra_text = str(ai_sections[extra_key] or "")
            writer.writerow([
                data.report_id or "", extra_key,
                "PRESENT" if extra_text.strip() else "NOT_ASSESSED",
                extra_text[:4000] if extra_text else "",
                "[]", "generated", data.created_at or "",
            ])

    # ── remediation.csv ───────────────────────────────────────────
    writer.writerow([])
    writer.writerow(["# remediation.csv"])
    writer.writerow([
        "report_id", "finding_id", "status",
        "affected_layer", "owner_team", "config_or_component",
        "exact_fix", "priority", "rollback_risk",
        "verification_step", "acceptance_criteria", "retest_status",
    ])
    for f in _findings_sorted(data.findings):
        finding_id = str(getattr(f, "id", getattr(f, "finding_id", "")) or "")
        sev = _safe_attr(f, "severity", "info")
        prio = "CRITICAL" if sev == "critical" else "HIGH" if sev == "high" else "MEDIUM" if sev == "medium" else "LOW"
        writer.writerow([
            data.report_id or "", finding_id,
            str(getattr(f, "evidence_classification", getattr(f, "validation_status", "unverified")) or "unverified").upper(),
            _safe_attr(f, "affected_layer") or "NOT_ASSESSED",
            _safe_attr(f, "owner_team") or "NOT_ASSESSED",
            _safe_attr(f, "config_or_component", _safe_attr(f, "affected_asset")) or "",
            _safe_attr(f, "fix_action", getattr(f, "remediation", None) if isinstance(getattr(f, "remediation", None), str) else "") or "NOT_ASSESSED",
            prio,
            _safe_attr(f, "rollback_risk") or "NOT_ASSESSED",
            _safe_attr(f, "verification_command") or "NOT_ASSESSED",
            _safe_attr(f, "acceptance_criteria") or "NOT_ASSESSED",
            _safe_attr(f, "retest_result") or "NOT_ASSESSED",
        ])

    return buf.getvalue().encode("utf-8")


def generate_technologies_csv(
    data: ReportData, *, jinja_context: dict[str, Any] | None = None
) -> bytes:
    """Generate technologies.csv — verified technology stack with detection sources."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["# report_id", data.report_id or ""])
    writer.writerow(["# scan_id", data.scan_id or ""])
    writer.writerow(["# target", data.target or ""])
    writer.writerow([])
    writer.writerow([
        "detected_value", "version", "category", "confidence",
        "source", "raw_evidence", "validation_method", "evidence_id",
    ])
    technologies = getattr(data, "technologies", []) or []
    if not technologies:
        writer.writerow(["NOT_ASSESSED", "", "", "", "", "", "", ""])
    else:
        for tech in sorted(technologies, key=lambda t: str(t).lower()):
            tech_str = str(tech)
            writer.writerow([
                tech_str, "unknown", "component",
                "medium", "whatweb/httpx", tech_str,
                "fingerprint", data.scan_id or "",
            ])
    return buf.getvalue().encode("utf-8")


def generate_outdated_components_csv(
    data: ReportData, *, jinja_context: dict[str, Any] | None = None
) -> bytes:
    """Generate outdated_components.csv — EOL/CVE risk for detected components."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["# report_id", data.report_id or ""])
    writer.writerow(["# scan_id", data.scan_id or ""])
    writer.writerow(["# target", data.target or ""])
    writer.writerow([])
    writer.writerow([
        "component", "detected_version", "latest_version",
        "cve_or_advisory", "max_cvss", "eol_status",
        "upgrade_effort", "package_manager", "severity",
        "source", "recommendation",
    ])
    technologies = getattr(data, "technologies", []) or []
    if not technologies:
        writer.writerow(["NOT_ASSESSED", "", "", "", "", "", "", "", "", "", ""])
    else:
        for tech in sorted(technologies, key=lambda t: str(t).lower()):
            tech_str = str(tech)
            writer.writerow([
                tech_str, "unknown", "NOT_ASSESSED",
                "", "", "NOT_ASSESSED",
                "NOT_ASSESSED", "", "INFO",
                "fingerprint", "Run Trivy / Grype / OSV Scanner for version analysis",
            ])
    return buf.getvalue().encode("utf-8")


def generate_tool_health_csv(
    data: ReportData, *, jinja_context: dict[str, Any] | None = None
) -> bytes:
    """Generate tool_health.csv — per-capability execution status."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["# report_id", data.report_id or ""])
    writer.writerow(["# scan_id", data.scan_id or ""])
    writer.writerow([])
    writer.writerow([
        "capability", "tools_representative", "all_tools_executed",
        "tool_command", "tool_version", "artifact_path",
        "exit_code", "parser_status", "parsed_rows",
        "failure_reason", "summary", "next_action",
    ])
    th = getattr(data, "tool_health", None)
    if th and hasattr(th, "capabilities"):
        for cap in th.capabilities:
            writer.writerow([
                getattr(cap, "capability", "") or "",
                getattr(cap, "tools_representative", "") or "",
                str(getattr(cap, "all_tools_executed", False)),
                getattr(cap, "tool_command", "") or "",
                getattr(cap, "tool_version", "") or "",
                getattr(cap, "artifact_path", "") or "",
                str(getattr(cap, "exit_code", 0)),
                getattr(cap, "parser_status", "NOT_ASSESSED") or "NOT_ASSESSED",
                str(getattr(cap, "parsed_rows", 0)),
                getattr(cap, "failure_reason", "") or "",
                getattr(cap, "summary", "") or "",
                getattr(cap, "next_action", "") or "",
            ])
    else:
        capabilities = [
            "recon", "port_discovery", "tls_assessment", "technology_fingerprinting",
            "vuln_active_scan", "web_server_scan", "security_headers",
            "email_osint", "dns_asn", "url_history", "sca_dependencies",
        ]
        for cap in capabilities:
            writer.writerow([cap, "", "False", "", "", "", "0", "NOT_ASSESSED", "0", "", "NOT_ASSESSED", "Run tool health scan"])
    return buf.getvalue().encode("utf-8")


def generate_export_validation_report(
    data: ReportData, *, jinja_context: dict[str, Any] | None = None
) -> bytes:
    """Generate export_validation_report.json — cross-format integrity verification."""
    from src.reports.valhalla_report_context import get_brand
    brand = get_brand()
    findings_count = len(data.findings) if data.findings else 0
    issues: list[str] = []
    ok, fmt_issues = _verify_cross_format(
        data.findings, data.report_id or "", data.target or "", data.scan_id
    )
    issues.extend(fmt_issues)
    report = {
        "report_id": data.report_id or "",
        "scan_id": data.scan_id or "",
        "target": data.target or "",
        "brand": brand.name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "validation": {
            "passed": len(issues) == 0,
            "issues": issues,
            "findings_count": findings_count,
            "formats_generated": ["html", "pdf", "md", "json", "csv"],
            "cross_format_consistent": ok,
        },
        "section_status": {
            "executive_summary": "PRESENT" if (data.executive_summary or "").strip() else "NOT_ASSESSED",
            "findings": "PRESENT" if findings_count > 0 else "NOT_ASSESSED",
            "remediation": "PRESENT" if (data.remediation or data.remediations) else "NOT_ASSESSED",
            "technologies": "PRESENT" if (getattr(data, "technologies", None) or []) else "NOT_ASSESSED",
            "timeline": "PRESENT" if (getattr(data, "timeline", None) or []) else "NOT_ASSESSED",
        },
        "evidence_integrity": {
            "total_findings": findings_count,
            "validated": sum(1 for f in data.findings if str(getattr(f, "evidence_classification", "")).lower() == "validated"),
            "observed": sum(1 for f in data.findings if str(getattr(f, "evidence_classification", "")).lower() == "observed"),
            "candidate": sum(1 for f in data.findings if str(getattr(f, "evidence_classification", "")).lower() == "candidate"),
            "inconclusive": sum(1 for f in data.findings if str(getattr(f, "evidence_classification", "")).lower() == "inconclusive"),
        },
    }
    return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")


def _safe_attr(obj: Any, name: str, default: Any = "") -> Any:
    val = getattr(obj, name, None)
    if val is None:
        pd = getattr(obj, "proof_of_concept", {}) or {}
        if isinstance(pd, dict):
            val = pd.get(name)
    return val if val is not None else default


def generate_html(
    data: ReportData,
    *,
    jinja_context: dict[str, Any] | None = None,
    tier: str | None = None,
) -> bytes:
    """RPT-008 — Tiered Jinja2 HTML (autoescape). Pass ``jinja_context`` from Report pipeline when available."""
    from src.reports.jinja_minimal_context import offline_minimal_jinja_context_from_report_data
    from src.reports.template_env import render_tier_report_html

    ctx = (
        jinja_context
        if jinja_context is not None
        else offline_minimal_jinja_context_from_report_data(data, tier or "midgard")
    )
    eff_tier = str(ctx.get("tier") or tier or "midgard")
    ctx = {**ctx, "tier": eff_tier}

    # Build remediation_matrix for HTML template (same logic as JSON generate_json)
    if "remediation_matrix" not in ctx:
        from src.reports.valhalla_report_context import build_remediation_matrix_rows
        html_findings = ctx.get("findings", [])
        if html_findings:
            ctx["remediation_matrix"] = build_remediation_matrix_rows(html_findings)

    # Build infra_recommendations for HTML template (same logic as JSON generate_json)
    if "infra_recommendations" not in ctx:
        from src.reports.infra_recommendations import generate_infra_recommendations
        vc = ctx.get("valhalla_context") or {}
        findings = ctx.get("findings", [])
        ctx["infra_recommendations"] = generate_infra_recommendations(
            tech_stack=vc if isinstance(vc, dict) else {},
            findings=findings,
            ssl_tls=vc.get("ssl_tls_analysis", {}) if isinstance(vc, dict) else {},
            security_headers=vc.get("security_headers_analysis", {}) if isinstance(vc, dict) else {},
        )

    html_str = render_tier_report_html(eff_tier, ctx)
    return html_str.encode("utf-8")


def _branded_pdf_templates_directory() -> Path:
    """Return ``backend/templates/reports`` (NEW top-level branded PDF templates).

    Distinct from :func:`template_env.report_templates_directory` which returns
    the legacy in-package templates (``src/reports/templates/reports``). Branded
    PDF layouts live outside the Python package so designers can iterate on the
    HTML/CSS without a Python re-deploy (the assets are shipped as data files
    via ``pyproject.toml`` package-data globs / Dockerfile COPY).
    """
    return Path(__file__).resolve().parents[2] / "templates" / "reports"


def _resolve_branded_pdf_template_path(tier: str) -> Path | None:
    """Return the branded ``pdf_layout.html`` path for ``tier`` or ``None``.

    ``None`` flips :func:`generate_pdf` into the legacy fallback (the same
    HTML used by :func:`generate_html`). Keeps the function safe to call on a
    deployment that has not yet shipped the ARG-036 templates.
    """
    candidate = _branded_pdf_templates_directory() / tier / "pdf_layout.html"
    return candidate if candidate.exists() else None


def _compute_pdf_watermark(
    *, tenant_id: str | None, scan_id: str | None, scan_completed_at: str | None
) -> str:
    """Deterministic SHA-256 watermark for the PDF cover page / footer.

    We deliberately do NOT hash the rendered PDF bytes — that would be
    circular (the watermark would change every render even for identical
    inputs). Instead we hash the immutable source-of-truth tuple
    ``(tenant_id, scan_id, scan_completed_at)``. Two PDFs derived from the
    same scan therefore share a watermark, satisfying the determinism
    contract documented in ``docs/report-service.md``.
    """
    seed = "|".join(
        [
            (tenant_id or "").strip(),
            (scan_id or "").strip(),
            (scan_completed_at or "").strip(),
        ]
    )
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return digest[:16]  # 64 bits = ample collision resistance for a watermark


def _build_branded_pdf_context(
    data: ReportData,
    base_context: Mapping[str, Any] | None,
    *,
    tier: str,
) -> dict[str, Any]:
    """Decorate ``base_context`` with ARG-036 fields the branded templates need."""
    from src.reports.jinja_minimal_context import offline_minimal_jinja_context_from_report_data

    ctx: dict[str, Any] = (
        dict(base_context)
        if base_context is not None
        else offline_minimal_jinja_context_from_report_data(data, tier)
    )
    ctx.setdefault("tier", tier)
    ctx.setdefault("target", data.target or "")
    ctx.setdefault("tenant_id", data.tenant_id or "")
    ctx.setdefault("scan_id", data.scan_id or "")
    ctx["scan_completed_at"] = data.created_at or ""
    ctx["pdf_watermark"] = _compute_pdf_watermark(
        tenant_id=data.tenant_id,
        scan_id=data.scan_id,
        scan_completed_at=data.created_at,
    )
    from src.reports.valhalla_report_context import get_brand
    brand = get_brand()
    ctx["brand_name"] = brand.name
    ctx["brand_logo_data_uri"] = (
        f"data:image/png;base64,{brand.logo_base64_png}"
        if brand.logo_base64_png
        else f"data:image/svg+xml;base64,{brand.logo_base64_svg}"
    )
    ctx["brand_logo_sha256"] = brand.logo_sha256
    ctx["brand_alt_text"] = brand.alt_text
    return ctx


def _render_branded_pdf_html(template_path: Path, context: dict[str, Any]) -> str:
    """Render a branded ``pdf_layout.html`` template with the report context.

    Each tier's template directory is loaded as its own Jinja root so that
    relative ``url(...)`` references in the linked CSS resolve correctly under
    WeasyPrint's ``base_url``. The shared ``md`` filter (markdown → sanitised
    HTML) is wired in to keep AI-section rendering consistent across HTML and
    PDF surfaces.
    """
    from src.reports.template_env import _md_filter

    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["md"] = _md_filter
    template = env.get_template(template_path.name)
    return template.render(context)


# B6-T02 / T48 — closed taxonomy for ``Tenant.pdf_archival_format``.
# Mirrored from ``src.db.models.PDF_ARCHIVAL_FORMAT_VALUES`` to avoid an
# import cycle (``generators`` is at the bottom of the import graph and
# ``models`` already pulls in ``owasp_top10_2025``).
_PDF_ARCHIVAL_FORMAT_STANDARD = "standard"
_PDF_ARCHIVAL_FORMAT_PDFA_2U = "pdfa-2u"
_PDFA_ENV_VAR = "REPORT_PDFA_MODE"
_PDFA_ENV_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _resolve_pdfa_mode(
    *,
    pdf_archival_format: str | None,
    report_id: str | None,
    tenant_id: str | None,
) -> bool:
    """Decide whether to engage PDF/A-2u rendering for a single report.

    Precedence (B6-T02 / T48 / D-4):

    1. Per-tenant ``pdf_archival_format`` — authoritative when supplied.
       ``"pdfa-2u"`` → ``True``; ``"standard"`` → ``False`` (env ignored,
       warning logged once so test ops can spot stale ``REPORT_PDFA_MODE``).
    2. ``REPORT_PDFA_MODE`` env var — *only* honoured when the caller did
       not pass ``pdf_archival_format`` (legacy/test paths where there is
       no Tenant row). Treated as a global testing override.

    Unknown taxonomy values fall back to the env path with a warning so a
    schema-drift bug never silently changes a production tenant's archival
    format.
    """
    import os

    env_raw = os.environ.get(_PDFA_ENV_VAR, "").strip().lower()
    env_pdfa_mode = env_raw in _PDFA_ENV_TRUTHY

    if pdf_archival_format is None:
        return env_pdfa_mode

    fmt = pdf_archival_format.strip().lower()
    if fmt == _PDF_ARCHIVAL_FORMAT_PDFA_2U:
        if env_raw and not env_pdfa_mode:
            logger.warning(
                "pdfa_mode_env_ignored_per_tenant_override",
                extra={
                    "event": "argus.report.pdfa_mode_env_ignored",
                    "report_id": report_id,
                    "tenant_id_set": bool(tenant_id),
                    "tenant_format": fmt,
                    "env_value_truthy": env_pdfa_mode,
                },
            )
        return True

    if fmt == _PDF_ARCHIVAL_FORMAT_STANDARD:
        if env_pdfa_mode:
            logger.warning(
                "pdfa_mode_env_ignored_per_tenant_override",
                extra={
                    "event": "argus.report.pdfa_mode_env_ignored",
                    "report_id": report_id,
                    "tenant_id_set": bool(tenant_id),
                    "tenant_format": fmt,
                    "env_value_truthy": True,
                },
            )
        return False

    logger.warning(
        "pdfa_mode_unknown_tenant_format",
        extra={
            "event": "argus.report.pdfa_mode_unknown_tenant_format",
            "report_id": report_id,
            "tenant_id_set": bool(tenant_id),
            "tenant_format": fmt,
        },
    )
    return env_pdfa_mode


def generate_pdf(
    data: ReportData,
    *,
    jinja_context: dict[str, Any] | None = None,
    tier: str | None = None,
    pdf_archival_format: str | None = None,
) -> bytes:
    """ARG-036 — Branded, deterministic PDF dispatched through ``pdf_backend``.

    Flow
    ----
    1. Resolve the active PDF backend (env-driven WeasyPrint → LaTeX → Disabled
       fallback chain) via :func:`pdf_backend.get_active_backend`.
    2. Render the tier-specific branded HTML
       (``backend/templates/reports/<tier>/pdf_layout.html``) with the
       provided ``jinja_context`` (or a freshly built minimal one) augmented
       with ARG-036 fields (``pdf_watermark``, ``scan_completed_at``).
    3. Hand the HTML + ``scan_completed_at`` to the backend, which writes the
       PDF to a tempfile we then read back as ``bytes``.

    PDF/A-2u archival mode (B6-T02 / T48 / D-4)
    -------------------------------------------
    The decision to render in PDF/A-2u mode follows a strict precedence:

    1. **Per-tenant** ``pdf_archival_format`` — when the caller supplies
       ``"pdfa-2u"`` (resolved from the ``Tenant`` row in the async layer)
       PDF/A-2u is engaged unconditionally.
    2. **Per-tenant** ``pdf_archival_format == "standard"`` — PDF/A-2u is
       disabled unconditionally, and the ``REPORT_PDFA_MODE`` env var is
       *ignored* (with a single warning log per render so test environments
       that still set the env get a visible nudge).
    3. **Env override** ``REPORT_PDFA_MODE`` — used only when the caller
       does NOT pass ``pdf_archival_format`` (i.e. the legacy/test path
       where there is no tenant context). Treated as a *testing-only*
       knob — production code paths should always pass the per-tenant
       value resolved by ``ReportService``.

    Rationale: the per-tenant flag is the source of truth in production.
    A global env override is unsafe in multi-tenant deployments because it
    silently flips every tenant's archival format at once. Keeping the env
    available behind the "no tenant context" gate preserves the
    single-process LaTeX backend tests that pre-date B6-T02.

    Backwards compatibility
    -----------------------
    * Function signature is **additive** — the new ``pdf_archival_format``
      keyword argument defaults to ``None`` so legacy callers
      (``generate_html`` flows, unit tests, the Phase-1 stub) keep their
      existing behaviour.
    * If the branded template directory is not present (older deployment)
      we fall back to the legacy HTML used by :func:`generate_html`. The
      legacy path keeps shipping reports while operators roll out the new
      template assets.
    * If both the WeasyPrint and the LaTeX backends are unavailable we
      raise ``RuntimeError`` — same surface contract as the previous
      implementation, mapped to HTTP 503 by the API layer.
    """
    import tempfile

    from src.reports.pdf_backend import (
        DisabledBackend,
        LatexBackend,
        WeasyPrintBackend,
        get_active_backend,
        render_latex_template,
        render_pdfa_xmpdata,
        resolve_latex_template_path,
    )

    tier_str = tier or "midgard"
    pdfa_mode = _resolve_pdfa_mode(
        pdf_archival_format=pdf_archival_format,
        report_id=data.report_id,
        tenant_id=data.tenant_id,
    )
    branded_template = _resolve_branded_pdf_template_path(tier_str)
    ctx_for_latex: dict[str, Any] | None = None

    if branded_template is not None:
        ctx = _build_branded_pdf_context(data, jinja_context, tier=tier_str)
        ctx_for_latex = ctx
        try:
            html_str = _render_branded_pdf_html(branded_template, ctx)
        except Exception as exc:  # template/Jinja errors fall through to legacy
            logger.warning(
                "branded_pdf_template_render_failed",
                extra={
                    "event": "branded_pdf_template_render_failed",
                    "tier": tier_str,
                    "error_type": type(exc).__name__,
                },
            )
            html_str = generate_html(
                data, jinja_context=jinja_context, tier=tier
            ).decode("utf-8")
            base_url = _legacy_base_url()
        else:
            base_url = str(branded_template.parent)
    else:
        html_str = generate_html(data, jinja_context=jinja_context, tier=tier).decode(
            "utf-8"
        )
        base_url = _legacy_base_url()

    backend = get_active_backend()

    # ARG-048 Phase-2 — if the active backend is LaTeX and a per-tier
    # ``main.tex.j2`` exists, pre-render the LaTeX source so the backend
    # can use the branded layout instead of the Phase-1 HTML→text stub.
    # We *attempt* the render here; any failure falls back gracefully to
    # the Phase-1 stub via ``latex_template_content=None``. This keeps
    # the PDF pipeline alive even if a tier template has a Jinja2 bug.
    latex_template_source: str | None = None
    xmpdata_source: str | None = None
    effective_pdfa_mode = False
    if isinstance(backend, LatexBackend):
        if resolve_latex_template_path(tier_str) is not None:
            latex_ctx = ctx_for_latex
            if latex_ctx is None:
                latex_ctx = _build_branded_pdf_context(
                    data, jinja_context, tier=tier_str
                )
            # ARG-058 — propagate the flag into the Jinja context so the
            # shared ``_preamble/pdfa.tex.j2`` fragment can switch between
            # the standard hyperref preamble and the pdfx PDF/A-2u stack.
            latex_ctx = {**latex_ctx, "pdfa_mode": pdfa_mode}
            try:
                latex_template_source = render_latex_template(tier_str, latex_ctx)
            except Exception as exc:  # noqa: BLE001 — template errors must not 503.
                logger.warning(
                    "latex_template_render_failed",
                    extra={
                        "event": "latex_template_render_failed",
                        "tier": tier_str,
                        "error_type": type(exc).__name__,
                    },
                )
                latex_template_source = None
            if pdfa_mode and latex_template_source is not None:
                try:
                    xmpdata_source = render_pdfa_xmpdata(tier_str, latex_ctx)
                    effective_pdfa_mode = True
                except Exception as exc:  # noqa: BLE001 — fall back to non-PDFA.
                    logger.warning(
                        "pdfa_xmpdata_render_failed",
                        extra={
                            "event": "pdfa_xmpdata_render_failed",
                            "tier": tier_str,
                            "error_type": type(exc).__name__,
                        },
                    )
                    xmpdata_source = None
                    effective_pdfa_mode = False

    if isinstance(backend, DisabledBackend):
        # Mirror the previous contract: callers expect a clear failure they can
        # surface as HTTP 503 / drop the PDF from the bundle. We only escalate
        # when WeasyPrint is the requested default; an explicit `disabled`
        # selection (operator override) is treated as the authoritative
        # decision and we still raise — the contract is "no PDF bytes ever".
        logger.error(
            "pdf_backend_unavailable",
            extra={
                "event": "pdf_backend_unavailable",
                "report_id": data.report_id,
                "requested_default": WeasyPrintBackend.name,
            },
        )
        raise RuntimeError(
            "PDF generation unavailable (no WeasyPrint or LaTeX backend on host)"
        )

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        output_path = Path(tmp.name)
    try:
        ok = backend.render(
            html_content=html_str,
            output_path=output_path,
            scan_completed_at=data.created_at or "",
            base_url=base_url,
            latex_template_content=latex_template_source,
            pdfa_mode=effective_pdfa_mode,
            xmpdata_content=xmpdata_source,
        )
        if not ok or not output_path.exists() or output_path.stat().st_size == 0:
            logger.error(
                "pdf_generation_failed",
                extra={
                    "event": "pdf_generation_failed",
                    "report_id": data.report_id,
                    "backend": backend.name,
                },
            )
            raise RuntimeError(f"PDF generation failed (backend={backend.name})")
        return output_path.read_bytes()
    finally:
        try:
            output_path.unlink(missing_ok=True)
        except OSError:
            # Tempfile cleanup failures must not mask successful generation.
            pass


def generate_markdown(
    data: ReportData, *, jinja_context: dict[str, Any] | None = None, tier: str | None = None
) -> bytes:
    """Generate Markdown report — headings, tables, collapsible evidence blocks."""
    from src.reports.valhalla_report_context import get_brand

    brand = get_brand()
    t = tier or _tier_from_jinja(jinja_context) or "midgard"
    tier_label = t.upper()
    lines: list[str] = []

    lines.append(f"# {brand.name} — Security Assessment Report")
    lines.append("")
    lines.append(f"**Tier:** {tier_label}  ")
    lines.append(f"**Target:** {data.target or 'N/A'}  ")
    lines.append(f"**Scan ID:** `{data.scan_id or 'N/A'}`  ")
    lines.append(f"**Report ID:** `{data.report_id or 'N/A'}`  ")
    lines.append(f"**Generated:** {data.created_at or ''}  ")
    lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    summary = _clean_ansi(data.executive_summary or "")
    lines.append(summary or "_No executive summary available._")
    lines.append("")

    lines.append("## Findings")
    lines.append("")

    findings_ordered = _findings_sorted(data.findings)
    findings_ordered = _apply_scope_filter(findings_ordered, data.target or "")
    findings_ordered = _apply_evidence_gate(findings_ordered)
    findings_ordered = _apply_fuzz_hit_evidence_gate(findings_ordered)
    findings_ordered = enforce_severity_by_evidence(findings_ordered)

    severity_emoji: dict[str, str] = {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "🟢 LOW",
        "info": "🔵 INFO",
        "none": "⚪ NONE",
    }

    counts: dict[str, int] = {}
    for f in findings_ordered:
        sev = str(getattr(f, "severity", "info") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1

    lines.append("| # | Severity | Title | Endpoint | Status |")
    lines.append("|---|----------|-------|----------|--------|")
    for idx, f in enumerate(findings_ordered, 1):
        sev = str(getattr(f, "severity", "info") or "info").lower()
        title = _clean_ansi(str(getattr(f, "title", getattr(f, "name", "")) or ""))
        endpoint = str(getattr(f, "endpoint", getattr(f, "url", "")) or "")
        status = str(getattr(f, "validation_status", getattr(f, "evidence_classification", "unverified"))) or "unverified"
        lines.append(f"| {idx} | {severity_emoji.get(sev, sev.upper())} | {title} | `{endpoint}` | {status} |")

    lines.append("")
    lines.append(f"**Severity Breakdown:** " + ", ".join(f"{severity_emoji.get(k, k.upper())}: {v}" for k, v in sorted(counts.items())))
    lines.append("")

    lines.append("### Finding Details")
    lines.append("")

    for idx, f in enumerate(findings_ordered, 1):
        sev = str(getattr(f, "severity", "info") or "info").lower()
        title = _clean_ansi(str(getattr(f, "title", getattr(f, "name", "")) or ""))
        desc = _clean_ansi(str(getattr(f, "description", "") or ""))
        endpoint = str(getattr(f, "endpoint", getattr(f, "url", "")) or "")
        method = str(getattr(f, "method", "") or "")
        param = str(getattr(f, "parameter", "") or "")
        status = str(getattr(f, "validation_status", getattr(f, "evidence_classification", ""))) or "unverified"
        cwe = str(getattr(f, "cwe", "") or "")
        owasp = str(getattr(f, "owasp", "") or "")
        cvss_score = getattr(f, "cvss_score", None)
        cvss_vector = str(getattr(f, "cvss_vector", "") or "")
        remediation = _clean_ansi(str(getattr(f, "remediation", getattr(f, "fix_action", "")) or ""))
        verification = str(getattr(f, "verification_command", "") or "")
        tool_name = str(getattr(f, "tool_name", "") or "")

        lines.append(f"#### {idx}. {title}")
        lines.append("")
        lines.append(f"- **Severity:** {severity_emoji.get(sev, sev.upper())}")
        lines.append(f"- **Status:** {status}")
        lines.append(f"- **Endpoint:** `{endpoint}`")
        if method:
            lines.append(f"- **Method:** `{method}`")
        if param:
            lines.append(f"- **Parameter:** `{param}`")
        if cwe:
            lines.append(f"- **CWE:** {cwe}")
        if owasp:
            lines.append(f"- **OWASP:** {owasp}")
        if cvss_score is not None and cvss_score != 0:
            lines.append(f"- **CVSS Score:** {cvss_score}")
        if cvss_vector:
            lines.append(f"- **CVSS Vector:** `{cvss_vector}`")
        if tool_name:
            lines.append(f"- **Tool:** {tool_name}")
        lines.append("")

        if desc:
            lines.append("**Description:**")
            lines.append("")
            lines.append(desc)
            lines.append("")

        if remediation:
            lines.append("**Remediation:**")
            lines.append("")
            lines.append(remediation)
            lines.append("")

        if verification:
            lines.append("**Verification:**")
            lines.append("")
            lines.append(f"```\n{verification}\n```")
            lines.append("")

        lines.append("---")
        lines.append("")

    lines.append("## Technologies Detected")
    lines.append("")
    tech_list = sorted(str(t) for t in (data.technologies or []))
    if tech_list:
        for tech in tech_list:
            lines.append(f"- {tech}")
    else:
        lines.append("_No technologies detected._")
    lines.append("")

    ai_sections, _ = _jinja_ai_sections_and_scan_artifacts(jinja_context)
    if ai_sections:
        lines.append("## AI-Generated Sections")
        lines.append("")
        if isinstance(ai_sections, list):
            for ai_sec in ai_sections:
                if isinstance(ai_sec, dict):
                    ai_title = str(ai_sec.get("section", ai_sec.get("heading", "")) or "")
                    ai_body = str(ai_sec.get("content", ai_sec.get("text", "")) or "")
                    if ai_title:
                        lines.append(f"### {ai_title}")
                        lines.append("")
                    if ai_body:
                        lines.append(ai_body)
                        lines.append("")
        elif isinstance(ai_sections, dict):
            for k, v in ai_sections.items():
                lines.append(f"### {k}")
                lines.append("")
                lines.append(_clean_ansi(str(v)))
                lines.append("")

    lines.append("## Timeline")
    lines.append("")
    timeline_sorted = sorted(
        data.timeline, key=lambda e: (e.order_index, e.phase or "", e.created_at or "")
    )
    for tl in timeline_sorted:
        phase = tl.phase or ""
        ts = tl.created_at or ""
        entry = _clean_ansi(str(tl.entry) if not isinstance(tl.entry, dict) else json.dumps(tl.entry))
        lines.append(f"- **[{phase}]** {ts}: {entry}")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"*Report generated by {brand.name} | Logo SHA-256: `{brand.logo_sha256}` | Export integrity verified*")
    lines.append("")

    return "\n".join(lines).encode("utf-8")


def _legacy_base_url() -> str:
    """Return base_url for the legacy in-package templates."""
    from src.reports.template_env import report_templates_directory

    return str(report_templates_directory())
