"""Report generators — HTML, JSON, PDF, CSV."""

import csv
import hashlib
import io
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
from src.storage.s3 import get_finding_poc_screenshot_presigned_url

logger = logging.getLogger(__name__)

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
    "headers",
    "dependencies",
    "risk_matrix",
    "critical_vulns",
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


def _finding_row_to_schema(row: FindingRow) -> Finding:
    return Finding(
        severity=row.severity,
        title=row.title,
        description=row.description or "",
        cwe=row.cwe,
        cvss=row.cvss,
        owasp_category=parse_owasp_category(row.owasp_category),
        proof_of_concept=row.proof_of_concept,
        confidence=normalize_confidence(row.confidence, default="likely"),
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
                cvss=f.cvss,
                owasp_category=parse_owasp_category(f.owasp_category),
                proof_of_concept=f.proof_of_concept
                if isinstance(f.proof_of_concept, dict)
                else None,
                confidence=normalize_confidence(
                    getattr(f, "confidence", None), default="likely"
                ),
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
                cvss=f.cvss,
                owasp_category=parse_owasp_category(f.owasp_category),
                proof_of_concept=f.proof_of_concept
                if isinstance(f.proof_of_concept, dict)
                else None,
                confidence=normalize_confidence(
                    getattr(f, "confidence", None), default="likely"
                ),
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
) -> list[dict[str, Any]]:
    """
    One row per A01..A10 with finding counts and a CSS hint class (0 → good, 1–2 → warn, 3+ → high).
    Merges description and remediation hints from ``owasp_summary`` or ``build_owasp_summary_from_counts`` (OWASP-002).
    Keys: ``category_id``, ``title``, ``findings_present``, ``count``, ``row_class``.
    """
    counts: dict[str, int] = dict.fromkeys(OWASP_TOP10_2025_CATEGORY_IDS, 0)
    for row in findings:
        oc = row.get("owasp_category")
        if isinstance(oc, str) and oc in counts:
            counts[oc] += 1
    entries = _resolve_owasp_summary_for_rows(counts, owasp_summary)
    out: list[dict[str, Any]] = []
    for cid in OWASP_TOP10_2025_CATEGORY_IDS:
        n = counts[cid]
        if n == 0:
            row_class = "owasp-compliance-0"
        elif n <= 2:
            row_class = "owasp-compliance-warn"
        else:
            row_class = "owasp-compliance-high"
        ent = entries.get(cid)
        description = ent.description if ent else ""
        how_short = ent.how_to_fix_short if ent else None
        description_hover = (how_short or "").strip()
        title_en = OWASP_TOP10_2025_CATEGORY_TITLES.get(cid, cid)
        out.append(
            {
                "category_id": cid,
                "title": title_en,
                "description": description,
                "description_hover": description_hover,
                "has_findings": n > 0,
                "findings_present": "Yes" if n > 0 else "No",
                "count": n,
                "row_class": row_class,
            }
        )
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


def _finding_to_dict(
    f: Finding,
    *,
    tenant_id: str | None = None,
    scan_id: str | None = None,
) -> dict[str, Any]:
    d: dict[str, Any] = {
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "cwe": f.cwe,
        "cvss": f.cvss,
    }
    oc = getattr(f, "owasp_category", None)
    if oc is not None:
        d["owasp_category"] = oc
    poc = getattr(f, "proof_of_concept", None)
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
            "exploitation": exploitation,
            "scan_artifacts": ctx.get("scan_artifacts"),
            "raw_artifacts": data.raw_artifacts,
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
    threat_modeling_ref = {
        "threat_model": vc.get("threat_model"),
        "threat_model_excerpt": vc.get("threat_model_excerpt"),
        "threat_model_phase_link": vc.get("threat_model_phase_link"),
        "exploitation_post_excerpt": vc.get("exploitation_post_excerpt"),
    }
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
        "ssl_tls": _canonical_json_nested(vc.get("ssl_tls_analysis") or {}),
        "headers": _canonical_json_nested(vc.get("security_headers_analysis") or {}),
        "dependencies": _canonical_json_nested(vc.get("dependency_analysis") or []),
        "risk_matrix": _canonical_json_nested(vc.get("risk_matrix") or {}),
        "critical_vulns": _canonical_json_nested(vc.get("critical_vulns") or []),
        "threat_modeling_ref": _canonical_json_nested(threat_modeling_ref),
        "findings": findings_canon,
        "exploit_chains_text": exploit_chains_text,
        "remediation_stages_text": remediation_stages_text,
        "zero_day_text": zero_day_text,
        "conclusion_text": conclusion_text,
        "hibp_pwned_password_summary": hibp_pwned_password_summary,
        "appendices": appendices,
    }


def generate_valhalla_sections_csv(
    data: ReportData,
    *,
    jinja_context: dict[str, Any] | None = None,
) -> bytes:
    """VHL-005 — one row per Valhalla section; text columns plain, structured cells JSON."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["section", "content_markdown_or_json"])
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
            writer.writerow([key, str(val or "")])
        else:
            writer.writerow(
                [key, json.dumps(_canonical_json_nested(val), ensure_ascii=False)]
            )
    return buf.getvalue().encode("utf-8")


def generate_json(
    data: ReportData, *, jinja_context: dict[str, Any] | None = None
) -> bytes:
    """Generate JSON report — full schema with metadata, timeline, phase outputs, findings, evidence, screenshots, AI conclusions, remediation, executive summary."""
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
    output = {
        "report_id": data.report_id,
        "target": data.target,
        "scan_id": data.scan_id,
        "created_at": data.created_at,
        "metadata": metadata,
        "executive_summary": data.executive_summary,
        "summary": _summary_ordered(data.summary),
        "findings": [
            _finding_to_dict(f, tenant_id=data.tenant_id, scan_id=data.scan_id)
            for f in findings_ordered
        ],
        "technologies": tech_sorted,
        "timeline": timeline,
        "phase_outputs": phase_outputs,
        "evidence": evidence,
        "screenshots": screenshots,
        "ai_conclusions": ai_list,
        "remediation": rem_list,
        "ai_sections": _canonical_json_nested(ai_sections),
        "scan_artifacts": _canonical_json_nested(scan_artifacts),
        "active_web_scan": _canonical_json_nested(active_web_scan),
        "raw_artifacts": data.raw_artifacts,
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
    return json.dumps(output, indent=2, ensure_ascii=False).encode("utf-8")


def generate_csv(
    data: ReportData, *, jinja_context: dict[str, Any] | None = None
) -> bytes:
    """Generate CSV report — findings as rows (same severity order as JSON, RPT-009); optional AI/artifacts appendix."""
    # Force LF line terminator so the generator is byte-deterministic across
    # platforms (Python's csv module defaults to CRLF on every host). This
    # matters for snapshot stability and for reproducible content hashes.
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["Severity", "Title", "Description", "CWE", "CVSS"])
    for f in _findings_sorted(data.findings):
        writer.writerow(
            [
                f.severity,
                f.title or "",
                (f.description or "").replace("\n", " "),
                f.cwe or "",
                str(f.cvss) if f.cvss is not None else "",
            ]
        )
    ai_sections, scan_artifacts = _jinja_ai_sections_and_scan_artifacts(jinja_context)
    writer.writerow([])
    writer.writerow(["# ai_sections (section_key, text)"])
    writer.writerow(["section_key", "section_text"])
    for k in sorted(ai_sections.keys(), key=str):
        writer.writerow([k, str(ai_sections[k] or "")])
    writer.writerow([])
    writer.writerow(["# scan_artifacts (single JSON cell)"])
    writer.writerow(
        [json.dumps(_canonical_json_nested(scan_artifacts), ensure_ascii=False)]
    )
    return buf.getvalue().encode("utf-8")


def generate_html(
    data: ReportData,
    *,
    jinja_context: dict[str, Any] | None = None,
    tier: str | None = None,
) -> bytes:
    """RPT-008 — Tiered Jinja2 HTML (autoescape). Pass ``jinja_context`` from Report pipeline when available."""
    from src.reports.jinja_minimal_context import minimal_jinja_context_from_report_data
    from src.reports.template_env import render_tier_report_html

    ctx = (
        jinja_context
        if jinja_context is not None
        else minimal_jinja_context_from_report_data(data, tier or "midgard")
    )
    eff_tier = str(ctx.get("tier") or tier or "midgard")
    ctx = {**ctx, "tier": eff_tier}
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
    from src.reports.jinja_minimal_context import minimal_jinja_context_from_report_data

    ctx: dict[str, Any] = (
        dict(base_context)
        if base_context is not None
        else minimal_jinja_context_from_report_data(data, tier)
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


def generate_pdf(
    data: ReportData,
    *,
    jinja_context: dict[str, Any] | None = None,
    tier: str | None = None,
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

    Backwards compatibility
    -----------------------
    * Function signature is **unchanged** — callers
      (``report_service``, ``report_pipeline``) get drop-in behaviour.
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
        resolve_latex_template_path,
    )

    tier_str = tier or "midgard"
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
    if isinstance(backend, LatexBackend):
        if resolve_latex_template_path(tier_str) is not None:
            latex_ctx = ctx_for_latex
            if latex_ctx is None:
                latex_ctx = _build_branded_pdf_context(
                    data, jinja_context, tier=tier_str
                )
            try:
                latex_template_source = render_latex_template(
                    tier_str, latex_ctx
                )
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


def _legacy_base_url() -> str:
    """Return base_url for the legacy in-package templates."""
    from src.reports.template_env import report_templates_directory

    return str(report_templates_directory())
