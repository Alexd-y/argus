"""Report generators — HTML, JSON, PDF, CSV."""

import csv
import io
import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

from src.api.schemas import Finding, ReportSummary
from src.db.models import Finding as FindingModel
from src.db.models import Report
from src.reports.data_collector import (
    FindingRow,
    RawArtifactItem,
    ScanReportData,
    TimelineRow,
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
    ai_insights: str | list[str] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    phase_outputs: list[PhaseOutputEntry] = field(default_factory=list)
    evidence: list[EvidenceEntry] = field(default_factory=list)
    screenshots: list[ScreenshotEntry] = field(default_factory=list)
    executive_summary: str | None = None
    remediation: str | list[str] = field(default_factory=list)
    raw_artifacts: list[dict[str, Any]] = field(default_factory=list)


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

    summary = summary_dict_to_report_summary(data.report.summary if data.report else None)
    technologies: list[str] = []
    if data.report and data.report.technologies:
        technologies = [str(t) for t in data.report.technologies]

    created_at: str | None = None
    if data.report and data.report.created_at is not None:
        ca = data.report.created_at
        created_at = ca.isoformat() if hasattr(ca, "isoformat") else str(ca)

    timeline = [_timeline_row_to_entry(t) for t in data.timeline]
    phase_outputs = [
        PhaseOutputEntry(phase=row.phase, output_data=row.output_data) for row in data.phase_outputs
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
        if isinstance(raw_exec, dict):
            exec_s = str(raw_exec)
        elif raw_exec is not None:
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

    raw_artifacts_dicts = [
        item.model_dump(mode="json") for item in data.raw_artifacts
    ]

    return ReportData(
        report_id=rid,
        target=target,
        summary=summary,
        findings=[_finding_row_to_schema(f) for f in data.findings],
        technologies=technologies,
        created_at=created_at,
        scan_id=data.scan_id,
        ai_insights=final_ai_list,
        timeline=timeline,
        phase_outputs=phase_outputs,
        evidence=[],
        screenshots=[],
        executive_summary=exec_s,
        remediation=rem,
        raw_artifacts=raw_artifacts_dicts,
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
    ai_insights = [str(x) for x in ai] if isinstance(ai, list) else [str(ai)] if ai else []
    exec_summary = executive_summary or s.get("executive_summary") or (s.get("executiveSummary"))
    if isinstance(exec_summary, dict):
        exec_summary = str(exec_summary)
    rem = remediation if remediation is not None else s.get("remediation") or s.get("recommendations")
    if isinstance(rem, str):
        rem = [rem] if rem else []
    elif rem is None:
        rem = []
    return ReportData(
        report_id=report.id,
        target=report.target,
        summary=report_to_summary(report),
        findings=[
            Finding(severity=f.severity, title=f.title, description=f.description or "", cwe=f.cwe, cvss=f.cvss)
            for f in findings
        ],
        technologies=report.technologies or [],
        created_at=report.created_at.isoformat() if report.created_at else None,
        scan_id=report.scan_id,
        ai_insights=ai_insights,
        timeline=timeline or [],
        phase_outputs=phase_outputs or [],
        evidence=evidence or [],
        screenshots=screenshots or [],
        executive_summary=exec_summary,
        remediation=rem,
    )


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "cwe": f.cwe,
        "cvss": f.cvss,
    }


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


def generate_json(data: ReportData, *, jinja_context: dict[str, Any] | None = None) -> bytes:
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
        {"finding_id": e.finding_id, "object_key": e.object_key, "description": e.description}
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
        "findings": [_finding_to_dict(f) for f in findings_ordered],
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
    return json.dumps(output, indent=2, ensure_ascii=False).encode("utf-8")


def generate_csv(data: ReportData, *, jinja_context: dict[str, Any] | None = None) -> bytes:
    """Generate CSV report — findings as rows (same severity order as JSON, RPT-009); optional AI/artifacts appendix."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Severity", "Title", "Description", "CWE", "CVSS"])
    for f in _findings_sorted(data.findings):
        writer.writerow([
            f.severity,
            f.title or "",
            (f.description or "").replace("\n", " "),
            f.cwe or "",
            str(f.cvss) if f.cvss is not None else "",
        ])
    ai_sections, scan_artifacts = _jinja_ai_sections_and_scan_artifacts(jinja_context)
    writer.writerow([])
    writer.writerow(["# ai_sections (section_key, text)"])
    writer.writerow(["section_key", "section_text"])
    for k in sorted(ai_sections.keys(), key=str):
        writer.writerow([k, str(ai_sections[k] or "")])
    writer.writerow([])
    writer.writerow(["# scan_artifacts (single JSON cell)"])
    writer.writerow([json.dumps(_canonical_json_nested(scan_artifacts), ensure_ascii=False)])
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

    ctx = jinja_context if jinja_context is not None else minimal_jinja_context_from_report_data(
        data, tier or "midgard"
    )
    eff_tier = str(ctx.get("tier") or tier or "midgard")
    ctx = {**ctx, "tier": eff_tier}
    html_str = render_tier_report_html(eff_tier, ctx)
    return html_str.encode("utf-8")


def generate_pdf(
    data: ReportData,
    *,
    jinja_context: dict[str, Any] | None = None,
    tier: str | None = None,
) -> bytes:
    """
    RPT-009 — PDF from the same tiered HTML as ``generate_html``, via WeasyPrint.
    Requires native libs (Pango, Cairo); use Docker image or OS packages.
    """
    from src.reports.template_env import report_templates_directory

    html_bytes = generate_html(data, jinja_context=jinja_context, tier=tier)
    html_str = html_bytes.decode("utf-8")
    base_url = str(report_templates_directory())

    try:
        from weasyprint import HTML
    except (OSError, ImportError) as exc:
        logger.error(
            "weasyprint_unavailable",
            extra={"event": "weasyprint_unavailable", "error_type": type(exc).__name__},
        )
        raise RuntimeError("PDF generation unavailable (WeasyPrint system libraries missing)") from exc

    try:
        return HTML(string=html_str, base_url=base_url).write_pdf()
    except Exception as exc:
        logger.exception(
            "pdf_generation_failed",
            extra={"event": "pdf_generation_failed", "report_id": data.report_id},
        )
        raise RuntimeError("PDF generation failed") from exc
