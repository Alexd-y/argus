"""Report generators — HTML, JSON, PDF, CSV."""

import csv
import html
import io
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from src.api.schemas import Finding, ReportSummary
from src.db.models import Finding as FindingModel
from src.db.models import Report


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


def report_to_summary(report: Report) -> ReportSummary:
    """Build ReportSummary from Report.summary JSONB."""
    s = dict(report.summary or {})
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


def generate_json(data: ReportData) -> bytes:
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
    output = {
        "report_id": data.report_id,
        "target": data.target,
        "scan_id": data.scan_id,
        "created_at": data.created_at,
        "metadata": {
            "report_id": data.report_id,
            "target": data.target,
            "scan_id": data.scan_id,
            "created_at": data.created_at,
            "technologies": data.technologies,
        },
        "executive_summary": data.executive_summary,
        "summary": data.summary.model_dump(),
        "findings": [_finding_to_dict(f) for f in data.findings],
        "technologies": data.technologies,
        "timeline": [
            {"phase": t.phase, "order_index": t.order_index, "entry": t.entry, "created_at": t.created_at}
            for t in data.timeline
        ],
        "phase_outputs": [
            {"phase": p.phase, "output_data": p.output_data}
            for p in data.phase_outputs
        ],
        "evidence": [
            {"finding_id": e.finding_id, "object_key": e.object_key, "description": e.description}
            for e in data.evidence
        ],
        "screenshots": [
            {"object_key": s.object_key, "url_or_email": s.url_or_email}
            for s in data.screenshots
        ],
        "ai_conclusions": ai_list,
        "remediation": rem_list,
    }
    return json.dumps(output, indent=2, ensure_ascii=False).encode("utf-8")


def generate_csv(data: ReportData) -> bytes:
    """Generate CSV report — findings as rows."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Severity", "Title", "Description", "CWE", "CVSS"])
    for f in data.findings:
        writer.writerow([
            f.severity,
            f.title or "",
            (f.description or "").replace("\n", " "),
            f.cwe or "",
            str(f.cvss) if f.cvss is not None else "",
        ])
    return buf.getvalue().encode("utf-8")


def generate_html(data: ReportData) -> bytes:
    """Generate HTML report with metadata, timeline, phase outputs, findings, evidence, screenshots, AI conclusions, remediation, executive summary."""
    created = data.created_at or datetime.now(UTC).isoformat()
    summary = data.summary

    findings_html = ""
    for f in data.findings:
        desc = html.escape(f.description or "").replace("\n", "<br>")
        cwe = html.escape(f.cwe or "-")
        cvss = str(f.cvss) if f.cvss is not None else "-"
        findings_html += f"""
        <tr>
            <td><span class="sev-{html.escape(f.severity.lower())}">{html.escape(f.severity)}</span></td>
            <td>{html.escape(f.title)}</td>
            <td>{desc}</td>
            <td>{cwe}</td>
            <td>{cvss}</td>
        </tr>"""

    tech_list = ", ".join(html.escape(t) for t in data.technologies) or "-"

    exec_block = ""
    if data.executive_summary:
        exec_block = f"""
        <section class="executive-summary">
            <h2>Executive Summary</h2>
            <p>{html.escape(data.executive_summary)}</p>
        </section>"""

    timeline_block = ""
    if data.timeline:
        items = "".join(
            f"<li>{html.escape(t.phase)} (order: {t.order_index})"
            + (f" — {html.escape(str(t.entry)[:100])}..." if t.entry else "")
            + "</li>"
            for t in sorted(data.timeline, key=lambda x: (x.order_index, x.phase))
        )
        timeline_block = f"""
        <section class="timeline">
            <h2>Timeline</h2>
            <ul>{items}</ul>
        </section>"""

    phase_block = ""
    if data.phase_outputs:
        items = "".join(
            f"<li><strong>{html.escape(p.phase)}</strong>: output available</li>"
            for p in data.phase_outputs
        )
        phase_block = f"""
        <section class="phase-outputs">
            <h2>Phase Outputs</h2>
            <ul>{items}</ul>
        </section>"""

    evidence_block = ""
    if data.evidence:
        items = "".join(
            f"<li>Finding {html.escape(e.finding_id[:8])}... — {html.escape(e.description or e.object_key)}</li>"
            for e in data.evidence[:20]
        )
        evidence_block = f"""
        <section class="evidence">
            <h2>Evidence</h2>
            <ul>{items}</ul>
        </section>"""

    screenshots_block = ""
    if data.screenshots:
        items = "".join(
            f"<li>{html.escape(s.url_or_email or s.object_key)}</li>"
            for s in data.screenshots[:20]
        )
        screenshots_block = f"""
        <section class="screenshots">
            <h2>Screenshots</h2>
            <ul>{items}</ul>
        </section>"""

    ai_block = ""
    if data.ai_insights:
        insights = data.ai_insights if isinstance(data.ai_insights, list) else [data.ai_insights]
        ai_items = "".join(f"<li>{html.escape(str(i))}</li>" for i in insights)
        ai_block = f"""
        <section class="ai-insights">
            <h2>AI Conclusions</h2>
            <ul>{ai_items}</ul>
        </section>"""

    rem_block = ""
    if data.remediation:
        rem_list = data.remediation if isinstance(data.remediation, list) else [data.remediation]
        rem_items = "".join(f"<li>{html.escape(str(r))}</li>" for r in rem_list)
        rem_block = f"""
        <section class="remediation">
            <h2>Remediation</h2>
            <ul>{rem_items}</ul>
        </section>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ARGUS Report — {html.escape(data.target)}</title>
    <style>
        body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; }}
        h1 {{ color: #1a1a2e; }}
        .meta {{ color: #666; font-size: 0.9rem; margin-bottom: 2rem; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 0.5rem 0.75rem; text-align: left; }}
        th {{ background: #f5f5f5; }}
        .sev-critical {{ color: #c00; font-weight: bold; }}
        .sev-high {{ color: #e67e22; font-weight: bold; }}
        .sev-medium {{ color: #f39c12; }}
        .sev-low {{ color: #27ae60; }}
        .sev-info {{ color: #3498db; }}
        .executive-summary, .timeline, .phase-outputs, .evidence, .screenshots, .ai-insights, .remediation {{
            margin-top: 2rem; padding: 1rem; background: #f8f9fa; border-radius: 6px;
        }}
        .executive-summary ul, .timeline ul, .phase-outputs ul, .evidence ul, .screenshots ul, .ai-insights ul, .remediation ul {{
            margin: 0.5rem 0 0 1.5rem;
        }}
    </style>
</head>
<body>
    <h1>ARGUS Security Report</h1>
    <div class="meta">
        <p><strong>Target:</strong> {html.escape(data.target)}</p>
        <p><strong>Report ID:</strong> {html.escape(data.report_id)}</p>
        <p><strong>Created:</strong> {html.escape(created)}</p>
        <p><strong>Technologies:</strong> {tech_list}</p>
        <p><strong>Summary:</strong> Critical: {summary.critical}, High: {summary.high}, Medium: {summary.medium}, Low: {summary.low}, Info: {summary.info}</p>
    </div>
    {exec_block}
    <section>
        <h2>Findings</h2>
        <table>
            <thead>
                <tr><th>Severity</th><th>Title</th><th>Description</th><th>CWE</th><th>CVSS</th></tr>
            </thead>
            <tbody>{findings_html}
            </tbody>
        </table>
    </section>
    {timeline_block}
    {phase_block}
    {evidence_block}
    {screenshots_block}
    {ai_block}
    {rem_block}
</body>
</html>"""
    return html_content.encode("utf-8")


def generate_pdf(data: ReportData) -> bytes:
    """Generate PDF report via reportlab — metadata, timeline, phase outputs, findings, evidence, screenshots, AI conclusions, remediation, executive summary."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=2 * cm, leftMargin=2 * cm)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("ARGUS Security Report", styles["Title"]))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(f"<b>Target:</b> {html.escape(str(data.target))}", styles["Normal"]))
    story.append(Paragraph(f"<b>Report ID:</b> {html.escape(str(data.report_id))}", styles["Normal"]))
    story.append(Paragraph(f"<b>Created:</b> {html.escape(str(data.created_at or '-'))}", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    if data.executive_summary:
        story.append(Paragraph("Executive Summary", styles["Heading2"]))
        story.append(Paragraph(html.escape(data.executive_summary[:1500]), styles["Normal"]))
        story.append(Spacer(1, 0.5 * cm))

    summary = data.summary
    story.append(Paragraph(
        f"Summary: Critical: {summary.critical}, High: {summary.high}, Medium: {summary.medium}, Low: {summary.low}, Info: {summary.info}",
        styles["Normal"],
    ))
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Findings", styles["Heading2"]))
    table_data = [["Severity", "Title", "Description", "CWE", "CVSS"]]
    for f in data.findings:
        desc = (f.description or "")[:200] + ("..." if len(f.description or "") > 200 else "")
        table_data.append([
            f.severity,
            f.title or "",
            desc,
            f.cwe or "-",
            str(f.cvss) if f.cvss is not None else "-",
        ])
    tbl = Table(table_data, colWidths=[1.5 * cm, 3 * cm, 6 * cm, 1.5 * cm, 1 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.5 * cm))

    if data.timeline:
        story.append(Paragraph("Timeline", styles["Heading2"]))
        for t in sorted(data.timeline, key=lambda x: (x.order_index, x.phase))[:15]:
            story.append(Paragraph(f"• {html.escape(t.phase)} (order {t.order_index})", styles["Normal"]))
        story.append(Spacer(1, 0.5 * cm))

    if data.phase_outputs:
        story.append(Paragraph("Phase Outputs", styles["Heading2"]))
        for p in data.phase_outputs[:10]:
            story.append(Paragraph(f"• {html.escape(p.phase)}", styles["Normal"]))
        story.append(Spacer(1, 0.5 * cm))

    if data.evidence:
        story.append(Paragraph("Evidence", styles["Heading2"]))
        for e in data.evidence[:10]:
            story.append(Paragraph(f"• {html.escape(e.description or e.object_key)[:200]}", styles["Normal"]))
        story.append(Spacer(1, 0.5 * cm))

    if data.screenshots:
        story.append(Paragraph("Screenshots", styles["Heading2"]))
        for s in data.screenshots[:10]:
            story.append(Paragraph(f"• {html.escape(s.url_or_email or s.object_key)[:200]}", styles["Normal"]))
        story.append(Spacer(1, 0.5 * cm))

    if data.ai_insights:
        story.append(Paragraph("AI Conclusions", styles["Heading2"]))
        insights = data.ai_insights if isinstance(data.ai_insights, list) else [data.ai_insights]
        for i in insights:
            story.append(Paragraph(html.escape(str(i)), styles["Normal"]))
            story.append(Spacer(1, 0.2 * cm))
        story.append(Spacer(1, 0.5 * cm))

    if data.remediation:
        story.append(Paragraph("Remediation", styles["Heading2"]))
        rem_list = data.remediation if isinstance(data.remediation, list) else [data.remediation]
        for r in rem_list:
            story.append(Paragraph(html.escape(str(r)), styles["Normal"]))
            story.append(Spacer(1, 0.2 * cm))

    doc.build(story)
    return buf.getvalue()
