"""HTML renderer — self-contained HTML projection (feeds the PDF backend).

Kept intentionally minimal and dependency-free (``html.escape`` only) so it can
be rendered to PDF by the existing ``reports.pdf_backend`` without templates.
It is semantically equivalent to the other formats (parity test asserts every
finding id / severity / evidence id / limitation / hash appears).
"""

from __future__ import annotations

from html import escape

from src.reports.report_document import ReportDocumentV1


def _na(value: object) -> str:
    return "not_assessed" if value in (None, "") else escape(str(value))


def render_html(doc: ReportDocumentV1) -> str:
    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append(f"<title>ARGUS Report — {escape(doc.target)}</title>")
    parts.append(
        "<style>body{font-family:sans-serif;margin:2rem;}"
        "h1,h2,h3{color:#1a1a2e;}code{background:#f2f2f2;padding:1px 4px;}"
        ".sev-critical{color:#b00020;}.sev-high{color:#d35400;}.sev-medium{color:#b8860b;}"
        "table{border-collapse:collapse;}td,th{border:1px solid #ccc;padding:4px 8px;}</style>"
    )
    parts.append("</head><body>")
    parts.append(f"<h1>ARGUS Report — {escape(doc.target)}</h1>")

    parts.append('<ul class="meta">')
    for label, value in (
        ("scan_id", doc.scan_id),
        ("scan_profile", doc.scan_profile),
        ("resolved_scan_mode", doc.resolved_scan_mode),
        ("execution_mode", doc.execution_mode),
        ("nuclei_profile", doc.nuclei_profile),
        ("started_at", doc.started_at),
        ("completed_at", doc.completed_at),
        ("schema_version", doc.schema_version),
        ("snapshot_hash", doc.snapshot_hash),
    ):
        parts.append(f"<li>{label}: <code>{_na(value)}</code></li>")
    parts.append("</ul>")

    parts.append(f"<h2>Findings ({len(doc.findings)})</h2>")
    if not doc.findings:
        parts.append("<p><em>not_assessed — no findings in this snapshot.</em></p>")
    for f in doc.findings:
        parts.append(f'<h3 class="sev-{escape(f.severity)}">{escape(f.title)} '
                     f"— <code>{escape(f.finding_id)}</code></h3>")
        parts.append("<ul>")
        parts.append(f"<li>severity: <code>{escape(f.severity)}</code></li>")
        parts.append(f"<li>verification_status: <code>{escape(f.verification_status)}</code></li>")
        parts.append(f"<li>confidence: <code>{f.confidence:.4f}</code></li>")
        parts.append(f"<li>cwe: <code>{_na(f.cwe)}</code></li>")
        parts.append(f"<li>tool_run_id: <code>{_na(f.tool_run_id)}</code></li>")
        parts.append(f"<li>validator_id: <code>{_na(f.validator_id)}</code></li>")
        parts.append(f"<li>raw_artifact_ref: <code>{_na(f.raw_artifact_ref)}</code></li>")
        ev = ", ".join(f"<code>{escape(e)}</code>" for e in f.evidence_ids) or "<em>none</em>"
        parts.append(f"<li>evidence_ids: {ev}</li>")
        parts.append("</ul>")
        if f.description:
            parts.append(f"<p>{escape(f.description)}</p>")

    parts.append("<h2>Coverage</h2>")
    if not doc.coverage:
        parts.append("<p><em>not_assessed</em></p>")
    else:
        parts.append("<ul>")
        for c in doc.coverage:
            reason = f" (reason: <code>{escape(c.reason_code)}</code>)" if c.reason_code else ""
            parts.append(
                f"<li><code>{escape(c.capability_id)}</code>: "
                f"<code>{escape(c.status)}</code>{reason}</li>"
            )
        parts.append("</ul>")

    parts.append("<h2>Tool runs</h2>")
    if not doc.tool_runs:
        parts.append("<p><em>not_assessed</em></p>")
    else:
        parts.append("<ul>")
        for t in doc.tool_runs:
            ps = f" parser_status=<code>{escape(t.parser_status)}</code>" if t.parser_status else ""
            parts.append(
                f"<li><code>{escape(t.tool_run_id)}</code> {escape(t.tool_name)}: "
                f"<code>{escape(t.status)}</code>{ps}</li>"
            )
        parts.append("</ul>")

    parts.append("<h2>Limitations</h2>")
    if not doc.limitations:
        parts.append("<p><em>none</em></p>")
    else:
        parts.append("<ul>")
        for lim in doc.limitations:
            parts.append(f"<li>{escape(lim)}</li>")
        parts.append("</ul>")

    if doc.validation_errors:
        parts.append("<h2>Validation errors</h2><ul>")
        for ve in doc.validation_errors:
            parts.append(
                f"<li><code>{escape(ve.code)}</code> {escape(ve.finding_id or '')}: "
                f"{escape(ve.message)}</li>"
            )
        parts.append("</ul>")

    parts.append("</body></html>")
    return "".join(parts)


__all__ = ["render_html"]
