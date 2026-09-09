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
        parts.append(
            f'<h3 class="sev-{escape(f.severity)}">{escape(f.title)} '
            f"— <code>{escape(f.finding_id)}</code></h3>"
        )
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

    if doc.wstg:
        w = doc.wstg
        cov = w.get("coverage_pct")
        cov_txt = "n/a (undefined)" if cov is None else f"{cov}%"
        parts.append("<h2>WSTG v4.2 Coverage</h2>")
        # Historical snapshots predate the evidence-based schema — never present
        # their numbers as newly validated (spec §13).
        if w.get("schema_version") is None:
            parts.append(
                "<p><strong>legacy / unverified:</strong> this snapshot predates "
                "evidence-based coverage (ARGUS-WSTG-COV-1); figures are shown as "
                "recorded and were not re-validated.</p>"
            )
        else:
            parts.append(
                f"<p><small>policy <code>{_na(w.get('policy_version'))}</code>, "
                f"rules <code>{_na(w.get('applicability_rules_version'))}</code>, "
                f"scenarios <code>{_na(w.get('scenario_registry_version'))}</code>, "
                f"catalog <code>{_na(w.get('catalog_checksum'))}</code></small></p>"
            )
        parts.append(
            "<p><em>pass/fail reflects a control's security result; the "
            "percentage reflects execution completeness, not application "
            "security.</em></p>"
        )
        parts.append("<ul>")
        parts.append(f"<li>assessment: <code>{_na(w.get('assessment_status'))}</code></li>")
        parts.append(
            f"<li>completed X of applicable: <code>{_na(w.get('counted'))}</code> / "
            f"<code>{_na(w.get('denominator', w.get('applicable')))}</code> "
            f"= <code>{cov_txt}</code> (threshold <code>{_na(w.get('threshold'))}%</code>)</li>"
        )
        parts.append(
            f"<li>completed X of catalog: <code>{_na(w.get('counted'))}</code> / "
            f"<code>{_na(w.get('catalog_total', w.get('catalog_size')))}</code></li>"
        )
        parts.append(
            f"<li>coverage_gate_passed: <code>{_na(w.get('coverage_gate_passed'))}</code>, "
            f"evidence_integrity_passed: <code>{_na(w.get('evidence_integrity_passed'))}</code></li>"
        )
        parts.append(
            f"<li>not_applicable: <code>{_na(w.get('validated_not_applicable'))}</code>, "
            f"out_of_scope: <code>{_na(w.get('out_of_scope'))}</code>, "
            f"unknown: <code>{_na(w.get('unknown_applicability'))}</code>, "
            f"blocked: <code>{_na(w.get('blocked'))}</code></li>"
        )
        parts.append(
            f"<li>completed_pass: <code>{_na(w.get('completed_pass'))}</code>, "
            f"completed_fail: <code>{_na(w.get('completed_fail'))}</code>, "
            f"partial: <code>{_na(w.get('partial'))}</code>, "
            f"not_started: <code>{_na(w.get('not_started'))}</code></li>"
        )
        parts.append("</ul>")
        ierrs = w.get("integrity_errors") or []
        if ierrs:
            parts.append("<h3>Integrity errors</h3><ul>")
            for err in ierrs:
                code = err.get("code") if isinstance(err, dict) else str(err)
                tid = err.get("test_id") if isinstance(err, dict) else ""
                detail = err.get("detail") if isinstance(err, dict) else ""
                parts.append(
                    f"<li><code>{escape(str(code))}</code> "
                    f"{escape(str(tid))}: {escape(str(detail))}</li>"
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
