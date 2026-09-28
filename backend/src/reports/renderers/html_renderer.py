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


def _li(parts: list[str], label: str, value: object) -> None:
    if value not in (None, "", [], {}):
        parts.append(f"<li>{escape(label)}: <code>{escape(str(value))}</code></li>")


def _render_finding_html(parts: list[str], f) -> None:  # noqa: ANN001 - ReportFinding
    parts.append(
        f'<h3 class="sev-{escape(f.severity)}">{escape(f.title)} '
        f"— <code>{escape(f.finding_id)}</code></h3>"
    )
    parts.append("<ul>")
    parts.append(f"<li>severity: <code>{escape(f.severity)}</code></li>")
    parts.append(f"<li>verification_status: <code>{escape(f.verification_status)}</code></li>")
    parts.append(f"<li>confidence: <code>{f.confidence:.4f}</code></li>")
    parts.append(f"<li>cwe: <code>{_na(f.cwe)}</code></li>")
    _li(parts, "owasp_category", f.owasp_category)
    if f.cvss_vector:
        parts.append(
            f"<li>cvss: <code>{_na(f.cvss_score)}</code> "
            f"<code>{_na(f.cvss_version)}</code> <code>{escape(f.cvss_vector)}</code></li>"
        )
    _li(parts, "established_or_hypothesis", f.established_or_hypothesis)
    _li(parts, "confirmation_class", f.confirmation_class)
    _li(parts, "downgrade_reason", f.downgrade_reason)
    if f.review_status != "not_required":
        _li(parts, "review_status", f.review_status)
    _li(parts, "reviewer", f.reviewer)
    parts.append(f"<li>tool_run_id: <code>{_na(f.tool_run_id)}</code></li>")
    parts.append(f"<li>validator_id: <code>{_na(f.validator_id)}</code></li>")
    parts.append(f"<li>raw_artifact_ref: <code>{_na(f.raw_artifact_ref)}</code></li>")
    ev = ", ".join(f"<code>{escape(e)}</code>" for e in f.evidence_ids) or "<em>none</em>"
    parts.append(f"<li>evidence_ids: {ev}</li>")
    parts.append("</ul>")
    if f.description:
        parts.append(f"<p>{escape(f.description)}</p>")
    if f.poc is not None:
        parts.append("<h4>Proof of Concept</h4><ul>")
        p = f.poc
        for label, value in (
            ("preconditions", p.preconditions),
            ("tool", p.tool),
            ("payload", p.payload),
            ("command", p.command),
            ("http_request", p.http_request),
            ("http_response", p.http_response),
            ("discriminator", p.discriminator),
            ("negative_control", p.negative_control),
            ("canary", p.canary),
            ("observation", p.observation),
            ("oast_callback", p.oast_callback),
            ("observed_impact", p.observed_impact),
            ("potential_impact", p.potential_impact),
            ("blast_radius", p.blast_radius),
            ("timing", p.timing),
            ("source", p.source),
            ("attempts", p.attempts),
            ("reproducibility", p.reproducibility),
            ("cleanup", p.cleanup),
            ("client_repro", p.client_repro),
            ("screenshot_ref", p.screenshot_ref),
        ):
            _li(parts, label, value)
        if p.evidence_ids:
            ev2 = ", ".join(f"<code>{escape(e)}</code>" for e in p.evidence_ids)
            parts.append(f"<li>evidence_ids: {ev2}</li>")
        parts.append("</ul>")
    if f.remediation is not None:
        r = f.remediation
        parts.append(f"<h4>Remediation (LLM) — status <code>{escape(r.status)}</code></h4><ul>")
        for label, value in (
            ("temporary_containment", r.temporary_containment),
            ("permanent_fix", r.permanent_fix),
            ("preventive_measures", r.preventive_measures),
            ("component", r.component),
            ("rollout_order", r.rollout_order),
            ("rollback_risk", r.rollback_risk),
            ("retest_plan", r.retest_plan),
        ):
            _li(parts, label, value)
        for i, crit in enumerate(r.acceptance_criteria, 1):
            parts.append(f"<li>acceptance_criteria C-{i:02d}: {escape(crit)}</li>")
        parts.append("</ul>")
    if f.closure is not None:
        c = f.closure
        parts.append(f"<h4>Closure (LLM) — status <code>{_na(c.permitted_status)}</code></h4><ul>")
        for label, value in (
            ("what_verified", c.what_verified),
            ("what_not_verified", c.what_not_verified),
            ("residual_risk", c.residual_risk),
            ("next_step", c.next_step),
        ):
            _li(parts, label, value)
        parts.append("</ul>")


def _render_sections_html(parts: list[str], doc: ReportDocumentV1) -> None:
    """v2 doc-level sections (engagement / methodology / surface / narrative / …)."""
    if doc.engagement is not None:
        e = doc.engagement
        parts.append("<h2>Engagement Parameters</h2><ul>")
        for label, seq in (
            ("testing_windows", e.testing_windows),
            ("source_ips", e.source_ips),
            ("user_agents", e.user_agents),
            ("canaries", e.canaries),
            ("oast_domains", e.oast_domains),
            ("test_accounts", e.test_accounts),
            ("roe_restrictions", e.roe_restrictions),
            ("incidents", e.incidents),
        ):
            if seq:
                parts.append(f"<li>{label}: {escape(', '.join(map(str, seq)))}</li>")
        _li(parts, "run_profile", e.run_profile)
        _li(parts, "execution_mode", e.execution_mode)
        _li(parts, "tool_catalog_version", e.tool_catalog_version)
        _li(parts, "time_source", e.time_source)
        parts.append("</ul>")

    if doc.methodology:
        parts.append("<h2>Methodology</h2><table><tr><th>Framework</th><th>Revision</th>")
        parts.append("<th>Applied</th><th>Notes</th></tr>")
        for m in doc.methodology:
            parts.append(
                f"<tr><td>{escape(m.framework)}</td><td>{_na(m.revision)}</td>"
                f"<td>{m.applied}</td><td>{_na(m.notes)}</td></tr>"
            )
        parts.append("</table>")
        parts.append(
            "<p><em>A mapping to a standard's controls is not a certification of "
            "compliance; testing does not guarantee discovery of all weaknesses.</em></p>"
        )

    if doc.surface_inventory:
        parts.append("<h2>Attack Surface Inventory</h2><table>")
        parts.append(
            "<tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th><th>Technology</th></tr>"
        )
        for s in doc.surface_inventory:
            parts.append(
                f"<tr><td>{escape(s.host)}</td><td>{_na(s.port)}</td>"
                f"<td>{_na(s.service)}</td><td>{_na(s.version)}</td>"
                f"<td>{_na(s.technology)}</td></tr>"
            )
        parts.append("</table>")


def _render_tail_sections_html(parts: list[str], doc: ReportDocumentV1) -> None:
    if doc.unconfirmed_observations:
        parts.append(f"<h2>Unconfirmed Observations ({len(doc.unconfirmed_observations)})</h2><ul>")
        for f in doc.unconfirmed_observations:
            dr = f" (downgraded: {escape(f.downgrade_reason)})" if f.downgrade_reason else ""
            parts.append(
                f"<li><code>{escape(f.finding_id)}</code> {escape(f.title)} — "
                f"<code>{escape(f.severity)}</code>/<code>{escape(f.verification_status)}</code>"
                f"{dr}</li>"
            )
        parts.append("</ul>")

    if doc.test_executions:
        parts.append("<h2>Executed Checks Without Findings</h2><table>")
        parts.append("<tr><th>Test</th><th>Control</th><th>Method</th><th>Result</th></tr>")
        for t in doc.test_executions:
            parts.append(
                f"<tr><td><code>{escape(t.test_id)}</code></td><td>{escape(t.control)}</td>"
                f"<td>{_na(t.method)}</td><td><code>{escape(t.result)}</code></td></tr>"
            )
        parts.append("</table>")

    if doc.attack_narrative:
        parts.append("<h2>Attack Narrative</h2><ol>")
        for step in sorted(doc.attack_narrative, key=lambda s: s.order_index):
            att = (
                f" [{escape(str(step.tactic))}/{escape(str(step.technique_id))}]"
                if step.technique_id
                else ""
            )
            parts.append(
                f"<li><strong>{escape(step.phase)}</strong>{att}: {escape(step.description)}</li>"
            )
        parts.append("</ol>")

    if doc.exploit_chains:
        parts.append("<h2>Impact Chains</h2>")
        for ch in doc.exploit_chains:
            parts.append(
                f"<h3><code>{escape(ch.chain_id)}</code> {escape(ch.title)} — {escape(ch.kind)}</h3><ul>"
            )
            _li(parts, "preconditions", ch.preconditions)
            _li(parts, "outcome", ch.outcome)
            _li(parts, "breaks_at", ch.breaks_at)
            if ch.kind == "hypothetical" and ch.to_verify:
                parts.append(f"<li>to_verify: {escape('; '.join(ch.to_verify))}</li>")
            parts.append("</ul>")

    if doc.conclusions and doc.conclusions.business_risk:
        parts.append("<h2>Business Risk</h2>")
        parts.append(f"<p>{escape(doc.conclusions.business_risk)}</p>")

    if doc.conclusions and doc.conclusions.priority_plan:
        parts.append("<h2>Prioritised Remediation Plan</h2><ol>")
        for item in doc.conclusions.priority_plan:
            fids = item.get("finding_ids") or item.get("findings") or []
            rationale = item.get("rationale") or item.get("reason") or ""
            parts.append(f"<li>{escape(str(rationale))} — {escape(', '.join(map(str, fids)))}</li>")
        parts.append("</ol>")

    if doc.evidence_references:
        parts.append("<h2>Evidence Inventory</h2><table>")
        parts.append(
            "<tr><th>Evidence ID</th><th>Kind</th><th>Object Key</th><th>Description</th></tr>"
        )
        for e in doc.evidence_references:
            parts.append(
                f"<tr><td><code>{escape(e.evidence_id)}</code></td><td>{escape(e.kind)}</td>"
                f"<td>{_na(e.object_key)}</td><td>{_na(e.description)}</td></tr>"
            )
        parts.append("</table>")

    if doc.client_impact is not None:
        c = doc.client_impact
        parts.append("<h2>Impact on Client Environment</h2><ul>")
        for label, seq in (
            ("created_artifacts", c.created_artifacts),
            ("removed", c.removed),
            ("not_removed", c.not_removed),
        ):
            parts.append(
                f"<li>{label}: {escape(', '.join(map(str, seq))) if seq else '<em>none</em>'}</li>"
            )
        _li(parts, "data_exfiltration", c.data_exfiltration)
        _li(parts, "availability_impact", c.availability_impact)
        parts.append("</ul>")

    if doc.conclusions and doc.conclusions.closure_summary:
        parts.append("<h2>Closure Summary</h2>")
        parts.append(f"<p>{escape(doc.conclusions.closure_summary)}</p>")

    if doc.claims:
        parts.append("<h2>Claims Ledger</h2><ul>")
        for cl in doc.claims:
            ev = ", ".join(f"<code>{escape(e)}</code>" for e in cl.evidence_ids) or "<em>none</em>"
            parts.append(
                f"<li><code>{escape(cl.claim_id)}</code> [{escape(cl.claim_type)}] "
                f"{escape(cl.text)} — evidence: {ev}</li>"
            )
        parts.append("</ul>")


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

    # Report passport — independent release statuses (prompt E.2).
    parts.append("<h2>Report Passport</h2><ul>")
    parts.append(f"<li>generation_status: <code>{escape(doc.generation_status)}</code></li>")
    parts.append(f"<li>llm_analysis_status: <code>{escape(doc.llm_analysis_status)}</code></li>")
    parts.append(
        f"<li>assessment_completeness: <code>{escape(doc.assessment_completeness)}</code></li>"
    )
    parts.append(f"<li>evidence_integrity: <code>{escape(doc.evidence_integrity)}</code></li>")
    parts.append(f"<li>review_status: <code>{escape(doc.review_status)}</code></li>")
    if doc.verification_kit_ref:
        parts.append(f"<li>verification_kit: <code>{_na(doc.verification_kit_ref)}</code></li>")
    parts.append("</ul>")

    if doc.conclusions and doc.conclusions.executive_summary:
        parts.append("<h2>Executive Summary</h2>")
        parts.append(f"<p>{escape(doc.conclusions.executive_summary)}</p>")

    _render_sections_html(parts, doc)

    parts.append(f"<h2>Findings ({len(doc.findings)})</h2>")
    if not doc.findings:
        parts.append("<p><em>not_assessed — no findings in this snapshot.</em></p>")
    for f in doc.findings:
        _render_finding_html(parts, f)

    _render_tail_sections_html(parts, doc)

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
