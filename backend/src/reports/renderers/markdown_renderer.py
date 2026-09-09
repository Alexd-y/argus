"""Markdown renderer — human-readable projection of the snapshot.

Every finding id, severity, evidence id, coverage capability, limitation and the
snapshot hash appears verbatim so the format stays semantically equivalent to
JSON/XML (parity test asserts this).
"""

from __future__ import annotations

from src.reports.report_document import ReportDocumentV1


def _na(value: object) -> str:
    return "not_assessed" if value in (None, "") else str(value)


def render_markdown(doc: ReportDocumentV1) -> str:
    lines: list[str] = []
    lines.append(f"# ARGUS Report — {doc.target}")
    lines.append("")
    lines.append(f"- scan_id: `{doc.scan_id}`")
    lines.append(f"- scan_profile: `{_na(doc.scan_profile)}`")
    lines.append(f"- resolved_scan_mode: `{_na(doc.resolved_scan_mode)}`")
    lines.append(f"- execution_mode: `{_na(doc.execution_mode)}`")
    lines.append(f"- nuclei_profile: `{_na(doc.nuclei_profile)}`")
    lines.append(f"- started_at: `{_na(doc.started_at)}`")
    lines.append(f"- completed_at: `{_na(doc.completed_at)}`")
    lines.append(f"- schema_version: `{doc.schema_version}`")
    lines.append(f"- snapshot_hash: `{doc.snapshot_hash}`")
    lines.append("")

    lines.append(f"## Findings ({len(doc.findings)})")
    lines.append("")
    if not doc.findings:
        lines.append("_not_assessed — no findings in this snapshot._")
    for f in doc.findings:
        lines.append(f"### {f.title} — `{f.finding_id}`")
        lines.append(f"- severity: `{f.severity}`")
        lines.append(f"- verification_status: `{f.verification_status}`")
        lines.append(f"- confidence: `{f.confidence:.4f}`")
        lines.append(f"- cwe: `{_na(f.cwe)}`")
        lines.append(f"- tool_run_id: `{_na(f.tool_run_id)}`")
        lines.append(f"- validator_id: `{_na(f.validator_id)}`")
        lines.append(f"- raw_artifact_ref: `{_na(f.raw_artifact_ref)}`")
        ev = ", ".join(f"`{e}`" for e in f.evidence_ids) or "_none_"
        lines.append(f"- evidence_ids: {ev}")
        if f.description:
            lines.append("")
            lines.append(f.description)
        lines.append("")

    lines.append("## Coverage")
    lines.append("")
    if not doc.coverage:
        lines.append("_not_assessed_")
    for c in doc.coverage:
        reason = f" (reason: `{c.reason_code}`)" if c.reason_code else ""
        lines.append(f"- `{c.capability_id}`: `{c.status}`{reason}")
    lines.append("")

    lines.append("## Tool runs")
    lines.append("")
    if not doc.tool_runs:
        lines.append("_not_assessed_")
    for t in doc.tool_runs:
        ps = f" parser_status=`{t.parser_status}`" if t.parser_status else ""
        lines.append(f"- `{t.tool_run_id}` {t.tool_name}: `{t.status}`{ps}")
    lines.append("")

    if doc.wstg:
        w = doc.wstg
        cov = w.get("coverage_pct")
        cov_txt = "n/a (undefined)" if cov is None else f"{cov}%"
        denom = w.get("denominator", w.get("applicable"))
        catalog = w.get("catalog_total", w.get("catalog_size"))
        lines.append("## WSTG v4.2 Coverage")
        lines.append("")
        if w.get("schema_version") is None:
            lines.append(
                "> **legacy / unverified:** this snapshot predates evidence-based "
                "coverage (ARGUS-WSTG-COV-1); figures were not re-validated."
            )
            lines.append("")
        else:
            lines.append(
                f"- versions: policy `{w.get('policy_version')}`, rules "
                f"`{w.get('applicability_rules_version')}`, scenarios "
                f"`{w.get('scenario_registry_version')}`"
            )
        lines.append(
            "> pass/fail is a control's security result; the percentage is "
            "execution completeness, not application security."
        )
        lines.append("")
        lines.append(f"- assessment: `{w.get('assessment_status')}`")
        lines.append(
            f"- completed X of applicable: `{w.get('counted')}` / `{denom}` = "
            f"`{cov_txt}` (threshold `{w.get('threshold')}%`)"
        )
        lines.append(f"- completed X of catalog: `{w.get('counted')}` / `{catalog}`")
        lines.append(
            f"- coverage_gate_passed: `{w.get('coverage_gate_passed')}`, "
            f"evidence_integrity_passed: `{w.get('evidence_integrity_passed')}`"
        )
        lines.append(
            f"- not_applicable: `{w.get('validated_not_applicable')}`, "
            f"out_of_scope: `{w.get('out_of_scope')}`, "
            f"unknown: `{w.get('unknown_applicability')}`, blocked: `{w.get('blocked')}`"
        )
        lines.append(
            f"- completed_pass: `{w.get('completed_pass')}`, "
            f"completed_fail: `{w.get('completed_fail')}`, "
            f"partial: `{w.get('partial')}`, not_started: `{w.get('not_started')}`"
        )
        for err in w.get("integrity_errors") or []:
            if isinstance(err, dict):
                lines.append(
                    f"- integrity_error: `{err.get('code')}` "
                    f"{err.get('test_id')}: {err.get('detail')}"
                )
            else:
                lines.append(f"- integrity_error: {err}")
        lines.append("")

    lines.append("## Limitations")
    lines.append("")
    if not doc.limitations:
        lines.append("_none_")
    for lim in doc.limitations:
        lines.append(f"- {lim}")
    lines.append("")

    if doc.validation_errors:
        lines.append("## Validation errors")
        lines.append("")
        for ve in doc.validation_errors:
            lines.append(f"- `{ve.code}` {ve.finding_id or ''}: {ve.message}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


__all__ = ["render_markdown"]
