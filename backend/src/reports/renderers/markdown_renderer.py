"""Markdown renderer — human-readable projection of the snapshot.

Every finding id, severity, evidence id, coverage capability, limitation and the
snapshot hash appears verbatim so the format stays semantically equivalent to
JSON/XML (parity test asserts this).
"""

from __future__ import annotations

from src.reports.report_document import ReportDocumentV1


def _na(value: object) -> str:
    return "not_assessed" if value in (None, "") else str(value)


def _kv(lines: list[str], label: str, value: object) -> None:
    if value not in (None, "", [], {}):
        lines.append(f"- {label}: `{value}`")


def _render_finding_md(lines: list[str], f) -> None:  # noqa: ANN001 - ReportFinding
    """Full vertical finding card (v2): identity, CVSS, PoC, remediation, closure."""
    lines.append(f"### {f.title} — `{f.finding_id}`")
    lines.append(f"- severity: `{f.severity}`")
    lines.append(f"- verification_status: `{f.verification_status}`")
    lines.append(f"- confidence: `{f.confidence:.4f}`")
    lines.append(f"- cwe: `{_na(f.cwe)}`")
    _kv(lines, "owasp_category", f.owasp_category)
    if f.cvss_vector:
        lines.append(f"- cvss: `{f.cvss_score}` `{f.cvss_version or ''}` `{f.cvss_vector}`")
    _kv(lines, "established_or_hypothesis", f.established_or_hypothesis)
    _kv(lines, "confirmation_class", f.confirmation_class)
    _kv(lines, "downgrade_reason", f.downgrade_reason)
    _kv(lines, "review_status", f.review_status if f.review_status != "not_required" else None)
    _kv(lines, "reviewer", f.reviewer)
    lines.append(f"- tool_run_id: `{_na(f.tool_run_id)}`")
    lines.append(f"- validator_id: `{_na(f.validator_id)}`")
    lines.append(f"- raw_artifact_ref: `{_na(f.raw_artifact_ref)}`")
    ev = ", ".join(f"`{e}`" for e in f.evidence_ids) or "_none_"
    lines.append(f"- evidence_ids: {ev}")
    if f.description:
        lines.append("")
        lines.append(f.description)
    if f.poc is not None:
        lines.append("")
        lines.append("#### Proof of Concept")
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
            _kv(lines, label, value)
        if p.evidence_ids:
            lines.append("- evidence_ids: " + ", ".join(f"`{e}`" for e in p.evidence_ids))
    if f.remediation is not None:
        r = f.remediation
        lines.append("")
        lines.append(f"#### Remediation (LLM) — status `{r.status}`")
        for label, value in (
            ("temporary_containment", r.temporary_containment),
            ("permanent_fix", r.permanent_fix),
            ("preventive_measures", r.preventive_measures),
            ("component", r.component),
            ("rollout_order", r.rollout_order),
            ("rollback_risk", r.rollback_risk),
            ("retest_plan", r.retest_plan),
        ):
            _kv(lines, label, value)
        for i, crit in enumerate(r.acceptance_criteria, 1):
            lines.append(f"- acceptance_criteria C-{i:02d}: {crit}")
    if f.closure is not None:
        c = f.closure
        lines.append("")
        lines.append(f"#### Closure (LLM) — status `{_na(c.permitted_status)}`")
        for label, value in (
            ("what_verified", c.what_verified),
            ("what_not_verified", c.what_not_verified),
            ("residual_risk", c.residual_risk),
            ("next_step", c.next_step),
        ):
            _kv(lines, label, value)
    lines.append("")


def _render_engagement_md(lines: list[str], doc: ReportDocumentV1) -> None:
    e = doc.engagement
    if e is None:
        return
    lines.append("## Engagement Parameters")
    lines.append("")
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
            lines.append(f"- {label}: " + ", ".join(f"`{x}`" for x in seq))
    _kv(lines, "run_profile", e.run_profile)
    _kv(lines, "execution_mode", e.execution_mode)
    _kv(lines, "tool_catalog_version", e.tool_catalog_version)
    _kv(lines, "time_source", e.time_source)
    lines.append("")


def _render_methodology_md(lines: list[str], doc: ReportDocumentV1) -> None:
    if not doc.methodology:
        return
    lines.append("## Methodology")
    lines.append("")
    lines.append("| Framework | Revision | Applied | Notes |")
    lines.append("|---|---|---|---|")
    for m in doc.methodology:
        lines.append(f"| {m.framework} | {_na(m.revision)} | {m.applied} | {_na(m.notes)} |")
    lines.append("")
    lines.append(
        "> A mapping to a standard's controls is not a certification of compliance; "
        "testing does not guarantee discovery of all weaknesses."
    )
    lines.append("")


def _render_surface_md(lines: list[str], doc: ReportDocumentV1) -> None:
    if not doc.surface_inventory:
        return
    lines.append("## Attack Surface Inventory")
    lines.append("")
    lines.append("| Host | Port | Service | Version | Technology |")
    lines.append("|---|---|---|---|---|")
    for s in doc.surface_inventory:
        lines.append(
            f"| {s.host} | {_na(s.port)} | {_na(s.service)} | "
            f"{_na(s.version)} | {_na(s.technology)} |"
        )
    lines.append("")


def _render_unconfirmed_md(lines: list[str], doc: ReportDocumentV1) -> None:
    if not doc.unconfirmed_observations:
        return
    lines.append(f"## Unconfirmed Observations ({len(doc.unconfirmed_observations)})")
    lines.append("")
    for f in doc.unconfirmed_observations:
        lines.append(
            f"- `{f.finding_id}` {f.title} — `{f.severity}` / `{f.verification_status}`"
            + (f" (downgraded: {f.downgrade_reason})" if f.downgrade_reason else "")
        )
    lines.append("")


def _render_test_executions_md(lines: list[str], doc: ReportDocumentV1) -> None:
    if not doc.test_executions:
        return
    lines.append("## Executed Checks Without Findings")
    lines.append("")
    lines.append("| Test | Control | Method | Result | Executed |")
    lines.append("|---|---|---|---|---|")
    for t in doc.test_executions:
        lines.append(
            f"| `{t.test_id}` | {t.control} | {_na(t.method)} | "
            f"`{t.result}` | {_na(t.executed_at)} |"
        )
    lines.append("")


def _render_attack_narrative_md(lines: list[str], doc: ReportDocumentV1) -> None:
    if not doc.attack_narrative:
        return
    lines.append("## Attack Narrative")
    lines.append("")
    for step in sorted(doc.attack_narrative, key=lambda s: s.order_index):
        att = f" [{step.tactic}/{step.technique_id}]" if step.technique_id else ""
        refs = "".join(f" [{c}]" for c in step.claim_ids)
        lines.append(f"{step.order_index}. **{step.phase}**{att}: {step.description}{refs}")
    lines.append("")


def _render_chains_md(lines: list[str], doc: ReportDocumentV1) -> None:
    if not doc.exploit_chains:
        return
    lines.append("## Impact Chains")
    lines.append("")
    for ch in doc.exploit_chains:
        lines.append(f"### `{ch.chain_id}` {ch.title} — **{ch.kind}**")
        _kv(lines, "preconditions", ch.preconditions)
        _kv(lines, "outcome", ch.outcome)
        _kv(lines, "breaks_at", ch.breaks_at)
        for step in ch.steps:
            lines.append(f"- {step.order_index}. {step.phase}: {step.description}")
        if ch.kind == "hypothetical" and ch.to_verify:
            lines.append("- to_verify: " + "; ".join(ch.to_verify))
        lines.append("")


def _render_priority_plan_md(lines: list[str], doc: ReportDocumentV1) -> None:
    if not (doc.conclusions and doc.conclusions.priority_plan):
        return
    lines.append("## Prioritised Remediation Plan")
    lines.append("")
    for i, item in enumerate(doc.conclusions.priority_plan, 1):
        fids = item.get("finding_ids") or item.get("findings") or []
        rationale = item.get("rationale") or item.get("reason") or ""
        lines.append(f"{i}. {rationale} — findings: " + ", ".join(f"`{x}`" for x in fids))
    lines.append("")


def _render_evidence_inventory_md(lines: list[str], doc: ReportDocumentV1) -> None:
    if not doc.evidence_references:
        return
    lines.append("## Evidence Inventory")
    lines.append("")
    lines.append("| Evidence ID | Kind | Object Key | Description |")
    lines.append("|---|---|---|---|")
    for e in doc.evidence_references:
        lines.append(
            f"| `{e.evidence_id}` | {e.kind} | `{_na(e.object_key)}` | {_na(e.description)} |"
        )
    lines.append("")


def _render_client_impact_md(lines: list[str], doc: ReportDocumentV1) -> None:
    c = doc.client_impact
    if c is None:
        return
    lines.append("## Impact on Client Environment")
    lines.append("")
    for label, seq in (
        ("created_artifacts", c.created_artifacts),
        ("removed", c.removed),
        ("not_removed", c.not_removed),
    ):
        lines.append(f"- {label}: " + (", ".join(f"`{x}`" for x in seq) if seq else "_none_"))
    _kv(lines, "data_exfiltration", c.data_exfiltration)
    _kv(lines, "availability_impact", c.availability_impact)
    lines.append("")


def _render_claims_md(lines: list[str], doc: ReportDocumentV1) -> None:
    if not doc.claims:
        return
    lines.append("## Claims Ledger")
    lines.append("")
    for cl in doc.claims:
        ev = ", ".join(f"`{e}`" for e in cl.evidence_ids) or "_none_"
        lines.append(f"- `{cl.claim_id}` [{cl.claim_type}] {cl.text} — evidence: {ev}")
    lines.append("")


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

    # Report passport — independent release statuses (prompt E.2).
    lines.append("## Report Passport")
    lines.append("")
    lines.append(f"- generation_status: `{doc.generation_status}`")
    lines.append(f"- llm_analysis_status: `{doc.llm_analysis_status}`")
    lines.append(f"- assessment_completeness: `{doc.assessment_completeness}`")
    lines.append(f"- evidence_integrity: `{doc.evidence_integrity}`")
    lines.append(f"- review_status: `{doc.review_status}`")
    if doc.verification_kit_ref:
        lines.append(f"- verification_kit: `{doc.verification_kit_ref}`")
    lines.append("")

    if doc.conclusions and doc.conclusions.executive_summary:
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(doc.conclusions.executive_summary)
        lines.append("")

    _render_engagement_md(lines, doc)
    _render_methodology_md(lines, doc)
    _render_surface_md(lines, doc)

    lines.append(f"## Findings ({len(doc.findings)})")
    lines.append("")
    if not doc.findings:
        lines.append("_not_assessed — no findings in this snapshot._")
    for f in doc.findings:
        _render_finding_md(lines, f)

    _render_unconfirmed_md(lines, doc)
    _render_test_executions_md(lines, doc)
    _render_attack_narrative_md(lines, doc)
    _render_chains_md(lines, doc)

    if doc.conclusions and doc.conclusions.business_risk:
        lines.append("## Business Risk")
        lines.append("")
        lines.append(doc.conclusions.business_risk)
        lines.append("")

    _render_priority_plan_md(lines, doc)
    _render_evidence_inventory_md(lines, doc)

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

    _render_client_impact_md(lines, doc)

    if doc.conclusions and doc.conclusions.closure_summary:
        lines.append("## Closure Summary")
        lines.append("")
        lines.append(doc.conclusions.closure_summary)
        lines.append("")

    lines.append("## Limitations")
    lines.append("")
    if not doc.limitations:
        lines.append("_none_")
    for lim in doc.limitations:
        lines.append(f"- {lim}")
    lines.append("")

    _render_claims_md(lines, doc)

    if doc.validation_errors:
        lines.append("## Validation errors")
        lines.append("")
        for ve in doc.validation_errors:
            lines.append(f"- `{ve.code}` {ve.finding_id or ''}: {ve.message}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


__all__ = ["render_markdown"]
