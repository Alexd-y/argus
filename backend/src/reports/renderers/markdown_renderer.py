"""Markdown renderer — human-readable projection of the snapshot.

Every finding id, severity, evidence id, coverage capability, limitation and the
snapshot hash appears verbatim so the format stays semantically equivalent to
JSON/XML (parity test asserts this).
"""

from __future__ import annotations

from src.reports.report_document import ReportDocumentV1


def _na(value: object) -> str:
    return "not_assessed" if value in (None, "") else str(value)


def _esc_md(value: object) -> str:
    """Escape Markdown-significant chars in an inline value (C-28 §7.4)."""
    text = str(value)
    for ch in ("\\", "`", "|", "*", "_", "<"):
        text = text.replace(ch, "\\" + ch)
    return text.replace("\n", " ")


def _kv(lines: list[str], label: str, value: object) -> None:
    if value not in (None, "", [], {}):
        lines.append(f"- {label}: `{value}`")


def _cvss_cell(f) -> str | None:  # noqa: ANN001 - ReportFinding
    """CVSS table cell: score + vector, or a heuristic marker; None when absent (C-20/C-27)."""
    score = f.cvss_score
    if score is None:
        return None
    if f.cvss_vector:
        ver = f.cvss_version or "CVSS"
        return f"{score} ({ver}/{f.cvss_vector})" if ":" not in str(f.cvss_vector) else f"{score} ({f.cvss_vector})"
    return f"{score} (severity_basis: heuristic — no vector)"


def _asset_cell(f) -> str | None:  # noqa: ANN001 - ReportFinding
    host = f.asset or f.url
    if not host:
        return None
    parts = str(host)
    if f.port:
        parts += f":{f.port}"
    if f.scheme:
        parts += f" ({f.scheme})"
    return parts


def _render_finding_md(lines: list[str], f, index: int) -> None:  # noqa: ANN001 - ReportFinding
    """Reference-layout finding card (C-28): identity, metrics table, narrative, PoC, plan.

    No ``not_assessed`` filler rows and no internal storage paths (C-29): a field with
    no value is omitted, and its absence is accounted for in the completeness section.
    """
    lines.append(
        f"### {index:02d} · {f.severity.upper()} · {f.verification_status} — {_esc_md(f.title)}"
    )
    lines.append(f"`{f.finding_id}`")
    lines.append("")
    # Metrics table — only rows that carry a value.
    lines.append("| | |")
    lines.append("|---|---|")
    cvss = _cvss_cell(f)
    if cvss:
        lines.append(f"| CVSS | {cvss} |")
    if f.cwe:
        lines.append(f"| CWE | {_esc_md(f.cwe)} |")
    lines.append(f"| OWASP | {_esc_md(f.owasp_category) if f.owasp_category else 'не сопоставлено'} |")
    asset = _asset_cell(f)
    if asset:
        lines.append(f"| Актив | {_esc_md(asset)} |")
    lines.append(f"| Статус верификации | {f.verification_status} |")
    lines.append(f"| Уверенность | {f.confidence:.2f} |")
    if f.confirmation_class:
        lines.append(f"| Класс | {_esc_md(f.confirmation_class)} |")
    if f.downgrade_reason:
        lines.append(f"| Понижение | {_esc_md(f.downgrade_reason)} |")
    if f.review_status and f.review_status != "not_required":
        lines.append(
            f"| Ревью | {f.review_status}{(' · ' + _esc_md(f.reviewer)) if f.reviewer else ''} |"
        )
    if f.evidence_ids:
        lines.append("| Evidence | " + ", ".join(f"`{e}`" for e in f.evidence_ids) + " |")
    lines.append("")
    if f.description:
        lines.append(f"**Что обнаружено.** {_esc_md(f.description)}")
    impact = f.observed_impact or f.potential_impact
    if impact:
        lines.append(f"**Почему это важно.** {_esc_md(impact)}")
    if f.description or impact:
        lines.append("")
    if f.poc is not None:
        lines.append("#### Доказательство")
        p = f.poc
        for label, value in (
            ("Предпосылки", p.preconditions),
            ("Инструмент", p.tool),
            ("Payload", p.payload),
            ("Команда", p.command),
            ("HTTP-запрос", p.http_request),
            ("HTTP-ответ", p.http_response),
            ("Дискриминатор", p.discriminator),
            ("Негативный контроль", p.negative_control),
            ("Канарейка", p.canary),
            ("Наблюдение", p.observation),
            ("OAST", p.oast_callback),
            ("Наблюдаемое воздействие", p.observed_impact),
            ("Потенциальное воздействие", p.potential_impact),
            ("Blast radius", p.blast_radius),
            ("Время", p.timing),
            ("Источник", p.source),
            ("Попытки", p.attempts),
            ("Воспроизводимость", p.reproducibility),
        ):
            if value not in (None, ""):
                lines.append(f"- {label}: {_esc_md(value)}")
        if p.evidence_ids:
            lines.append("- Evidence: " + ", ".join(f"`{e}`" for e in p.evidence_ids))
    if f.remediation is not None:
        r = f.remediation
        lines.append("")
        lines.append(f"#### План устранения (LLM · {r.status})")
        for label, value in (
            ("Сдерживание", r.temporary_containment),
            ("Исправление", r.permanent_fix),
            ("Превентивные меры", r.preventive_measures),
            ("Компонент", r.component),
            ("Порядок внедрения", r.rollout_order),
            ("Риск отката", r.rollback_risk),
            ("Ретест", r.retest_plan),
        ):
            if value not in (None, ""):
                lines.append(f"- {label}: {_esc_md(value)}")
        if r.acceptance_criteria:
            lines.append("")
            lines.append("#### Критерии приёмки")
            for i, crit in enumerate(r.acceptance_criteria, 1):
                lines.append(f"- C-{i:02d}: {_esc_md(crit)}")
    if f.closure is not None:
        c = f.closure
        lines.append("")
        lines.append(f"#### Вывод о закрытии (LLM · {_na(c.permitted_status)})")
        for label, value in (
            ("Проверено", c.what_verified),
            ("Не проверено", c.what_not_verified),
            ("Остаточный риск", c.residual_risk),
            ("Следующий шаг", c.next_step),
        ):
            if value not in (None, ""):
                lines.append(f"- {label}: {_esc_md(value)}")
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
    # Passport scalars — print only what was actually recorded (no not_assessed spam).
    for label, value in (
        ("scan_profile", doc.scan_profile),
        ("resolved_scan_mode", doc.resolved_scan_mode),
        ("execution_mode", doc.execution_mode),
        ("nuclei_profile", doc.nuclei_profile),
        ("started_at", doc.started_at),
        ("completed_at", doc.completed_at),
    ):
        if value not in (None, ""):
            lines.append(f"- {label}: `{value}`")
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
    for i, f in enumerate(doc.findings, 1):
        _render_finding_md(lines, f, i)

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
