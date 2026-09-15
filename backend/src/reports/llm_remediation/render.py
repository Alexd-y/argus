"""Format projections of the Valhalla LLM document (VH-LLM-08).

MD / HTML / XML / JSON are rendered from the single
:class:`ValhallaLlmDocument`; every format carries the same facts, both
mandatory LLM blocks per finding and the final closure summary (prompt §11).
Renderers are pure: no LLM calls, no new facts, no changed conclusions.

Also provides:

* :func:`parity_facts` / :func:`assert_semantic_parity` — the canonical fact
  token set that must appear in *every* textual format (prompt L17/§11).
* :data:`VALHALLA_LLM_XSD` + :func:`validate_valhalla_xml` — a typed XML schema
  and a validator (lxml XSD when available, else a structural check via the
  entity-safe ``defusedxml`` parser; external entities are always rejected).
"""

from __future__ import annotations

import json
from xml.etree.ElementTree import Element, SubElement, tostring

from defusedxml.ElementTree import fromstring as safe_fromstring
from markupsafe import escape

from src.reports.llm_remediation.document import ValhallaLlmDocument
from src.reports.llm_remediation.schemas import (
    FindingClosureConclusion,
    FindingRemediationAnalysis,
)

# Optional dependency: when lxml is installed we validate against the XSD;
# otherwise a structural check is used. Guarded top-level import keeps the
# module import-safe without inline imports.
try:  # pragma: no cover - availability depends on environment
    from lxml import etree as _lxml_etree
except ImportError:  # pragma: no cover
    _lxml_etree = None

VALHALLA_LLM_XML_NS = "urn:argus:valhalla-llm:v1"
VALHALLA_LLM_XML_VERSION = "1.0"

_HAS_LXML = _lxml_etree is not None


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def render_json(doc: ValhallaLlmDocument) -> str:
    """Deterministic JSON projection of the whole document."""

    return json.dumps(doc.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, indent=2)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _md_list(items: list[str], *, bullet: str = "- ") -> list[str]:
    return [f"  {bullet}{i}" for i in items] if items else ["  - —"]


def _md_remediation(rem: FindingRemediationAnalysis | None) -> list[str]:
    if rem is None:
        return ["**LLM-план устранения:** отсутствует (анализ не выполнен)."]
    lines = [
        "**LLM-план устранения:**",
        f"  - Причина ({rem.root_cause.established_or_hypothesis.value}): {rem.root_cause.text}",
        f"  - Цель: {rem.remediation_objective}",
        f"  - Статус анализа: {rem.analysis_status.value}",
        "  - Временное сдерживание:",
        *_md_list(rem.immediate_containment),
        "  - Шаги постоянного исправления:",
    ]
    for step in rem.permanent_fix_steps:
        lines.append(
            f"    - [{step.step_id}] ({step.component}) {step.action} — {step.rationale}"
            f" · критерии: {', '.join(step.acceptance_criteria_ids) or '—'}"
            f" · ссылки: {', '.join(step.source_reference_ids) or '—'}"
        )
    lines.append("  - Критерии приёмки:")
    for crit in rem.acceptance_criteria:
        lines.append(
            f"    - [{crit.criterion_id}] {crit.measurable_property} · evidence: {crit.required_evidence}"
        )
    lines.append("  - План ретеста:")
    for test in rem.retest_plan:
        lines.append(
            f"    - [{test.test_id}] {test.procedure} → ожидается: {test.expected_secure_result}"
            f" · критерии: {', '.join(test.criteria_ids) or '—'}"
        )
    if rem.missing_information:
        lines.append("  - Недостающая информация:")
        lines.extend(_md_list(rem.missing_information))
    owner = rem.assigned_owner or rem.suggested_owner or "—"
    deadline = rem.agreed_deadline or rem.suggested_deadline or "—"
    lines.append(f"  - Владелец/срок: {owner} / {deadline}")
    return lines


def _md_closure(clo: FindingClosureConclusion | None) -> list[str]:
    if clo is None:
        return ["**LLM-вывод по закрытию:** отсутствует (анализ не выполнен)."]
    return [
        "**LLM-вывод по закрытию:**",
        f"  - Допустимый статус: {clo.permitted_closure_status.value}",
        f"  - Вывод: {clo.conclusion_text}",
        f"  - Подтверждённые критерии: {', '.join(clo.satisfied_criteria_ids) or '—'}",
        f"  - Не подтверждено: {', '.join(clo.unsatisfied_criteria_ids) or '—'}",
        f"  - Не проверено: {', '.join(clo.untested_criteria_ids) or '—'}",
        f"  - Ретесты: {', '.join(clo.supporting_retest_ids) or '—'}",
        f"  - Evidence: {', '.join(clo.supporting_evidence_ids) or '—'}",
        f"  - Остаточный риск: {clo.residual_risk}",
        f"  - Дальнейшие шаги: {', '.join(clo.next_actions) or '—'}",
        f"  - Blockers: {', '.join(clo.blockers) or '—'}",
    ]


def render_markdown(doc: ValhallaLlmDocument) -> str:
    lines: list[str] = [
        "# Valhalla — устранение и закрытие уязвимостей",
        "",
        f"- Отчёт: {doc.report_id} (версия {doc.report_version})",
        f"- Цель: {doc.target}",
        f"- Snapshot: {doc.canonical_snapshot_hash or '—'} · content_hash: {doc.content_hash}",
        f"- Полнота LLM-анализа: {doc.assessment_completeness.value}",
        "",
        "## Находки",
        "",
    ]
    for node in doc.findings:
        lines.append(
            f"### Находка {node.finding_id} — {node.title} "
            f"[{node.severity}/{node.verification_status}] "
            f"(анализ: {node.llm_analysis_status})"
        )
        lines.extend(_md_remediation(node.remediation))
        lines.append("")
        lines.extend(_md_closure(node.closure))
        lines.append("")

    lines.append("## Итоговые выводы по устранению и закрытию уязвимостей")
    if doc.summary is not None:
        s = doc.summary
        lines.append(f"- Общий вывод: {s.overall_conclusion}")
        lines.append(f"- Подтверждённо закрыты: {', '.join(s.verified_closed_finding_ids) or '—'}")
        lines.append(f"- Не подтверждены: {', '.join(s.not_verified_closed_finding_ids) or '—'}")
        lines.append(f"- Принятый риск: {', '.join(s.accepted_risk_finding_ids) or '—'}")
        lines.append("- Счётчики:")
        for key, value in sorted(s.exact_counts_by_verification_and_remediation_status.items()):
            lines.append(f"  - {key}: {value}")
        if s.priority_actions:
            lines.append("- Приоритетные действия:")
            for act in s.priority_actions:
                lines.append(
                    f"  - [{act.action_id}] {act.rationale} · находки: {', '.join(act.finding_ids)}"
                )
    else:
        lines.append("- Итоговый LLM-вывод недоступен (анализ неполон).")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# HTML (payload rendered as text, never executed)
# ---------------------------------------------------------------------------


def _h(value: object) -> str:
    return str(escape("" if value is None else str(value)))


def _html_kv(label: str, value: object) -> str:
    return f'<div class="kv"><span class="k">{_h(label)}</span>: <span class="v">{_h(value)}</span></div>'


def render_html(doc: ValhallaLlmDocument) -> str:
    parts: list[str] = [
        "<!DOCTYPE html>",
        f'<html lang="{_h(doc.locale)}"><head><meta charset="utf-8">',
        "<title>Valhalla — устранение и закрытие</title></head><body>",
        "<h1>Valhalla — устранение и закрытие уязвимостей</h1>",
        _html_kv("Отчёт", f"{doc.report_id} (версия {doc.report_version})"),
        _html_kv("Цель", doc.target),
        _html_kv("content_hash", doc.content_hash),
        _html_kv("Полнота LLM-анализа", doc.assessment_completeness.value),
        "<h2>Находки</h2>",
    ]
    for node in doc.findings:
        parts.append(f'<section class="finding" data-finding-id="{_h(node.finding_id)}">')
        parts.append(
            f"<h3>Находка {_h(node.finding_id)} — {_h(node.title)} "
            f"[{_h(node.severity)}/{_h(node.verification_status)}] "
            f"(анализ: {_h(node.llm_analysis_status)})</h3>"
        )
        parts.append('<div class="remediation">')
        if node.remediation is not None:
            rem = node.remediation
            parts.append("<h4>LLM-план устранения</h4>")
            parts.append(_html_kv("Причина", rem.root_cause.text))
            parts.append(_html_kv("Цель", rem.remediation_objective))
            parts.append("<ol>")
            for step in rem.permanent_fix_steps:
                parts.append(
                    f'<li data-step-id="{_h(step.step_id)}">[{_h(step.step_id)}] '
                    f"({_h(step.component)}) {_h(step.action)} — {_h(step.rationale)}</li>"
                )
            parts.append("</ol>")
            parts.append("<ul>")
            for crit in rem.acceptance_criteria:
                parts.append(
                    f'<li data-criterion-id="{_h(crit.criterion_id)}">'
                    f"[{_h(crit.criterion_id)}] {_h(crit.measurable_property)}</li>"
                )
            for test in rem.retest_plan:
                parts.append(
                    f'<li data-test-id="{_h(test.test_id)}">[{_h(test.test_id)}] '
                    f"{_h(test.procedure)} → {_h(test.expected_secure_result)}</li>"
                )
            parts.append("</ul>")
        else:
            parts.append("<p>LLM-план устранения отсутствует (анализ не выполнен).</p>")
        parts.append("</div>")

        parts.append('<div class="closure">')
        if node.closure is not None:
            clo = node.closure
            parts.append("<h4>LLM-вывод по закрытию</h4>")
            parts.append(_html_kv("Допустимый статус", clo.permitted_closure_status.value))
            parts.append(_html_kv("Вывод", clo.conclusion_text))
            parts.append(_html_kv("Подтверждено", ", ".join(clo.satisfied_criteria_ids) or "—"))
            parts.append(
                _html_kv("Не подтверждено", ", ".join(clo.unsatisfied_criteria_ids) or "—")
            )
            parts.append(_html_kv("Не проверено", ", ".join(clo.untested_criteria_ids) or "—"))
            parts.append(_html_kv("Ретесты", ", ".join(clo.supporting_retest_ids) or "—"))
            parts.append(_html_kv("Evidence", ", ".join(clo.supporting_evidence_ids) or "—"))
            parts.append(_html_kv("Остаточный риск", clo.residual_risk))
        else:
            parts.append("<p>LLM-вывод по закрытию отсутствует (анализ не выполнен).</p>")
        parts.append("</div></section>")

    parts.append("<h2>Итоговые выводы по устранению и закрытию уязвимостей</h2>")
    if doc.summary is not None:
        s = doc.summary
        parts.append(_html_kv("Общий вывод", s.overall_conclusion))
        parts.append(
            _html_kv("Подтверждённо закрыты", ", ".join(s.verified_closed_finding_ids) or "—")
        )
        parts.append(
            _html_kv("Не подтверждены", ", ".join(s.not_verified_closed_finding_ids) or "—")
        )
        parts.append(_html_kv("Принятый риск", ", ".join(s.accepted_risk_finding_ids) or "—"))
    else:
        parts.append("<p>Итоговый LLM-вывод недоступен (анализ неполон).</p>")
    parts.append("</body></html>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# XML (typed elements; no CDATA blob; entity-safe)
# ---------------------------------------------------------------------------


def _xtext(parent: Element, tag: str, value: object) -> Element:
    el = SubElement(parent, tag)
    el.text = "" if value is None else str(value)
    return el


def _xlist(parent: Element, wrapper: str, item_tag: str, values: list[str]) -> None:
    wrap = SubElement(parent, wrapper)
    for value in values:
        _xtext(wrap, item_tag, value)


def _xml_remediation(parent: Element, rem: FindingRemediationAnalysis) -> None:
    ra = SubElement(parent, "remediation-analysis")
    ra.set("status", rem.analysis_status.value)
    rc = SubElement(ra, "root-cause")
    rc.set("basis", rem.root_cause.established_or_hypothesis.value)
    _xtext(rc, "text", rem.root_cause.text)
    _xtext(ra, "objective", rem.remediation_objective)
    steps = SubElement(ra, "fix-steps")
    for step in rem.permanent_fix_steps:
        se = SubElement(steps, "fix-step")
        se.set("step_id", step.step_id)
        _xtext(se, "component", step.component)
        _xtext(se, "action", step.action)
        _xtext(se, "rationale", step.rationale)
        _xlist(se, "acceptance-criteria-ids", "criterion-id", step.acceptance_criteria_ids)
        _xlist(se, "source-reference-ids", "reference-id", step.source_reference_ids)
    crits = SubElement(ra, "acceptance-criteria")
    for crit in rem.acceptance_criteria:
        ce = SubElement(crits, "criterion")
        ce.set("criterion_id", crit.criterion_id)
        _xtext(ce, "measurable-property", crit.measurable_property)
        _xtext(ce, "required-evidence", crit.required_evidence)
    tests = SubElement(ra, "retest-plan")
    for test in rem.retest_plan:
        te = SubElement(tests, "retest")
        te.set("test_id", test.test_id)
        _xtext(te, "procedure", test.procedure)
        _xtext(te, "expected-secure-result", test.expected_secure_result)
        _xlist(te, "criteria-ids", "criterion-id", test.criteria_ids)
    _xlist(ra, "missing-information", "item", rem.missing_information)


def _xml_closure(parent: Element, clo: FindingClosureConclusion) -> None:
    cc = SubElement(parent, "closure-conclusion")
    cc.set("status", clo.permitted_closure_status.value)
    _xtext(cc, "text", clo.conclusion_text)
    _xlist(cc, "satisfied-criteria", "criterion-id", clo.satisfied_criteria_ids)
    _xlist(cc, "unsatisfied-criteria", "criterion-id", clo.unsatisfied_criteria_ids)
    _xlist(cc, "untested-criteria", "criterion-id", clo.untested_criteria_ids)
    _xlist(cc, "supporting-retests", "retest-id", clo.supporting_retest_ids)
    _xlist(cc, "supporting-evidence", "evidence-id", clo.supporting_evidence_ids)
    _xtext(cc, "residual-risk", clo.residual_risk)
    _xlist(cc, "next-actions", "action", clo.next_actions)
    _xlist(cc, "blockers", "blocker", clo.blockers)


def render_xml(doc: ValhallaLlmDocument) -> str:
    root = Element("valhalla-llm-report")
    root.set("xmlns", VALHALLA_LLM_XML_NS)
    root.set("version", VALHALLA_LLM_XML_VERSION)
    root.set("doc_version", doc.doc_version)
    root.set("content_hash", doc.content_hash)
    root.set("assessment_completeness", doc.assessment_completeness.value)

    meta = SubElement(root, "meta")
    _xtext(meta, "report-id", doc.report_id)
    _xtext(meta, "report-version", doc.report_version)
    _xtext(meta, "target", doc.target)
    _xtext(meta, "canonical-snapshot-hash", doc.canonical_snapshot_hash)

    findings = SubElement(root, "findings")
    findings.set("count", str(len(doc.findings)))
    for node in doc.findings:
        fe = SubElement(findings, "finding")
        fe.set("finding_id", node.finding_id)
        fe.set("severity", node.severity)
        fe.set("verification_status", node.verification_status)
        fe.set("llm_analysis_status", node.llm_analysis_status)
        _xtext(fe, "title", node.title)
        if node.remediation is not None:
            _xml_remediation(fe, node.remediation)
        if node.closure is not None:
            _xml_closure(fe, node.closure)

    summary = SubElement(root, "closure-summary")
    if doc.summary is not None:
        s = doc.summary
        _xtext(summary, "overall-conclusion", s.overall_conclusion)
        _xlist(summary, "verified-closed", "finding-id", s.verified_closed_finding_ids)
        _xlist(summary, "not-verified-closed", "finding-id", s.not_verified_closed_finding_ids)
        _xlist(summary, "accepted-risk", "finding-id", s.accepted_risk_finding_ids)
        counts = SubElement(summary, "counts")
        for key, value in sorted(s.exact_counts_by_verification_and_remediation_status.items()):
            ce = SubElement(counts, "count")
            ce.set("key", key)
            ce.text = str(value)

    return tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")


# ---------------------------------------------------------------------------
# Semantic parity
# ---------------------------------------------------------------------------


def parity_facts(doc: ValhallaLlmDocument) -> set[str]:
    """Canonical fact tokens that must appear in every textual format."""

    facts: set[str] = set()
    for node in doc.findings:
        facts.add(node.finding_id)
        if node.closure is not None:
            facts.add(node.closure.permitted_closure_status.value)
            facts.update(node.closure.satisfied_criteria_ids)
            facts.update(node.closure.supporting_retest_ids)
        if node.remediation is not None:
            facts.update(s.step_id for s in node.remediation.permanent_fix_steps)
            facts.update(c.criterion_id for c in node.remediation.acceptance_criteria)
            facts.update(t.test_id for t in node.remediation.retest_plan)
    if doc.summary is not None:
        facts.update(doc.summary.verified_closed_finding_ids)
    # Drop empty tokens.
    return {f for f in facts if f}


def assert_semantic_parity(
    doc: ValhallaLlmDocument, rendered: dict[str, str]
) -> dict[str, list[str]]:
    """Return, per format, the list of missing fact tokens (empty == parity)."""

    facts = parity_facts(doc)
    missing: dict[str, list[str]] = {}
    for fmt, text in rendered.items():
        gaps = sorted(fact for fact in facts if fact not in text)
        if gaps:
            missing[fmt] = gaps
    return missing


# ---------------------------------------------------------------------------
# XSD + validation
# ---------------------------------------------------------------------------

VALHALLA_LLM_XSD = """<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns="urn:argus:valhalla-llm:v1"
           targetNamespace="urn:argus:valhalla-llm:v1"
           elementFormDefault="qualified">

  <!-- Generic id/text list wrappers -->
  <xs:complexType name="CriterionIdList">
    <xs:sequence>
      <xs:element name="criterion-id" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="ReferenceIdList">
    <xs:sequence>
      <xs:element name="reference-id" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="RetestIdList">
    <xs:sequence>
      <xs:element name="retest-id" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="EvidenceIdList">
    <xs:sequence>
      <xs:element name="evidence-id" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="FindingIdList">
    <xs:sequence>
      <xs:element name="finding-id" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="ItemList">
    <xs:sequence>
      <xs:element name="item" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="ActionList">
    <xs:sequence>
      <xs:element name="action" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="BlockerList">
    <xs:sequence>
      <xs:element name="blocker" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>

  <xs:complexType name="RootCauseType">
    <xs:sequence>
      <xs:element name="text" type="xs:string"/>
    </xs:sequence>
    <xs:attribute name="basis" type="xs:string" use="required"/>
  </xs:complexType>

  <xs:complexType name="FixStepType">
    <xs:sequence>
      <xs:element name="component" type="xs:string"/>
      <xs:element name="action" type="xs:string"/>
      <xs:element name="rationale" type="xs:string"/>
      <xs:element name="acceptance-criteria-ids" type="CriterionIdList"/>
      <xs:element name="source-reference-ids" type="ReferenceIdList"/>
    </xs:sequence>
    <xs:attribute name="step_id" type="xs:string" use="required"/>
  </xs:complexType>
  <xs:complexType name="FixStepsType">
    <xs:sequence>
      <xs:element name="fix-step" type="FixStepType" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>

  <xs:complexType name="CriterionType">
    <xs:sequence>
      <xs:element name="measurable-property" type="xs:string"/>
      <xs:element name="required-evidence" type="xs:string"/>
    </xs:sequence>
    <xs:attribute name="criterion_id" type="xs:string" use="required"/>
  </xs:complexType>
  <xs:complexType name="AcceptanceCriteriaType">
    <xs:sequence>
      <xs:element name="criterion" type="CriterionType" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>

  <xs:complexType name="RetestType">
    <xs:sequence>
      <xs:element name="procedure" type="xs:string"/>
      <xs:element name="expected-secure-result" type="xs:string"/>
      <xs:element name="criteria-ids" type="CriterionIdList"/>
    </xs:sequence>
    <xs:attribute name="test_id" type="xs:string" use="required"/>
  </xs:complexType>
  <xs:complexType name="RetestPlanType">
    <xs:sequence>
      <xs:element name="retest" type="RetestType" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>

  <xs:complexType name="RemediationType">
    <xs:sequence>
      <xs:element name="root-cause" type="RootCauseType"/>
      <xs:element name="objective" type="xs:string"/>
      <xs:element name="fix-steps" type="FixStepsType"/>
      <xs:element name="acceptance-criteria" type="AcceptanceCriteriaType"/>
      <xs:element name="retest-plan" type="RetestPlanType"/>
      <xs:element name="missing-information" type="ItemList"/>
    </xs:sequence>
    <xs:attribute name="status" type="xs:string" use="required"/>
  </xs:complexType>

  <xs:complexType name="ClosureType">
    <xs:sequence>
      <xs:element name="text" type="xs:string"/>
      <xs:element name="satisfied-criteria" type="CriterionIdList"/>
      <xs:element name="unsatisfied-criteria" type="CriterionIdList"/>
      <xs:element name="untested-criteria" type="CriterionIdList"/>
      <xs:element name="supporting-retests" type="RetestIdList"/>
      <xs:element name="supporting-evidence" type="EvidenceIdList"/>
      <xs:element name="residual-risk" type="xs:string"/>
      <xs:element name="next-actions" type="ActionList"/>
      <xs:element name="blockers" type="BlockerList"/>
    </xs:sequence>
    <xs:attribute name="status" type="xs:string" use="required"/>
  </xs:complexType>

  <xs:complexType name="FindingType">
    <xs:sequence>
      <xs:element name="title" type="xs:string"/>
      <xs:element name="remediation-analysis" type="RemediationType" minOccurs="0"/>
      <xs:element name="closure-conclusion" type="ClosureType" minOccurs="0"/>
    </xs:sequence>
    <xs:attribute name="finding_id" type="xs:string" use="required"/>
    <xs:attribute name="severity" type="xs:string"/>
    <xs:attribute name="verification_status" type="xs:string"/>
    <xs:attribute name="llm_analysis_status" type="xs:string"/>
  </xs:complexType>
  <xs:complexType name="FindingsType">
    <xs:sequence>
      <xs:element name="finding" type="FindingType" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
    <xs:attribute name="count" type="xs:string"/>
  </xs:complexType>

  <xs:complexType name="MetaType">
    <xs:sequence>
      <xs:element name="report-id" type="xs:string"/>
      <xs:element name="report-version" type="xs:string"/>
      <xs:element name="target" type="xs:string"/>
      <xs:element name="canonical-snapshot-hash" type="xs:string"/>
    </xs:sequence>
  </xs:complexType>

  <xs:complexType name="CountType">
    <xs:simpleContent>
      <xs:extension base="xs:string">
        <xs:attribute name="key" type="xs:string" use="required"/>
      </xs:extension>
    </xs:simpleContent>
  </xs:complexType>
  <xs:complexType name="CountsType">
    <xs:sequence>
      <xs:element name="count" type="CountType" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="SummaryType">
    <xs:sequence>
      <xs:element name="overall-conclusion" type="xs:string" minOccurs="0"/>
      <xs:element name="verified-closed" type="FindingIdList" minOccurs="0"/>
      <xs:element name="not-verified-closed" type="FindingIdList" minOccurs="0"/>
      <xs:element name="accepted-risk" type="FindingIdList" minOccurs="0"/>
      <xs:element name="counts" type="CountsType" minOccurs="0"/>
    </xs:sequence>
  </xs:complexType>

  <xs:complexType name="ReportType">
    <xs:sequence>
      <xs:element name="meta" type="MetaType"/>
      <xs:element name="findings" type="FindingsType"/>
      <xs:element name="closure-summary" type="SummaryType"/>
    </xs:sequence>
    <xs:attribute name="version" type="xs:string" use="required"/>
    <xs:attribute name="doc_version" type="xs:string" use="required"/>
    <xs:attribute name="content_hash" type="xs:string" use="required"/>
    <xs:attribute name="assessment_completeness" type="xs:string" use="required"/>
  </xs:complexType>

  <xs:element name="valhalla-llm-report" type="ReportType"/>
</xs:schema>
"""

_REQUIRED_ROOT_ATTRS = ("version", "doc_version", "content_hash", "assessment_completeness")
_REQUIRED_CHILDREN = ("meta", "findings", "closure-summary")


def validate_valhalla_xml(xml_str: str) -> list[str]:
    """Validate the Valhalla XML. Returns a list of error strings ([] == valid).

    Uses lxml XSD validation when available; otherwise performs a structural
    check with the entity-safe parser (external entities are always rejected,
    prompt §11 "XML parser для валидации не разрешает внешние entities").
    """

    errors: list[str] = []
    try:
        root = safe_fromstring(xml_str)
    except Exception as exc:  # any parse/entity failure is reported as a validation error
        return [f"parse_error: {exc}"]

    # Namespace-agnostic local tag (ElementTree prefixes with {ns}).
    local = root.tag.split("}")[-1]
    if local != "valhalla-llm-report":
        errors.append(f"unexpected_root: {local}")
    for attr in _REQUIRED_ROOT_ATTRS:
        if root.get(attr) in (None, ""):
            errors.append(f"missing_root_attr: {attr}")
    child_locals = {child.tag.split("}")[-1] for child in root}
    for required in _REQUIRED_CHILDREN:
        if required not in child_locals:
            errors.append(f"missing_child: {required}")

    if _HAS_LXML:
        errors.extend(_lxml_xsd_errors(xml_str))
    return errors


def _lxml_xsd_errors(xml_str: str) -> list[str]:  # pragma: no cover - exercised only with lxml
    etree = _lxml_etree
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    schema = etree.XMLSchema(etree.fromstring(VALHALLA_LLM_XSD.encode("utf-8")))
    doc = etree.fromstring(xml_str.encode("utf-8"), parser)
    if not schema.validate(doc):
        return [str(e.message) for e in schema.error_log]
    return []


def render_all_text_formats(doc: ValhallaLlmDocument) -> dict[str, str]:
    """Render every textual format from the one document (json/md/xml/html)."""

    return {
        "json": render_json(doc),
        "md": render_markdown(doc),
        "xml": render_xml(doc),
        "html": render_html(doc),
    }


__all__ = [
    "VALHALLA_LLM_XML_NS",
    "VALHALLA_LLM_XML_VERSION",
    "VALHALLA_LLM_XSD",
    "assert_semantic_parity",
    "parity_facts",
    "render_all_text_formats",
    "render_html",
    "render_json",
    "render_markdown",
    "render_xml",
    "validate_valhalla_xml",
]
