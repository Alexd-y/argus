"""XML renderer — structured, round-trippable projection of the snapshot."""

from __future__ import annotations

from xml.etree.ElementTree import Element, SubElement, tostring

from src.reports.report_document import ReportDocumentV1


def _text(parent: Element, tag: str, value: object) -> Element:
    el = SubElement(parent, tag)
    el.text = "" if value is None else str(value)
    return el


def render_xml(doc: ReportDocumentV1) -> str:
    root = Element("argus_report")
    root.set("schema_version", doc.schema_version)
    root.set("snapshot_hash", doc.snapshot_hash)

    meta = SubElement(root, "meta")
    for tag in (
        "scan_id",
        "tenant_id",
        "target",
        "scan_profile",
        "resolved_scan_mode",
        "execution_mode",
        "quick_profile",
        "nuclei_profile",
        "started_at",
        "completed_at",
        "generated_at",
    ):
        _text(meta, tag, getattr(doc, tag))

    findings_el = SubElement(root, "findings")
    findings_el.set("count", str(len(doc.findings)))
    for f in doc.findings:
        fe = SubElement(findings_el, "finding")
        fe.set("finding_id", f.finding_id)
        fe.set("severity", f.severity)
        fe.set("verification_status", f.verification_status)
        fe.set("confidence", f"{f.confidence:.4f}")
        _text(fe, "title", f.title)
        _text(fe, "category", f.category)
        _text(fe, "cwe", f.cwe)
        _text(fe, "description", f.description)
        _text(fe, "tool_run_id", f.tool_run_id)
        _text(fe, "validator_id", f.validator_id)
        _text(fe, "raw_artifact_ref", f.raw_artifact_ref)
        ev = SubElement(fe, "evidence_ids")
        for eid in f.evidence_ids:
            _text(ev, "evidence_id", eid)

    tools_el = SubElement(root, "tool_runs")
    for t in doc.tool_runs:
        te = SubElement(tools_el, "tool_run")
        te.set("tool_run_id", t.tool_run_id)
        te.set("tool_name", t.tool_name)
        te.set("status", t.status)
        _text(te, "parser_status", t.parser_status)
        _text(te, "raw_artifact_ref", t.raw_artifact_ref)

    cov_el = SubElement(root, "coverage")
    for c in doc.coverage:
        ce = SubElement(cov_el, "capability")
        ce.set("capability_id", c.capability_id)
        ce.set("status", c.status)
        _text(ce, "reason_code", c.reason_code)

    ev_refs = SubElement(root, "evidence_references")
    for e in doc.evidence_references:
        ee = SubElement(ev_refs, "evidence")
        ee.set("evidence_id", e.evidence_id)
        ee.set("kind", e.kind)
        _text(ee, "object_key", e.object_key)

    if doc.wstg:
        w = doc.wstg
        we = SubElement(root, "wstg")
        we.set("version", str(w.get("wstg_version", "")))
        we.set("policy_version", str(w.get("policy_version", "")))
        we.set(
            "schema_version",
            "" if w.get("schema_version") is None else str(w.get("schema_version")),
        )
        we.set("legacy_unverified", "true" if w.get("schema_version") is None else "false")
        we.set("applicability_rules_version", str(w.get("applicability_rules_version", "")))
        we.set("scenario_registry_version", str(w.get("scenario_registry_version", "")))
        we.set("coverage_pct", "" if w.get("coverage_pct") is None else str(w.get("coverage_pct")))
        we.set("assessment_status", str(w.get("assessment_status", "")))
        we.set("coverage_gate_passed", str(w.get("coverage_gate_passed", "")))
        we.set("evidence_integrity_passed", str(w.get("evidence_integrity_passed", "")))
        we.set("gate_passed", str(w.get("gate_passed", "")))  # deprecated
        for tag in (
            "threshold",
            "catalog_total",
            "in_scope_total",
            "denominator",
            "validated_not_applicable",
            "out_of_scope",
            "unknown_applicability",
            "counted",
            "completed_pass",
            "completed_fail",
            "partial",
            "blocked",
            "failed",
            "running",
            "not_started",
            "inconclusive",
        ):
            _text(we, tag, w.get(tag))
        ierrs_el = SubElement(we, "integrity_errors")
        for err in w.get("integrity_errors") or []:
            if isinstance(err, dict):
                iee = SubElement(ierrs_el, "integrity_error")
                iee.set("code", str(err.get("code", "")))
                iee.set("test_id", str(err.get("test_id", "")))
                _text(iee, "detail", err.get("detail"))
            else:
                _text(ierrs_el, "integrity_error", err)

    fails = SubElement(root, "failures")
    for fl in doc.failures:
        fle = SubElement(fails, "failure")
        fle.set("where", fl.where)
        fle.set("reason_code", fl.reason_code)
        _text(fle, "message", fl.message)

    limits_el = SubElement(root, "limitations")
    for lim in doc.limitations:
        _text(limits_el, "limitation", lim)

    verr_el = SubElement(root, "validation_errors")
    for ve in doc.validation_errors:
        vee = SubElement(verr_el, "validation_error")
        vee.set("code", ve.code)
        _text(vee, "finding_id", ve.finding_id)
        _text(vee, "message", ve.message)

    xml_bytes = tostring(root, encoding="utf-8", xml_declaration=True)
    return xml_bytes.decode("utf-8")


__all__ = ["render_xml"]
