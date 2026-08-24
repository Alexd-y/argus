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
