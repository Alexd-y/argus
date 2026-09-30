"""XML renderer — structured, round-trippable projection of the snapshot."""

from __future__ import annotations

from xml.etree.ElementTree import Element, SubElement, tostring

from src.reports.report_document import ReportDocumentV1

#: Canonical Valhalla report XML namespace (registered alongside urn:argus:valhalla-llm:v1).
VALHALLA_REPORT_XML_NS = "urn:argus:valhalla-report:v2"
_XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"


def _text(parent: Element, tag: str, value: object) -> Element:
    """Emit ``<tag>value</tag>``; for ``None`` emit ``<tag xsi:nil="true"/>`` (C-26).

    This distinguishes "not defined" (nil) from an empty string, so a consumer can
    tell a genuinely absent value from a present-but-empty one.
    """
    el = SubElement(parent, tag)
    if value is None:
        el.set("xsi:nil", "true")
    else:
        el.text = str(value)
    return el


def render_xml(doc: ReportDocumentV1) -> str:
    root = Element("argus_report")
    root.set("xmlns", VALHALLA_REPORT_XML_NS)
    root.set("xmlns:xsi", _XSI_NS)
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
        _text(fe, "owasp_category", f.owasp_category)
        _text(fe, "cvss_version", f.cvss_version)
        _text(fe, "cvss_vector", f.cvss_vector)
        _text(fe, "cvss_score", f.cvss_score)
        _text(fe, "established_or_hypothesis", f.established_or_hypothesis)
        _text(fe, "confirmation_class", f.confirmation_class)
        _text(fe, "downgrade_reason", f.downgrade_reason)
        _text(fe, "review_status", f.review_status)
        _text(fe, "reviewer", f.reviewer)
        ev = SubElement(fe, "evidence_ids")
        for eid in f.evidence_ids:
            _text(ev, "evidence_id", eid)
        if f.poc is not None:
            pe = SubElement(fe, "proof_of_concept")
            for tag in (
                "preconditions",
                "tool",
                "payload",
                "command",
                "http_request",
                "http_response",
                "discriminator",
                "negative_control",
                "canary",
                "observation",
                "oast_callback",
                "observed_impact",
                "potential_impact",
                "blast_radius",
                "timing",
                "source",
                "attempts",
                "reproducibility",
                "cleanup",
                "client_repro",
                "screenshot_ref",
            ):
                _text(pe, tag, getattr(f.poc, tag))
            pev = SubElement(pe, "evidence_ids")
            for eid in f.poc.evidence_ids:
                _text(pev, "evidence_id", eid)
        if f.remediation is not None:
            re_ = SubElement(fe, "remediation")
            re_.set("status", f.remediation.status)
            for tag in (
                "established_or_hypothesis",
                "temporary_containment",
                "permanent_fix",
                "preventive_measures",
                "component",
                "rollout_order",
                "rollback_risk",
                "retest_plan",
            ):
                _text(re_, tag, getattr(f.remediation, tag))
            crits = SubElement(re_, "acceptance_criteria")
            for crit in f.remediation.acceptance_criteria:
                _text(crits, "criterion", crit)
        if f.closure is not None:
            cl = SubElement(fe, "closure")
            _text(cl, "permitted_status", f.closure.permitted_status)
            for tag in ("what_verified", "what_not_verified", "residual_risk", "next_step"):
                _text(cl, tag, getattr(f.closure, tag))

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
        we.set(
            "coverage_pct",
            "" if w.get("coverage_pct") is None else str(w.get("coverage_pct")),
        )
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

    _render_v2_sections_xml(root, doc)

    xml_bytes = tostring(root, encoding="utf-8", xml_declaration=True)
    return xml_bytes.decode("utf-8")


def _render_v2_sections_xml(root: Element, doc: ReportDocumentV1) -> None:
    """v2 doc-level sections: passport, conclusions, engagement, surface, narrative…"""
    passport = SubElement(root, "passport")
    passport.set("generation_status", doc.generation_status)
    passport.set("llm_analysis_status", doc.llm_analysis_status)
    passport.set("assessment_completeness", doc.assessment_completeness)
    passport.set("evidence_integrity", doc.evidence_integrity)
    passport.set("review_status", doc.review_status)
    _text(passport, "verification_kit_ref", doc.verification_kit_ref)

    if doc.conclusions is not None:
        ce = SubElement(root, "conclusions")
        _text(ce, "executive_summary", doc.conclusions.executive_summary)
        _text(ce, "business_risk", doc.conclusions.business_risk)
        _text(ce, "closure_summary", doc.conclusions.closure_summary)
        pp = SubElement(ce, "priority_plan")
        for item in doc.conclusions.priority_plan:
            ie = SubElement(pp, "item")
            _text(ie, "rationale", item.get("rationale") or item.get("reason"))
            fids = SubElement(ie, "finding_ids")
            for fid in item.get("finding_ids") or item.get("findings") or []:
                _text(fids, "finding_id", fid)

    if doc.engagement is not None:
        e = doc.engagement
        ee = SubElement(root, "engagement")
        for tag, seq in (
            ("testing_windows", e.testing_windows),
            ("source_ips", e.source_ips),
            ("user_agents", e.user_agents),
            ("canaries", e.canaries),
            ("oast_domains", e.oast_domains),
            ("test_accounts", e.test_accounts),
            ("roe_restrictions", e.roe_restrictions),
            ("incidents", e.incidents),
        ):
            container = SubElement(ee, tag)
            for val in seq:
                _text(container, "item", val)
        _text(ee, "run_profile", e.run_profile)
        _text(ee, "execution_mode", e.execution_mode)
        _text(ee, "tool_catalog_version", e.tool_catalog_version)
        _text(ee, "time_source", e.time_source)

    surface = SubElement(root, "surface_inventory")
    for s in doc.surface_inventory:
        se = SubElement(surface, "asset")
        se.set("host", s.host)
        _text(se, "port", s.port)
        _text(se, "service", s.service)
        _text(se, "version", s.version)
        _text(se, "technology", s.technology)

    unconf = SubElement(root, "unconfirmed_observations")
    unconf.set("count", str(len(doc.unconfirmed_observations)))
    for f in doc.unconfirmed_observations:
        ue = SubElement(unconf, "observation")
        ue.set("finding_id", f.finding_id)
        ue.set("severity", f.severity)
        _text(ue, "title", f.title)
        _text(ue, "downgrade_reason", f.downgrade_reason)

    tests = SubElement(root, "test_executions")
    for t in doc.test_executions:
        te = SubElement(tests, "test_execution")
        te.set("test_id", t.test_id)
        te.set("result", t.result)
        _text(te, "control", t.control)
        _text(te, "method", t.method)
        _text(te, "executed_at", t.executed_at)

    narrative = SubElement(root, "attack_narrative")
    for step in sorted(doc.attack_narrative, key=lambda s: s.order_index):
        ste = SubElement(narrative, "step")
        ste.set("order_index", str(step.order_index))
        ste.set("phase", step.phase)
        _text(ste, "tactic", step.tactic)
        _text(ste, "technique_id", step.technique_id)
        _text(ste, "description", step.description)

    chains = SubElement(root, "exploit_chains")
    for ch in doc.exploit_chains:
        che = SubElement(chains, "chain")
        che.set("chain_id", ch.chain_id)
        che.set("kind", ch.kind)
        _text(che, "title", ch.title)
        _text(che, "preconditions", ch.preconditions)
        _text(che, "outcome", ch.outcome)
        _text(che, "breaks_at", ch.breaks_at)
        tv = SubElement(che, "to_verify")
        for item in ch.to_verify:
            _text(tv, "item", item)

    method = SubElement(root, "methodology")
    for m in doc.methodology:
        me = SubElement(method, "framework")
        me.set("name", m.framework)
        me.set("applied", str(m.applied))
        _text(me, "revision", m.revision)
        _text(me, "notes", m.notes)

    if doc.client_impact is not None:
        c = doc.client_impact
        cie = SubElement(root, "client_impact")
        for tag, seq in (
            ("created_artifacts", c.created_artifacts),
            ("removed", c.removed),
            ("not_removed", c.not_removed),
        ):
            container = SubElement(cie, tag)
            for val in seq:
                _text(container, "item", val)
        _text(cie, "data_exfiltration", c.data_exfiltration)
        _text(cie, "availability_impact", c.availability_impact)

    claims = SubElement(root, "claims")
    for cl in doc.claims:
        cle = SubElement(claims, "claim")
        cle.set("claim_id", cl.claim_id)
        cle.set("claim_type", cl.claim_type)
        _text(cle, "text", cl.text)
        cev = SubElement(cle, "evidence_ids")
        for eid in cl.evidence_ids:
            _text(cev, "evidence_id", eid)


__all__ = ["VALHALLA_REPORT_XML_NS", "render_xml"]
