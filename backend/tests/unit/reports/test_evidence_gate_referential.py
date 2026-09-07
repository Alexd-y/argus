"""A2 — evidence gate enforces referential integrity for confirmed findings.

Spec §5: finding → evidence → run/session. A ``confirmed``/``exploitable``
status is only allowed when the evidence id resolves to a real reference (or a
concrete raw_artifact_ref) AND a producer (resolvable tool_run or validator).
Opaque, unresolvable refs like ``finding-3`` must NOT satisfy the gate.
"""

from __future__ import annotations

from src.reports.report_document import (
    ReportEvidenceRef,
    ReportFinding,
    ReportToolRun,
    apply_evidence_gate,
    build_report_document,
)


def _confirmed(fid: str, **kw) -> ReportFinding:
    base = {
        "finding_id": fid,
        "title": f"Finding {fid}",
        "severity": "high",
        "verification_status": "confirmed",
        "confidence": 0.95,
    }
    base.update(kw)
    return ReportFinding(**base)


def test_resolvable_evidence_and_validator_keeps_confirmed():
    gated, errors = apply_evidence_gate(
        [_confirmed("f1", evidence_ids=["argus/poc/f1.json"], validator_id="dalfox")],
        known_evidence_ids={"argus/poc/f1.json"},
        known_tool_run_ids=set(),
    )
    assert gated[0].verification_status == "confirmed"
    assert errors == []


def test_opaque_unresolvable_ref_is_downgraded():
    gated, errors = apply_evidence_gate(
        [_confirmed("f2", evidence_ids=["finding-3"], validator_id="whatweb")],
        known_evidence_ids={"argus/poc/other.json"},
        known_tool_run_ids=set(),
    )
    assert gated[0].verification_status == "insufficient_evidence"
    assert any(e.finding_id == "f2" and e.code == "insufficient_evidence" for e in errors)


def test_raw_artifact_ref_counts_as_verifiable_evidence():
    gated, _ = apply_evidence_gate(
        [_confirmed("f3", evidence_ids=["finding-3"], raw_artifact_ref="argus/raw/f3.txt",
                    validator_id="sqlmap")],
        known_evidence_ids=set(),
        known_tool_run_ids=set(),
    )
    assert gated[0].verification_status == "confirmed"


def test_resolvable_tool_run_counts_as_producer():
    gated, _ = apply_evidence_gate(
        [_confirmed("f4", evidence_ids=["e1"], tool_run_id="TR-9")],
        known_evidence_ids={"e1"},
        known_tool_run_ids={"TR-9"},
    )
    assert gated[0].verification_status == "confirmed"


def test_no_producer_is_downgraded():
    gated, _ = apply_evidence_gate(
        [_confirmed("f5", evidence_ids=["e1"])],  # resolvable evidence, but no source
        known_evidence_ids={"e1"},
        known_tool_run_ids=set(),
    )
    assert gated[0].verification_status == "insufficient_evidence"


def test_backward_compatible_without_known_sets():
    # No known sets → historical non-empty behavior (any evidence id + source).
    gated, _ = apply_evidence_gate(
        [_confirmed("f6", evidence_ids=["finding-3"], validator_id="whatweb")]
    )
    assert gated[0].verification_status == "confirmed"


def test_build_report_document_enforces_referential_integrity():
    doc = build_report_document(
        scan_id="s", tenant_id="t", target="example.com",
        evidence_references=[ReportEvidenceRef(evidence_id="E-1", object_key="argus/poc/f1.json")],
        tool_runs=[ReportToolRun(tool_run_id="TR-1", tool_name="dalfox", status="ok")],
        findings=[
            _confirmed("keep", evidence_ids=["argus/poc/f1.json"], tool_run_id="TR-1"),
            _confirmed("drop", evidence_ids=["finding-99"], validator_id="llm"),
        ],
    )
    by_id = {f.finding_id: f for f in doc.findings}
    assert by_id["keep"].verification_status == "confirmed"
    assert by_id["drop"].verification_status == "insufficient_evidence"
    assert any(ve.finding_id == "drop" for ve in doc.validation_errors)
