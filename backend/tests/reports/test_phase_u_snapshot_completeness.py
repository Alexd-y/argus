"""Part III Phase U — snapshot completeness + evidence chain (R-13…R-19)."""

from __future__ import annotations

from datetime import UTC, datetime

from src.reports.report_document import (
    ReportEvidenceRef,
    ReportFinding,
    ReportToolRun,
    build_report_document,
)
from src.reports.snapshot_builder import build_snapshot_from_report_data
from src.reports.snapshot_completeness_gate import (
    evidence_blockers,
    finding_chain_blockers,
    is_pseudo_evidence,
    limitations_blockers,
    passport_blockers,
    snapshot_release_blockers,
    tool_run_blockers,
)

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _full_doc(**over):
    kw = {
        "scan_id": "s1",
        "tenant_id": "t1",
        "target": "https://target.example",
        "execution_mode": "production",
        "scan_profile": "deep",
        "resolved_scan_mode": "standard",
        "started_at": "2026-01-01T00:00:00Z",
        "registry_versions": {"tools": "t-v1"},
        "scope_summary": {"in_scope": ["target.example"]},
        "generated_at": _TS,
    }
    kw.update(over)
    return build_report_document(**kw)


# --------------------------------------------------------------------------- R-13
def test_snapshot_passport_required_fields():
    empty = build_report_document(scan_id="s", tenant_id="t", target="x", generated_at=_TS)
    problems = passport_blockers(empty)
    assert any("execution_mode" in p for p in problems)
    assert any("registry_versions" in p for p in problems)
    # A filled passport passes.
    assert passport_blockers(_full_doc()) == []


# --------------------------------------------------------------------------- R-14
def test_limitations_nonempty_when_coverage_gate_failed():
    doc = _full_doc(wstg={"coverage_gate_passed": False}, limitations=[])
    assert any("R-14" in p for p in limitations_blockers(doc))
    ok = _full_doc(wstg={"coverage_gate_passed": False}, limitations=["WSTG coverage 2% only"])
    assert limitations_blockers(ok) == []


# --------------------------------------------------------------------------- R-15
def test_tool_run_requires_timing_and_artifact():
    bad = _full_doc(
        tool_runs=[ReportToolRun(tool_run_id="TR-1", tool_name="nmap", status="success")]
    )
    problems = tool_run_blockers(bad)
    assert any("timing" in p for p in problems)
    assert any("completed_no_output" in p for p in problems)
    good = _full_doc(
        tool_runs=[
            ReportToolRun(
                tool_run_id="TR-1",
                tool_name="nmap",
                status="success",
                started_at="2026-01-01T00:00:00Z",
                finished_at="2026-01-01T00:01:00Z",
                raw_artifact_ref="minio://k1",
            )
        ]
    )
    assert tool_run_blockers(good) == []


# --------------------------------------------------------------------------- R-16
def test_evidence_reference_requires_hash_and_timestamp():
    bad = _full_doc(evidence_references=[ReportEvidenceRef(evidence_id="E-1", object_key="k1")])
    problems = evidence_blockers(bad)
    assert any("sha256" in p for p in problems)
    assert any("collected_at_utc" in p for p in problems)
    good = _full_doc(
        evidence_references=[
            ReportEvidenceRef(
                evidence_id="E-1",
                object_key="k1",
                sha256="a" * 64,
                collected_at_utc="2026-01-01T00:00:00Z",
            )
        ]
    )
    assert evidence_blockers(good) == []


# --------------------------------------------------------------------------- R-17
def test_pseudo_evidence_caps_verification_status():
    assert is_pseudo_evidence("tool:testssl")
    assert is_pseudo_evidence("recon:asnmap")
    assert not is_pseudo_evidence("minio://argus/poc/F-1.json")

    # Build via snapshot_builder from a finding whose only evidence is pseudo.
    class _F:
        finding_id = "F-1"
        title = "TLS misconfig"
        severity = "high"
        cwe = "CWE-295"
        description = "d"
        validation_status = "validated"
        confidence = "confirmed"
        evidence_refs = ["tool:testssl"]
        proof_of_concept = None

    class _RD:
        findings = [_F()]
        evidence = []
        technologies = []
        target = "https://target.example"
        scan_id = "s1"
        tenant_id = "t1"

    doc = build_snapshot_from_report_data(_RD(), scan_meta={"scan_id": "s1"})
    f = doc.findings[0]
    assert f.verification_status == "suspected"  # capped, not confirmed
    assert f.downgrade_reason and "R-17" in f.downgrade_reason
    # And the gate flags a provable finding that slipped through with only pseudo evidence.
    provable = _full_doc(
        findings=[
            ReportFinding(
                finding_id="F-9",
                title="x",
                severity="high",
                verification_status="confirmed",
                evidence_ids=["tool:testssl"],
                validator_id="testssl",
            )
        ],
        evidence_references=[ReportEvidenceRef(evidence_id="tool:testssl")],
    )
    assert provable.findings[0].verification_status == "confirmed"
    assert any("R-17" in p for p in finding_chain_blockers(provable))


# --------------------------------------------------------------------------- R-18
def test_finding_requires_tool_run_link():
    broken = _full_doc(
        findings=[
            ReportFinding(
                finding_id="F-1",
                title="x",
                severity="medium",
                verification_status="suspected",
                evidence_ids=["minio://k1"],
            )
        ]
    )
    assert any("R-18" in p for p in finding_chain_blockers(broken))
    linked = _full_doc(
        findings=[
            ReportFinding(
                finding_id="F-1",
                title="x",
                severity="medium",
                verification_status="suspected",
                evidence_ids=["minio://k1"],
                tool_run_id="TR-1",
            )
        ]
    )
    assert not any("R-18" in p for p in finding_chain_blockers(linked))


# --------------------------------------------------------------------------- R-19
def test_snapshot_preserves_cvss_and_owasp():
    class _F:
        finding_id = "F-1"
        title = "SQLi"
        severity = "high"
        cwe = "CWE-89"
        description = "d"
        validation_status = "validated"
        confidence = "confirmed"
        evidence_refs = ["k1"]
        proof_of_concept = {"payload": "x"}
        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
        cvss_score = 5.3
        owasp_category = "A03:2021"
        source_tool = "sqlmap"

    class _RD:
        findings = [_F()]
        evidence = [{"finding_id": "F-1", "object_key": "k1", "kind": "artifact"}]
        technologies = []
        target = "https://target.example"
        scan_id = "s1"
        tenant_id = "t1"

    doc = build_snapshot_from_report_data(_RD(), scan_meta={"scan_id": "s1"})
    f = doc.findings[0]
    # CVSS / vector / OWASP must survive the transfer into the snapshot (no degradation).
    assert f.cvss_score == 5.3
    assert f.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
    assert f.owasp_category.startswith("A03")


def test_snapshot_release_blockers_aggregates():
    empty = build_report_document(scan_id="s", tenant_id="t", target="x", generated_at=_TS)
    problems = snapshot_release_blockers(empty)
    assert any("R-13" in p for p in problems)
