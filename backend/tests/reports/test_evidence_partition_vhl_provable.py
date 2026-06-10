"""VHL-PROVABLE-001 — the Valhalla report is built from raw, provable data.

These tests pin the provability partition that decides which findings appear in the
main report (provable from raw evidence) versus the "Unconfirmed — requires manual
verification" section, and assert the partition is identical across HTML context and the
JSON export. They also guard the data-loss fix: ``threat_model_inference`` findings are
no longer silently dropped.
"""

from __future__ import annotations

import json

from src.reports.data_collector import FindingRow, ScanReportData
from src.reports.evidence_partition import (
    is_provable_from_raw,
    partition_findings,
    unconfirmed_reason,
)
from src.reports.generators import (
    build_report_data_from_scan_report,
    generate_csv,
    generate_json,
    generate_markdown,
)
from src.reports.report_quality_gate import normalize_findings_for_report
from src.services.reporting import ReportGenerator, findings_rows_for_jinja


def _finding(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "f",
        "evidence_classification": "candidate",
        "evidence_type": None,
        "proof_of_concept": {},
        "evidence_refs": [],
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# Unit: the predicate and the reason text                                      #
# --------------------------------------------------------------------------- #

def test_validated_finding_is_provable() -> None:
    f = _finding(evidence_classification="validated")
    assert is_provable_from_raw(f) is True
    assert unconfirmed_reason(f) is None


def test_observed_finding_is_provable() -> None:
    # A missing-header / banner observation is proven by the raw response.
    assert is_provable_from_raw(_finding(evidence_classification="observed")) is True


def test_candidate_finding_is_not_provable() -> None:
    f = _finding(evidence_classification="candidate")
    assert is_provable_from_raw(f) is False
    assert "candidate" in (unconfirmed_reason(f) or "").lower()


def test_inconclusive_finding_is_not_provable() -> None:
    f = _finding(evidence_classification="inconclusive")
    assert is_provable_from_raw(f) is False
    assert "inconclusive" in (unconfirmed_reason(f) or "").lower()


def test_threat_model_inference_never_provable_even_with_strong_evidence() -> None:
    # An inference is excluded by type even if it carries a (claimed) validated chain.
    f = _finding(
        evidence_classification="validated",
        evidence_type="threat_model_inference",
        proof_of_concept={"raw_request": "x", "raw_response": "y"},
        evidence_refs=["a", "b"],
    )
    assert is_provable_from_raw(f) is False
    assert "threat-model" in (unconfirmed_reason(f) or "").lower()


def test_partition_splits_and_tags_in_place() -> None:
    provable = _finding(id="ok", evidence_classification="validated")
    weak = _finding(id="weak", evidence_classification="candidate")
    confirmed, unconfirmed = partition_findings([provable, weak])
    assert [f["id"] for f in confirmed] == ["ok"]
    assert [f["id"] for f in unconfirmed] == ["weak"]
    assert provable["is_provable"] is True and provable["unconfirmed_reason"] is None
    assert weak["is_provable"] is False and weak["unconfirmed_reason"]


def test_predicate_recomputes_when_classification_absent() -> None:
    # No stored classification and no evidence → inconclusive → not provable.
    assert is_provable_from_raw({"proof_of_concept": {}, "evidence_refs": []}) is False


# --------------------------------------------------------------------------- #
# Fixtures for the integration tests                                           #
# --------------------------------------------------------------------------- #

def _provable_row(fid: str = "prov") -> FindingRow:
    return FindingRow(
        id=fid,
        tenant_id="t",
        scan_id="s",
        severity="high",
        title="Reflected XSS in q parameter",
        description="Payload reflected unescaped in the response body.",
        cwe="CWE-79",
        cvss=7.2,
        confidence="confirmed",
        evidence_refs=["artifact-1", "artifact-2"],
        proof_of_concept={
            "raw_request": "GET /search?q=<script>alert(1)</script> HTTP/1.1",
            "raw_response": "HTTP/1.1 200 OK\n\n<html><script>alert(1)</script></html>",
            "url": "https://target.example/search",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "observed_impact": "Injected script executed in the response context.",
            "timestamp": "2026-01-01T00:00:00Z",
        },
        reproducible_steps="1. Send the request above. 2. Observe the reflected script.",
    )


def _inference_row(fid: str = "inf") -> FindingRow:
    return FindingRow(
        id=fid,
        tenant_id="t",
        scan_id="s",
        severity="high",
        title="Potential privilege escalation via role model",
        description="Threat-model derived hypothesis about a role escalation path.",
        evidence_type="threat_model_inference",
    )


# --------------------------------------------------------------------------- #
# Integration: no silent data loss + consistent split across formats           #
# --------------------------------------------------------------------------- #

def test_normalize_no_longer_drops_threat_model_inference() -> None:
    out = normalize_findings_for_report([_inference_row()])
    assert len(out) == 1, "threat_model_inference findings must be preserved, not dropped"
    assert out[0].evidence_type == "threat_model_inference"


def test_html_context_valhalla_splits_provable_and_unconfirmed() -> None:
    findings = normalize_findings_for_report([_provable_row(), _inference_row()])
    partition_findings(findings)  # collector tags findings before context build
    data = ScanReportData(scan_id="s", tenant_id="t", findings=findings)

    ctx = ReportGenerator().prepare_template_context("valhalla", data, {})

    main_titles = {r["title"] for r in ctx["findings"]}
    unconfirmed_titles = {r["title"] for r in ctx["unconfirmed_findings"]}
    assert "Reflected XSS in q parameter" in main_titles
    assert any("privilege escalation" in t.lower() for t in unconfirmed_titles)
    # A finding is never in both buckets.
    assert not (main_titles & unconfirmed_titles)
    assert ctx["unconfirmed_findings_count"] == len(ctx["unconfirmed_findings"]) >= 1
    assert ctx["findings_count"] == len(ctx["findings"]) >= 1
    # Every unconfirmed row carries a reason.
    assert all(r.get("unconfirmed_reason") for r in ctx["unconfirmed_findings"])


def test_findings_rows_for_jinja_carry_partition_flags() -> None:
    findings = normalize_findings_for_report([_provable_row()])
    partition_findings(findings)
    [row] = findings_rows_for_jinja(
        ScanReportData(scan_id="s", tenant_id="t", findings=findings),
        report_tier="valhalla",
    )
    assert row["is_provable"] is True
    assert row["unconfirmed_reason"] is None


def test_generate_json_valhalla_splits_provable_and_unconfirmed() -> None:
    findings = normalize_findings_for_report([_provable_row(), _inference_row()])
    partition_findings(findings)
    data = ScanReportData(scan_id="s", tenant_id="t", findings=findings)
    report_data = build_report_data_from_scan_report(data, report_id="r1")

    payload = json.loads(
        generate_json(report_data, jinja_context={"tier": "valhalla"}).decode("utf-8")
    )

    main_titles = {f["title"] for f in payload["findings"]}
    unconfirmed_titles = {f["title"] for f in payload["unconfirmed_findings"]}
    assert any("xss" in t.lower() for t in main_titles)
    assert any("privilege escalation" in t.lower() for t in unconfirmed_titles)
    assert not (main_titles & unconfirmed_titles)
    for f in payload["unconfirmed_findings"]:
        assert f["unconfirmed_reason"], "each unconfirmed finding must explain why"
        assert f["is_provable"] is False
    for f in payload["findings"]:
        assert f["is_provable"] is True


def test_generate_json_non_valhalla_keeps_all_findings_in_main_list() -> None:
    # Backward-compatibility: only Valhalla applies the provability partition.
    findings = normalize_findings_for_report([_provable_row(), _inference_row()])
    partition_findings(findings)
    data = ScanReportData(scan_id="s", tenant_id="t", findings=findings)
    report_data = build_report_data_from_scan_report(data, report_id="r1")

    payload = json.loads(
        generate_json(report_data, jinja_context={"tier": "midgard"}).decode("utf-8")
    )
    assert payload["unconfirmed_findings"] == []
    assert len(payload["findings"]) == 2


def test_generate_markdown_valhalla_has_unconfirmed_section() -> None:
    findings = normalize_findings_for_report([_provable_row(), _inference_row()])
    partition_findings(findings)
    data = ScanReportData(scan_id="s", tenant_id="t", findings=findings)
    report_data = build_report_data_from_scan_report(data, report_id="r1")

    md = generate_markdown(
        report_data, tier="valhalla", jinja_context={"tier": "valhalla"}
    ).decode("utf-8")
    assert "## Unconfirmed Observations (require manual verification)" in md
    assert "privilege escalation" in md.lower()


def test_generate_csv_exposes_provability_columns() -> None:
    findings = normalize_findings_for_report([_provable_row(), _inference_row()])
    partition_findings(findings)
    data = ScanReportData(scan_id="s", tenant_id="t", findings=findings)
    report_data = build_report_data_from_scan_report(data, report_id="r1")

    csv_text = generate_csv(
        report_data, jinja_context={"tier": "valhalla"}
    ).decode("utf-8")
    assert "is_provable" in csv_text
    assert "unconfirmed_reason" in csv_text
