"""T3 — ``validate_report_data`` (severity, findings, HIBP, Valhalla context)."""

from __future__ import annotations

from src.api.schemas import Finding, ReportSummary
from src.reports.generators import ReportData
from src.reports.report_data_validation import (
    grounded_executive_summary_fallback_text,
    report_validation_failure_payload,
    validate_executive_ai_text_against_payload,
    validate_report_data,
)
from src.reports.valhalla_report_context import ValhallaReportContext


def _rd(
    *,
    findings: list[Finding],
    summary: ReportSummary | None = None,
    hibp: dict | None = None,
) -> ReportData:
    sm = summary or ReportSummary(
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
        technologies=[],
        sslIssues=0,
        headerIssues=0,
        leaksFound=False,
    )
    return ReportData(
        report_id="r1",
        target="https://x.test",
        summary=sm,
        findings=findings,
        technologies=[],
        hibp_pwned_password_summary=hibp,
    )


def test_validate_ok_aligned_severities_empty_hibp_midgard() -> None:
    f = [
        Finding(severity="high", title="A", description="d"),
        Finding(severity="low", title="B", description=""),
    ]
    sm = ReportSummary(
        critical=0,
        high=1,
        medium=0,
        low=1,
        info=0,
        technologies=[],
        sslIssues=0,
        headerIssues=0,
        leaksFound=False,
    )
    r = validate_report_data(_rd(findings=f, summary=sm), tier="midgard", template_context={})
    assert r.ok
    assert r.reason_codes == []


def test_validate_severity_summary_mismatch() -> None:
    f = [Finding(severity="critical", title="t", description="")]
    sm = ReportSummary(
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
        technologies=[],
        sslIssues=0,
        headerIssues=0,
        leaksFound=False,
    )
    r = validate_report_data(_rd(findings=f, summary=sm))
    assert not r.ok
    assert "severity_summary_mismatch" in r.reason_codes


def test_validate_finding_unknown_empty_rejected() -> None:
    f = [Finding(severity="unknown", title=" ", description="   ")]
    sm = ReportSummary(
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
        technologies=[],
        sslIssues=0,
        headerIssues=0,
        leaksFound=False,
    )
    r = validate_report_data(_rd(findings=f, summary=sm))
    assert not r.ok
    assert "finding_unknown_empty" in r.reason_codes


def test_validate_unknown_severity_ok_when_title_present() -> None:
    f = [Finding(severity="unknown", title="Has title", description="")]
    sm = ReportSummary(
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
        technologies=[],
        sslIssues=0,
        headerIssues=0,
        leaksFound=False,
    )
    r = validate_report_data(_rd(findings=f, summary=sm), tier="midgard")
    assert r.ok


def test_validate_hibp_pwned_le_checks_run() -> None:
    f: list[Finding] = []
    sm = ReportSummary(
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
        technologies=[],
        sslIssues=0,
        headerIssues=0,
        leaksFound=False,
    )
    r = validate_report_data(
        _rd(
            findings=f,
            summary=sm,
            hibp={"checks_run": 3, "pwned_count": 2, "checks_attempted": 5},
        )
    )
    assert r.ok


def test_validate_hibp_pwned_gt_checks_run_fails() -> None:
    f: list[Finding] = []
    sm = ReportSummary(
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
        technologies=[],
        sslIssues=0,
        headerIssues=0,
        leaksFound=False,
    )
    r = validate_report_data(
        _rd(
            findings=f,
            summary=sm,
            hibp={"checks_run": 2, "pwned_count": 5},
        )
    )
    assert not r.ok
    assert "hibp_pwned_gt_checks_run" in r.reason_codes


def test_validate_hibp_attempted_lt_run_fails() -> None:
    f: list[Finding] = []
    sm = ReportSummary(
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
        technologies=[],
        sslIssues=0,
        headerIssues=0,
        leaksFound=False,
    )
    r = validate_report_data(
        _rd(
            findings=f,
            summary=sm,
            hibp={"checks_run": 5, "pwned_count": 0, "checks_attempted": 2},
        )
    )
    assert not r.ok
    assert "hibp_checks_attempted_lt_run" in r.reason_codes


def test_validate_valhalla_requires_context() -> None:
    f: list[Finding] = []
    sm = ReportSummary(
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
        technologies=[],
        sslIssues=0,
        headerIssues=0,
        leaksFound=False,
    )
    r = validate_report_data(_rd(findings=f, summary=sm), tier="valhalla", template_context={})
    assert not r.ok
    assert "valhalla_context_missing" in r.reason_codes
    assert "valhalla_scan_artifacts_meta_missing" in r.reason_codes


def test_validate_valhalla_ok_with_model_dump() -> None:
    vc = ValhallaReportContext().model_dump(mode="json")
    f: list[Finding] = []
    sm = ReportSummary(
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
        technologies=[],
        sslIssues=0,
        headerIssues=0,
        leaksFound=False,
    )
    r = validate_report_data(
        _rd(findings=f, summary=sm),
        tier="valhalla",
        template_context={
            "valhalla_context": vc,
            "scan_artifacts": {"status": "skipped", "phase_blocks": []},
        },
    )
    assert r.ok


def test_validate_executive_ai_text_ok_when_no_numeric_claims() -> None:
    ok, codes = validate_executive_ai_text_against_payload(
        "executive_summary",
        {"executive_severity_totals": {"critical": 2}},
        "Overall risk is elevated; review findings in the technical sections.",
    )
    assert ok and codes == []


def test_validate_executive_ai_text_detects_severity_mismatch() -> None:
    payload = {
        "executive_severity_totals": {
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
        "finding_count": 3,
    }
    ok, codes = validate_executive_ai_text_against_payload(
        "executive_summary_valhalla",
        payload,
        "We recorded 5 critical issues and 10 findings total.",
    )
    assert not ok
    assert "executive_ai_severity_count_mismatch" in codes
    assert "executive_ai_finding_count_mismatch" in codes


def test_grounded_executive_fallback_contains_totals() -> None:
    text = grounded_executive_summary_fallback_text(
        {
            "finding_count": 4,
            "executive_severity_totals": {
                "critical": 0,
                "high": 2,
                "medium": 1,
                "low": 1,
                "info": 0,
            },
            "hibp_pwned_password_summary": {"pwned_count": 0, "checks_run": 3},
        }
    )
    assert "4 finding" in text
    assert "high: 2" in text
    assert "HIBP" in text or "check" in text.lower()


def test_report_validation_failure_payload_shape() -> None:
    p = report_validation_failure_payload(
        report_id="rid",
        tenant_id="tid",
        tier="midgard",
        reason_codes=["a", "b"],
    )
    assert p["event"] == "report_data_validation_failed"
    assert p["report_id"] == "rid"
    assert p["tenant_id"] == "tid"
    assert p["tier"] == "midgard"
    assert p["reason_codes"] == ["a", "b"]
