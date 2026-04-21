"""ARG-024 — Tests for :mod:`src.reports.tier_classifier`.

Coverage targets:
    * Midgard strips evidence / screenshots / raw artifacts / timeline.
    * Midgard caps findings to ``MIDGARD_TOP_FINDINGS`` (top-10 by priority).
    * Asgard preserves findings + remediation + evidence; strips raw artifacts.
    * Valhalla is full pass-through.
    * Classifier never mutates the input ``ReportData``.
    * Stable ordering: critical→high→medium→low→info, then by CVSS.
"""

from __future__ import annotations

from src.api.schemas import Finding, ReportSummary
from src.reports.generators import (
    EvidenceEntry,
    PhaseOutputEntry,
    ReportData,
    ScreenshotEntry,
    TimelineEntry,
)
from src.reports.report_bundle import ReportTier
from src.reports.tier_classifier import (
    MIDGARD_TOP_FINDINGS,
    classify_for_tier,
)


def _summary() -> ReportSummary:
    return ReportSummary(
        critical=0, high=0, medium=0, low=0, info=0,
        technologies=[], sslIssues=0, headerIssues=0, leaksFound=False,
    )


def _make_finding(
    severity: str,
    title: str,
    *,
    cvss: float | None = None,
    cwe: str | None = None,
) -> Finding:
    return Finding(
        severity=severity,
        title=title,
        description=f"description for {title}",
        cwe=cwe,
        cvss=cvss,
    )


def _make_full_data(*, num_findings: int = 5) -> ReportData:
    findings = [
        _make_finding("critical", f"crit-{i}", cvss=9.8 - 0.1 * i, cwe="CWE-79")
        for i in range(num_findings)
    ]
    return ReportData(
        report_id="r-1",
        target="https://x.test",
        summary=_summary(),
        findings=findings,
        technologies=["nginx", "django"],
        timeline=[
            TimelineEntry(
                phase="recon", order_index=0, entry={"x": 1}, created_at="2026-04-19T10:00:00Z"
            )
        ],
        phase_outputs=[PhaseOutputEntry(phase="recon", output_data={"k": "v"})],
        evidence=[
            EvidenceEntry(finding_id="f1", object_key="evidence/a.txt", description="hex dump")
        ],
        screenshots=[
            ScreenshotEntry(object_key="screenshots/x.png", url_or_email="login")
        ],
        ai_insights=["LLM commentary"],
        executive_summary="Top-level summary.",
        remediation=["Apply patch X.", "Rotate secret Y."],
        raw_artifacts=[{"sensitive": "raw recon dump"}],
        hibp_pwned_password_summary={"pwned_count": 3},
    )


class TestMidgard:
    def test_strips_evidence_and_screenshots(self) -> None:
        data = _make_full_data()
        out = classify_for_tier(data, ReportTier.MIDGARD)
        assert out.evidence == []
        assert out.screenshots == []

    def test_strips_raw_artifacts_and_phase_outputs(self) -> None:
        out = classify_for_tier(_make_full_data(), ReportTier.MIDGARD)
        assert out.raw_artifacts == []
        assert out.phase_outputs == []
        assert out.timeline == []

    def test_strips_ai_insights_and_remediation(self) -> None:
        out = classify_for_tier(_make_full_data(), ReportTier.MIDGARD)
        assert out.ai_insights == []
        assert out.remediation == []

    def test_strips_hibp(self) -> None:
        out = classify_for_tier(_make_full_data(), ReportTier.MIDGARD)
        assert out.hibp_pwned_password_summary is None

    def test_keeps_executive_summary(self) -> None:
        out = classify_for_tier(_make_full_data(), ReportTier.MIDGARD)
        assert out.executive_summary == "Top-level summary."

    def test_caps_findings_to_top_n(self) -> None:
        data = _make_full_data(num_findings=MIDGARD_TOP_FINDINGS + 5)
        out = classify_for_tier(data, ReportTier.MIDGARD)
        assert len(out.findings) == MIDGARD_TOP_FINDINGS

    def test_does_not_mutate_input(self) -> None:
        data = _make_full_data()
        before_findings = list(data.findings)
        before_evidence = list(data.evidence)
        before_remediation = list(data.remediation) if isinstance(data.remediation, list) else data.remediation
        classify_for_tier(data, ReportTier.MIDGARD)
        assert data.findings == before_findings
        assert data.evidence == before_evidence
        assert data.remediation == before_remediation

    def test_orders_by_severity_then_cvss(self) -> None:
        findings = [
            _make_finding("low", "z-low", cvss=3.0),
            _make_finding("critical", "a-crit-low-cvss", cvss=9.0),
            _make_finding("critical", "b-crit-high-cvss", cvss=9.9),
            _make_finding("high", "c-high", cvss=8.0),
            _make_finding("info", "d-info"),
        ]
        data = ReportData(
            report_id="r", target="x",
            summary=_summary(), findings=findings, technologies=[],
        )
        out = classify_for_tier(data, ReportTier.MIDGARD)
        titles = [f.title for f in out.findings]
        assert titles == [
            "b-crit-high-cvss",
            "a-crit-low-cvss",
            "c-high",
            "z-low",
            "d-info",
        ]

    def test_handles_empty_findings(self) -> None:
        data = ReportData(
            report_id="r", target="x",
            summary=_summary(), findings=[], technologies=[],
        )
        out = classify_for_tier(data, ReportTier.MIDGARD)
        assert out.findings == []


class TestAsgard:
    def test_preserves_evidence_and_remediation(self) -> None:
        out = classify_for_tier(_make_full_data(), ReportTier.ASGARD)
        assert len(out.evidence) == 1
        assert len(out.remediation) == 2

    def test_preserves_findings_count(self) -> None:
        data = _make_full_data(num_findings=20)
        out = classify_for_tier(data, ReportTier.ASGARD)
        assert len(out.findings) == 20

    def test_strips_raw_artifacts_and_hibp(self) -> None:
        out = classify_for_tier(_make_full_data(), ReportTier.ASGARD)
        assert out.raw_artifacts == []
        assert out.hibp_pwned_password_summary is None

    def test_preserves_timeline_and_phase_outputs(self) -> None:
        out = classify_for_tier(_make_full_data(), ReportTier.ASGARD)
        assert len(out.timeline) == 1
        assert len(out.phase_outputs) == 1


class TestValhalla:
    def test_pass_through_full_data(self) -> None:
        data = _make_full_data()
        out = classify_for_tier(data, ReportTier.VALHALLA)
        assert len(out.findings) == len(data.findings)
        assert len(out.evidence) == 1
        assert len(out.screenshots) == 1
        assert len(out.raw_artifacts) == 1
        assert out.hibp_pwned_password_summary == {"pwned_count": 3}

    def test_preserves_remediation_and_timeline(self) -> None:
        out = classify_for_tier(_make_full_data(), ReportTier.VALHALLA)
        assert len(out.remediation) == 2
        assert len(out.timeline) == 1
