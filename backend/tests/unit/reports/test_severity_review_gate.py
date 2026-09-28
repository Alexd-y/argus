"""Part II Phase O — severity / CVSS / review release rules."""

from __future__ import annotations

from src.reports.report_document import ReportFinding
from src.reports.valhalla_severity_review_gate import severity_review_blockers


def _f(**kw):
    base = {
        "finding_id": "F-1",
        "title": "x",
        "severity": "high",
        "verification_status": "confirmed",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_version": "3.1",
        "review_status": "approved",
    }
    base.update(kw)
    return ReportFinding(**base)


def test_clean_high_finding_passes():
    assert severity_review_blockers([_f()]) == []


def test_high_without_cvss_vector_blocks():
    bl = severity_review_blockers([_f(cvss_vector=None)])
    assert any("O-CVSS" in b for b in bl)


def test_impact_overclaim_without_proof_blocks():
    bl = severity_review_blockers([_f(verification_status="suspected")])
    assert any("O-IMPACT" in b for b in bl)


def test_high_without_review_blocks():
    bl = severity_review_blockers([_f(review_status="pending")])
    assert any("O-REVIEW" in b for b in bl)


def test_review_can_be_disabled():
    bl = severity_review_blockers([_f(review_status="pending")], require_review=False)
    assert not any("O-REVIEW" in b for b in bl)


def test_low_finding_needs_no_vector_or_review():
    low = _f(finding_id="F-2", severity="low", cvss_vector=None, review_status="not_required")
    assert severity_review_blockers([low]) == []


def test_medium_theoretical_with_high_impact_vector_blocks():
    # Medium band but vector claims C:H while unproven → impact overclaim.
    m = _f(
        severity="medium",
        verification_status="suspected",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        review_status="not_required",
    )
    bl = severity_review_blockers([m])
    assert any("O-IMPACT" in b for b in bl)
