"""Regression tests: keyword auto-scoring is provisional, never authoritative.

Guards ARGUS policy §7 — the OWASP/keyword heuristic may *suggest* a CVSS,
but must never overwrite an authoritative severity/vector, and must not
fabricate a score for an unmatched finding.
"""

from __future__ import annotations

from src.findings.cvss_auto_score import CVSSAutoScorer, auto_score_finding


def test_no_keyword_match_returns_none_no_fabricated_vector() -> None:
    assert auto_score_finding({"title": "totally benign observation"}) is None


def test_unmatched_finding_keeps_source_severity_and_gets_no_cvss() -> None:
    scorer = CVSSAutoScorer()
    finding = {"title": "misc note", "severity": "low"}
    out = scorer.score_finding(finding)

    # Source severity is untouched; no synthetic authoritative CVSS is stamped.
    assert out["severity"] == "low"
    assert "cvss" not in out
    assert "cvss_vector" not in out
    assert out["cvss_auto_scored"] is False
    assert out["cvss_suggested_score"] is None


def test_sqli_suggestion_is_provisional_and_does_not_overwrite_severity() -> None:
    scorer = CVSSAutoScorer()
    finding = {"title": "Possible sqli in id parameter", "owasp_category": "A05", "severity": "medium"}
    out = scorer.score_finding(finding)

    # Suggestion is present but authoritative fields are NOT touched.
    assert out["cvss_provisional"] is True
    assert out["cvss_auto_scored"] is True
    assert out["cvss_suggested_severity"] in {"critical", "high", "medium", "low", "none"}
    assert out["cvss_suggested_vector"].startswith("CVSS:3.1/")
    assert out["severity"] == "medium"  # not auto-promoted to Critical
    assert "cvss" not in out
    assert "cvss_vector" not in out


def test_existing_authoritative_vector_is_never_overridden() -> None:
    scorer = CVSSAutoScorer()
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    finding = {"title": "XSS reflected", "cvss_vector": vector, "severity": "high"}
    out = scorer.score_finding(finding)

    assert out["cvss_vector"] == vector
    assert out["severity"] == "high"
    assert out["cvss_auto_scored"] is False
    assert "cvss_suggested_vector" not in out
