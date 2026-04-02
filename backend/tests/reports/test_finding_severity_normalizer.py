"""VHQ-004 — CVSS / severity normalization for report findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from src.reports.finding_severity_normalizer import (
    normalize_findings_severity,
    severity_from_cvss,
)


def test_normalize_empty_list_returns_empty_list() -> None:
    findings: list[Any] = []
    out = normalize_findings_severity(findings)
    assert out == []
    assert out is findings


def test_normalize_correct_severity_and_cvss_unchanged() -> None:
    f = {"title": "x", "cvss": 5.5, "severity": "medium"}
    findings = [f]
    out = normalize_findings_severity(findings)
    assert f["severity"] == "medium"
    assert out is findings


def test_normalize_cvss_7_2_with_low_severity_corrected_to_high() -> None:
    f = {"title": "x", "cvss": 7.2, "severity": "low"}
    normalize_findings_severity([f])
    assert f["severity"] == "high"


def test_normalize_cvss_9_5_with_medium_severity_corrected_to_critical() -> None:
    f = {"title": "x", "cvss": 9.5, "severity": "medium"}
    normalize_findings_severity([f])
    assert f["severity"] == "critical"


def test_normalize_cvss_zero_sets_severity_info() -> None:
    f = {"title": "x", "cvss": 0.0, "severity": "low"}
    normalize_findings_severity([f])
    assert f["severity"] == "info"


def test_normalize_no_cvss_severity_unchanged() -> None:
    f = {"title": "x", "severity": "low"}
    normalize_findings_severity([f])
    assert f["severity"] == "low"


@pytest.mark.parametrize(
    "bad_cvss",
    ["not-a-number", -0.1, 10.1],
)
def test_normalize_invalid_cvss_severity_unchanged(bad_cvss: Any) -> None:
    f = {"title": "x", "cvss": bad_cvss, "severity": "low"}
    normalize_findings_severity([f])
    assert f["severity"] == "low"


@pytest.mark.parametrize(
    ("cvss", "expected"),
    [
        (0.0, "info"),
        (0.1, "low"),
        (3.9, "low"),
        (4.0, "medium"),
        (6.9, "medium"),
        (7.0, "high"),
        (8.9, "high"),
        (9.0, "critical"),
        (10.0, "critical"),
    ],
)
def test_severity_from_cvss_boundary_values(cvss: float, expected: str) -> None:
    assert severity_from_cvss(cvss) == expected


@dataclass
class _ObjectFinding:
    title: str
    severity: str
    cvss: float | None = None
    cvss_score: float | None = None


def test_normalize_works_with_object_style_findings() -> None:
    obj = _ObjectFinding(title="o", severity="medium", cvss=9.2)
    normalize_findings_severity([obj])
    assert obj.severity == "critical"


def test_normalize_uses_cvss_score_when_present() -> None:
    obj = _ObjectFinding(title="o", severity="wrong", cvss=2.0, cvss_score=8.0)
    normalize_findings_severity([obj])
    assert obj.severity == "high"


def test_normalize_multiple_findings_some_corrected_some_not() -> None:
    a = {"title": "ok", "cvss": 4.0, "severity": "medium"}
    b = {"title": "fix", "cvss": 7.2, "severity": "low"}
    c = {"title": "no cvss", "severity": "high"}
    d = {"title": "bad cvss", "cvss": "x", "severity": "high"}
    findings = [a, b, c, d]
    normalize_findings_severity(findings)
    assert a["severity"] == "medium"
    assert b["severity"] == "high"
    assert c["severity"] == "high"
    assert d["severity"] == "high"
    assert findings == [a, b, c, d]
