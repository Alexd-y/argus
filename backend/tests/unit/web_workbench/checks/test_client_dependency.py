"""Unit tests for the client-side dependency scanner (WB-P7)."""

from __future__ import annotations

import re
from uuid import UUID

import pytest

from src.pipeline.contracts.finding_dto import FindingCategory, FindingStatus
from src.web_workbench.checks.client_dependency import (
    DependencySeverity,
    DetectedLibrary,
    dependency_findings_to_dtos,
    detect_libraries,
    match_vulnerabilities,
    scan,
)

_CVSS_RE = re.compile(r"^CVSS:[34]\.[0-9]/[A-Z:/0-9]+$")
_IDS = dict(
    tenant_id=UUID("11111111-1111-1111-1111-111111111111"),
    scan_id=UUID("22222222-2222-2222-2222-222222222222"),
    asset_id=UUID("33333333-3333-3333-3333-333333333333"),
    tool_run_id=UUID("44444444-4444-4444-4444-444444444444"),
)


def test_detect_from_uri() -> None:
    libs = detect_libraries(uri="https://cdn.example.com/js/jquery-1.7.2.min.js")
    assert any(lib.name == "jquery" and lib.version == "1.7.2" for lib in libs)


def test_detect_from_content_banner() -> None:
    content = "/*! jQuery v3.3.1 | (c) JS Foundation */"
    libs = detect_libraries(content=content)
    assert libs and libs[0].name == "jquery" and libs[0].version == "3.3.1"


def test_scan_flags_vulnerable_jquery() -> None:
    findings = scan(uri="/assets/jquery-1.7.2.min.js")
    # 1.7.2 is < 1.9.0, < 3.0.0 and in [1.2.0, 3.5.0) → three advisory ranges.
    ids = {cve for f in findings for cve in f.identifiers}
    assert "CVE-2012-6708" in ids
    assert "CVE-2015-9251" in ids
    assert "CVE-2020-11022" in ids


def test_scan_clears_patched_jquery() -> None:
    assert scan(uri="/assets/jquery-3.5.1.min.js") == []


def test_at_or_above_lower_bound_excludes_ancient() -> None:
    # jQuery 1.1.0 is below the [1.2.0, 3.5.0) htmlPrefilter range lower bound,
    # so CVE-2020-11022 must NOT be reported for it (but the <1.9.0 one is).
    findings = scan(uri="/js/jquery-1.1.0.js")
    ids = {cve for f in findings for cve in f.identifiers}
    assert "CVE-2020-11022" not in ids
    assert "CVE-2012-6708" in ids


def test_bootstrap_v4_range() -> None:
    findings = scan(uri="/vendor/bootstrap-4.1.0.min.js")
    ids = {cve for f in findings for cve in f.identifiers}
    assert "CVE-2019-8331" in ids


def test_lodash_high_severity() -> None:
    findings = scan(uri="/static/lodash-4.17.4.min.js")
    assert findings
    assert all(f.severity is DependencySeverity.HIGH for f in findings)
    assert {"CVE-2019-10744", "CVE-2020-8203"} <= {c for f in findings for c in f.identifiers}


def test_moment_patched_is_clean() -> None:
    assert scan(uri="/js/moment-2.29.4.min.js") == []


def test_no_signature_no_finding() -> None:
    assert detect_libraries(uri="/js/app.bundle.js", content="console.log(1)") == []
    assert scan(uri="/js/app.bundle.js") == []


def test_scan_dedups_uri_and_content_same_version() -> None:
    findings = scan(
        uri="/js/jquery-3.4.1.min.js",
        content="/*! jQuery v3.4.1 */",
    )
    # 3.4.1 is only in [1.2.0, 3.5.0) → exactly one advisory, not duplicated
    # despite being detected from both uri and content.
    assert len(findings) == 1
    assert findings[0].identifiers == ("CVE-2020-11022", "CVE-2020-11023")


def test_match_vulnerabilities_on_detected() -> None:
    detected = DetectedLibrary(name="handlebars", version="4.7.6", source="uri", evidence="x")
    findings = match_vulnerabilities(detected)
    assert findings and findings[0].identifiers == ("CVE-2021-23369",)


def test_bridge_to_finding_dto() -> None:
    findings = scan(uri="/static/lodash-4.17.4.min.js")
    dtos = dependency_findings_to_dtos(findings, **_IDS)
    assert dtos
    for dto in dtos:
        assert dto.category is FindingCategory.SUPPLY_CHAIN
        assert dto.status is FindingStatus.NEW
        assert _CVSS_RE.fullmatch(dto.cvss_v3_vector)
        assert dto.cwe and dto.cwe[0] > 0
        assert dto.remediation is not None
        assert "lodash" in dto.remediation.summary


@pytest.mark.parametrize(
    ("version", "vulnerable"),
    [
        ("2.29.3", True),
        ("2.29.4", False),
        ("2.30.0", False),
        ("2.9.0", True),
    ],
)
def test_moment_version_boundaries(version: str, vulnerable: bool) -> None:
    findings = scan(uri=f"/js/moment-{version}.min.js")
    assert bool(findings) is vulnerable
