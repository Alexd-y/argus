"""Unit tests for the passive → FindingDTO bridge (WB-P5b, pure)."""

from __future__ import annotations

import re
from uuid import UUID, uuid4

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    EvidenceTier,
    FindingCategory,
    FindingStatus,
)
from src.web_workbench.passive.analyzer import PassiveFinding, PassiveSeverity, analyze
from src.web_workbench.passive.finding_bridge import (
    passive_finding_to_dto,
    passive_findings_to_dtos,
)
from src.web_workbench.proxy.transport import NormalizedRequest, NormalizedResponse

_CVSS_RE = re.compile(r"^CVSS:[34]\.[0-9]/[A-Z:/0-9]+$")

_TENANT = UUID("11111111-1111-1111-1111-111111111111")
_SCAN = UUID("22222222-2222-2222-2222-222222222222")
_ASSET = UUID("33333333-3333-3333-3333-333333333333")
_TOOL_RUN = UUID("44444444-4444-4444-4444-444444444444")

_ALL_CODES = [
    ("missing-hsts", 319, EvidenceTier.INFORMATIONAL),
    ("missing-nosniff", 693, EvidenceTier.INFORMATIONAL),
    ("missing-csp", 693, EvidenceTier.INFORMATIONAL),
    ("clickjacking", 1021, EvidenceTier.INFORMATIONAL),
    ("cookie-missing-secure", 614, EvidenceTier.INFORMATIONAL),
    ("cookie-missing-httponly", 1004, EvidenceTier.INFORMATIONAL),
    ("cookie-missing-samesite", 1275, EvidenceTier.INFORMATIONAL),
    ("version-disclosure", 200, EvidenceTier.INFORMATIONAL),
    ("cors-wildcard-credentials", 942, EvidenceTier.INFORMATIONAL),
    ("reflected-input", 79, EvidenceTier.SUSPECTED),
]


def _finding(code: str, severity: PassiveSeverity = PassiveSeverity.LOW) -> PassiveFinding:
    return PassiveFinding(
        code=code,
        category=FindingCategory.MISCONFIG,
        confidence=ConfidenceLevel.SUSPECTED,
        severity=severity,
        title="Title",
        detail="Detail text",
        evidence="Header",
        location="GET https://app/",
    )


def _to_dto(finding: PassiveFinding):
    return passive_finding_to_dto(
        finding,
        tenant_id=_TENANT,
        scan_id=_SCAN,
        asset_id=_ASSET,
        tool_run_id=_TOOL_RUN,
    )


@pytest.mark.parametrize(("code", "cwe", "tier"), _ALL_CODES)
def test_every_code_maps_to_valid_dto(code: str, cwe: int, tier: EvidenceTier) -> None:
    dto = _to_dto(_finding(code))
    assert dto.cwe == [cwe]
    assert dto.evidence_tier is tier
    assert dto.status is FindingStatus.NEW
    assert _CVSS_RE.fullmatch(dto.cvss_v3_vector)
    assert 0.0 <= dto.cvss_v3_score <= 10.0
    assert dto.tenant_id == _TENANT
    assert dto.scan_id == _SCAN


def test_category_and_confidence_are_carried() -> None:
    finding = PassiveFinding(
        code="reflected-input",
        category=FindingCategory.XSS,
        confidence=ConfidenceLevel.LIKELY,
        severity=PassiveSeverity.MEDIUM,
        title="Reflected",
        detail="reflected",
        evidence="q",
        location="GET https://app/",
    )
    dto = _to_dto(finding)
    assert dto.category is FindingCategory.XSS
    assert dto.confidence is ConfidenceLevel.LIKELY


@pytest.mark.parametrize(
    ("severity", "score"),
    [
        (PassiveSeverity.INFO, 0.0),
        (PassiveSeverity.LOW, 3.1),
        (PassiveSeverity.MEDIUM, 5.3),
        (PassiveSeverity.HIGH, 7.5),
    ],
)
def test_severity_maps_to_expected_cvss_score(severity: PassiveSeverity, score: float) -> None:
    dto = _to_dto(_finding("missing-csp", severity))
    assert dto.cvss_v3_score == score


def test_remediation_preserves_context() -> None:
    dto = _to_dto(_finding("missing-hsts"))
    assert dto.remediation is not None
    assert "Title" in dto.remediation.summary
    assert "Detail text" in dto.remediation.summary
    assert "GET https://app/" in dto.remediation.summary


def test_explicit_finding_id_is_used() -> None:
    fixed = uuid4()
    dto = passive_finding_to_dto(
        _finding("missing-csp"),
        tenant_id=_TENANT,
        scan_id=_SCAN,
        asset_id=_ASSET,
        tool_run_id=_TOOL_RUN,
        finding_id=fixed,
    )
    assert dto.id == fixed


def test_unknown_code_fails_closed() -> None:
    with pytest.raises(ValueError, match="unmapped passive finding code"):
        _to_dto(_finding("totally-unknown-code"))


def test_batch_mapping_generates_distinct_ids() -> None:
    findings = [_finding("missing-csp"), _finding("missing-hsts")]
    dtos = passive_findings_to_dtos(
        findings,
        tenant_id=_TENANT,
        scan_id=_SCAN,
        asset_id=_ASSET,
        tool_run_id=_TOOL_RUN,
    )
    assert len(dtos) == 2
    assert dtos[0].id != dtos[1].id


def test_end_to_end_analyze_to_dtos() -> None:
    """Every code the analyzer can emit must be bridgeable (no unmapped code)."""
    req = NormalizedRequest.parse(b"GET /p?q=reflectme HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
    resp = NormalizedResponse.parse(
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.58\r\n"
        b"Set-Cookie: sid=1\r\n"
        b"Access-Control-Allow-Origin: *\r\n"
        b"Access-Control-Allow-Credentials: true\r\n"
        b"\r\n"
    )
    findings = analyze(req, resp, b"echo reflectme", secure=True)
    dtos = passive_findings_to_dtos(
        findings,
        tenant_id=_TENANT,
        scan_id=_SCAN,
        asset_id=_ASSET,
        tool_run_id=_TOOL_RUN,
    )
    assert len(dtos) == len(findings) > 0
