"""Unit tests for the passive NoSQL-injection analyzer (WB-P7c)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    EvidenceTier,
    FindingCategory,
    FindingStatus,
)
from src.web_workbench.checks.nosqli import (
    NosqlFinding,
    analyze,
    detect_error_signature,
    detect_operator_injection,
    nosql_finding_to_dto,
    nosql_findings_to_dtos,
)
from src.web_workbench.checks.severity import CheckSeverity
from src.web_workbench.proxy.transport import NormalizedRequest, NormalizedResponse


def _request(
    method: str = "GET",
    target: str = "/api/users",
    headers: tuple[tuple[str, str], ...] = (),
) -> NormalizedRequest:
    return NormalizedRequest(
        method=method,
        target=target,
        http_version="HTTP/1.1",
        headers=(("Host", "app.test"), *headers),
    )


def _response(status: int = 200) -> NormalizedResponse:
    return NormalizedResponse(
        http_version="HTTP/1.1",
        status_code=status,
        reason="",
        headers=(),
    )


# --------------------------------------------------------------------------- #
# Operator injection (request input)                                          #
# --------------------------------------------------------------------------- #


def test_bracket_operator_in_query_flagged() -> None:
    req = _request(target="/login?user[$ne]=&password[$ne]=")
    findings = detect_operator_injection(req)
    codes = {f.code for f in findings}
    assert codes == {"nosqli-operator-injection"}
    evidence = {f.evidence for f in findings}
    assert "user[$ne]" in evidence
    assert "password[$ne]" in evidence


def test_operator_token_in_query_value_flagged() -> None:
    req = _request(target='/search?q={"$where":"1"}')
    findings = detect_operator_injection(req)
    assert findings
    assert any(f.evidence == "q=$where" for f in findings)


def test_operator_in_json_body_flagged() -> None:
    req = _request(
        method="POST",
        target="/login",
        headers=(("Content-Type", "application/json"),),
    )
    body = b'{"user": {"$ne": null}, "pw": {"$gt": ""}}'
    findings = detect_operator_injection(req, body)
    evidence = {f.evidence for f in findings}
    assert "body.$ne" in evidence
    assert "body.$gt" in evidence


def test_operator_in_urlencoded_body_flagged() -> None:
    req = _request(
        method="POST",
        target="/login",
        headers=(("Content-Type", "application/x-www-form-urlencoded"),),
    )
    findings = detect_operator_injection(req, b"user[$ne]=x&pw=ok")
    assert any(f.evidence == "user[$ne]" for f in findings)


def test_operator_findings_deduplicated() -> None:
    req = _request(target="/x?a[$ne]=1&a[$ne]=2")
    findings = detect_operator_injection(req)
    assert len(findings) == 1


def test_clean_request_yields_no_operator_finding() -> None:
    req = _request(target="/api/users?id=42&name=alice")
    assert detect_operator_injection(req) == []


def test_dollar_key_not_a_real_operator_is_ignored() -> None:
    req = _request(
        method="POST",
        target="/x",
        headers=(("Content-Type", "application/json"),),
    )
    findings = detect_operator_injection(req, b'{"$custom": 1, "price": {"$total": 2}}')
    assert findings == []


# --------------------------------------------------------------------------- #
# Error signatures (response body)                                            #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "marker",
    [
        b"MongoError: something failed",
        b"E11000 duplicate key error",
        b"BSONError while parsing",
        b"Invalid BSON field name",
        b"CasterError: cast to ObjectId failed",
        b"unknown operator: $foo",
    ],
)
def test_error_signatures_detected(marker: bytes) -> None:
    findings = detect_error_signature(_request(), marker)
    assert findings
    assert findings[0].code == "nosqli-error-signature"


def test_no_error_signature_in_clean_body() -> None:
    assert detect_error_signature(_request(), b'{"ok": true}') == []


def test_error_body_scan_is_bounded() -> None:
    # Marker sits beyond the scan cap and must not be found.
    body = b"x" * 300_000 + b"mongoerror"
    assert detect_error_signature(_request(), body) == []


# --------------------------------------------------------------------------- #
# Combined analysis                                                           #
# --------------------------------------------------------------------------- #


def test_operator_plus_error_elevates_to_error_based() -> None:
    req = _request(target="/login?user[$ne]=")
    findings = analyze(req, _response(500), b"MongoError: cast failed")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.code == "nosqli-error-based"
    assert finding.severity is CheckSeverity.HIGH
    assert finding.confidence is ConfidenceLevel.LIKELY
    assert "user[$ne]" in finding.evidence
    assert "mongoerror" in finding.evidence


def test_operator_only_returns_suspected() -> None:
    req = _request(target="/login?user[$ne]=")
    findings = analyze(req, _response(200), b'{"ok": true}')
    assert findings
    assert all(f.confidence is ConfidenceLevel.SUSPECTED for f in findings)
    assert all(f.code == "nosqli-operator-injection" for f in findings)


def test_error_only_returns_suspected() -> None:
    findings = analyze(_request(), _response(500), b"BSONError")
    assert len(findings) == 1
    assert findings[0].code == "nosqli-error-signature"
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_clean_exchange_has_no_findings() -> None:
    req = _request(target="/api/users?id=7")
    assert analyze(req, _response(200), b'{"users": []}') == []


def test_findings_never_contain_request_values() -> None:
    req = _request(target="/login?user[$ne]=SECRETVALUE")
    findings = analyze(req, _response(500), b"MongoError")
    joined = " ".join(f"{f.evidence} {f.detail}" for f in findings)
    assert "SECRETVALUE" not in joined


# --------------------------------------------------------------------------- #
# FindingDTO bridge                                                           #
# --------------------------------------------------------------------------- #


def _ids() -> dict[str, object]:
    return {
        "tenant_id": uuid4(),
        "scan_id": uuid4(),
        "asset_id": uuid4(),
        "tool_run_id": uuid4(),
    }


def test_bridge_maps_category_and_metadata() -> None:
    finding = NosqlFinding(
        code="nosqli-error-based",
        severity=CheckSeverity.HIGH,
        confidence=ConfidenceLevel.LIKELY,
        cwe=943,
        title="Error-based NoSQL injection",
        detail="d",
        evidence="user[$ne] -> mongoerror",
        location="GET /login",
    )
    dto = nosql_finding_to_dto(finding, **_ids())  # type: ignore[arg-type]
    assert dto.category is FindingCategory.NOSQLI
    assert dto.cwe == [943]
    assert dto.status is FindingStatus.NEW
    assert dto.confidence is ConfidenceLevel.LIKELY
    assert dto.evidence_tier is EvidenceTier.SUSPECTED
    assert dto.cvss_v3_score is not None and dto.cvss_v3_score > 0


def test_bridge_uses_explicit_finding_id() -> None:
    finding = NosqlFinding(
        code="nosqli-operator-injection",
        severity=CheckSeverity.MEDIUM,
        confidence=ConfidenceLevel.SUSPECTED,
        cwe=943,
        title="t",
        detail="d",
        evidence="e",
        location="loc",
    )
    fixed = uuid4()
    dto = nosql_finding_to_dto(finding, finding_id=fixed, **_ids())  # type: ignore[arg-type]
    assert dto.id == fixed


def test_batch_bridge_assigns_unique_ids() -> None:
    req = _request(target="/x?a[$ne]=1&b[$gt]=2")
    findings = detect_operator_injection(req)
    dtos = nosql_findings_to_dtos(findings, **_ids())  # type: ignore[arg-type]
    assert len(dtos) == len(findings) >= 2
    assert len({d.id for d in dtos}) == len(dtos)


def test_end_to_end_analyze_to_dto() -> None:
    req = _request(target="/login?user[$ne]=")
    findings = analyze(req, _response(500), b"MongoError")
    dtos = nosql_findings_to_dtos(findings, **_ids())  # type: ignore[arg-type]
    assert len(dtos) == 1
    assert dtos[0].category is FindingCategory.NOSQLI
