"""Unit tests for the JWT inspector/analyzer (WB-P7b)."""

from __future__ import annotations

import base64
import json
import re
from uuid import UUID

import pytest

from src.pipeline.contracts.finding_dto import FindingCategory, FindingStatus
from src.web_workbench.checks.jwt_editor import (
    JwtError,
    analyze_jwt,
    decode_jwt,
    is_jwt,
    jwt_findings_to_dtos,
)
from src.web_workbench.checks.severity import CheckSeverity

_CVSS_RE = re.compile(r"^CVSS:[34]\.[0-9]/[A-Z:/0-9]+$")
_NOW = 1_700_000_000.0
_IDS = dict(
    tenant_id=UUID("11111111-1111-1111-1111-111111111111"),
    scan_id=UUID("22222222-2222-2222-2222-222222222222"),
    asset_id=UUID("33333333-3333-3333-3333-333333333333"),
    tool_run_id=UUID("44444444-4444-4444-4444-444444444444"),
)


def _seg(obj: dict[str, object]) -> str:
    raw = json.dumps(obj).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwt(
    header: dict[str, object], payload: dict[str, object], signature: str | None = "sig"
) -> str:
    token = f"{_seg(header)}.{_seg(payload)}"
    if signature is not None:
        token += f".{signature}"
    return token


def _codes(findings) -> set[str]:
    return {f.code for f in findings}


def test_decode_jwt_roundtrip() -> None:
    token = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "u1", "exp": _NOW + 60})
    decoded = decode_jwt(token)
    assert decoded.header["alg"] == "HS256"
    assert decoded.payload["sub"] == "u1"
    assert decoded.parts == 3


def test_alg_none_is_critical() -> None:
    token = _jwt({"alg": "none"}, {"sub": "admin", "exp": _NOW + 60}, signature=None)
    findings = analyze_jwt(token, now=_NOW)
    critical = [f for f in findings if f.code == "jwt-alg-none"]
    assert critical and critical[0].severity is CheckSeverity.CRITICAL


def test_empty_signature_with_signing_alg() -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "u1", "exp": _NOW + 60}, signature="")
    assert "jwt-empty-signature" in _codes(analyze_jwt(token, now=_NOW))


def test_embedded_jwk_header() -> None:
    token = _jwt(
        {"alg": "RS256", "jwk": {"kty": "RSA", "n": "x"}},
        {"sub": "u1", "exp": _NOW + 60},
    )
    assert "jwt-embedded-jwk" in _codes(analyze_jwt(token, now=_NOW))


@pytest.mark.parametrize("header_name", ["jku", "x5u"])
def test_external_key_url_headers(header_name: str) -> None:
    token = _jwt(
        {"alg": "RS256", header_name: "https://evil.example/keys"},
        {"sub": "u1", "exp": _NOW + 60},
    )
    assert f"jwt-{header_name}-header" in _codes(analyze_jwt(token, now=_NOW))


def test_kid_injection() -> None:
    token = _jwt(
        {"alg": "HS256", "kid": "../../etc/passwd"},
        {"sub": "u1", "exp": _NOW + 60},
    )
    assert "jwt-kid-injection" in _codes(analyze_jwt(token, now=_NOW))


def test_no_expiry() -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "u1"})
    assert "jwt-no-expiry" in _codes(analyze_jwt(token, now=_NOW))


def test_expired_token() -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "u1", "exp": _NOW - 10})
    assert "jwt-expired" in _codes(analyze_jwt(token, now=_NOW))


def test_excessive_lifetime() -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "u1", "exp": _NOW + 40_000_000})
    assert "jwt-long-expiry" in _codes(analyze_jwt(token, now=_NOW))


def test_valid_expiry_not_flagged() -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "u1", "exp": _NOW + 3600})
    codes = _codes(analyze_jwt(token, now=_NOW))
    assert not {"jwt-no-expiry", "jwt-expired", "jwt-long-expiry"} & codes


def test_sensitive_claim_detected_without_leaking_value() -> None:
    token = _jwt(
        {"alg": "HS256"},
        {"sub": "u1", "exp": _NOW + 60, "user": {"password": "hunter2"}},
    )
    findings = analyze_jwt(token, now=_NOW)
    sensitive = [f for f in findings if f.code == "jwt-sensitive-claim"]
    assert sensitive
    assert sensitive[0].evidence == "payload.password"
    # SI-3: the actual secret value must never appear in the finding.
    for f in findings:
        assert "hunter2" not in f.evidence
        assert "hunter2" not in f.detail


def test_clean_token_has_no_findings() -> None:
    token = _jwt({"alg": "HS256"}, {"sub": "u1", "exp": _NOW + 3600})
    assert analyze_jwt(token, now=_NOW) == []


def test_decode_invalid_fails_closed() -> None:
    with pytest.raises(JwtError):
        decode_jwt("not-a-jwt")
    assert is_jwt("still.not.jwt") is False
    assert is_jwt(_jwt({"alg": "HS256"}, {"sub": "u1"})) is True


def test_bridge_to_finding_dto() -> None:
    token = _jwt({"alg": "none"}, {"admin": True}, signature=None)
    findings = analyze_jwt(token, now=_NOW)
    dtos = jwt_findings_to_dtos(findings, **_IDS)
    assert dtos
    for dto in dtos:
        assert dto.category is FindingCategory.JWT
        assert dto.status is FindingStatus.NEW
        assert _CVSS_RE.fullmatch(dto.cvss_v3_vector)
        assert dto.cwe and dto.cwe[0] > 0


def test_multiple_weaknesses_reported_together() -> None:
    token = _jwt(
        {"alg": "none", "kid": "id/../x"},
        {"sub": "u1", "password": "p"},
        signature=None,
    )
    codes = _codes(analyze_jwt(token, now=_NOW))
    assert {"jwt-alg-none", "jwt-kid-injection", "jwt-no-expiry", "jwt-sensitive-claim"} <= codes
