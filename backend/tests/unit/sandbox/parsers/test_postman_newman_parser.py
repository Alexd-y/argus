"""Unit tests for :mod:`src.sandbox.parsers.postman_newman_parser` (Backlog §4.14 — ARG-029).

Pinned contracts:

* Canonical artefact ``newman.json`` overrides stdout.
* ``run.failures[]`` → assertion findings; ``run.executions[].response``
  with ``code >= 500`` → server-error (OTHER) findings tagged CWE-755.
* Assertion routing keywords escalate severity:

  - secret/leak/api key/private key → SECRET_LEAK + CWE-200/532, severity=high
  - auth/token/credential/jwt/bearer → AUTH + CWE-287/285, severity=high
  - security/csrf/xss/sqli           → MISCONFIG + CWE-16, severity=medium
  - everything else                  → OTHER + CWE-710, severity=medium

* Response previews are scrubbed via :data:`_TOKEN_PATTERNS` so bearer
  tokens, JWTs, AWS access keys never reach the sidecar.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers import postman_newman_parser as newman_module
from src.sandbox.parsers.postman_newman_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_postman_newman_json,
)

_AWS_KEY_RE = re.compile(rb"AKIA[0-9A-Z]{16}")
_BEARER_RE = re.compile(rb"Bearer\s+[A-Za-z0-9._\-/+=]+")
_JWT_RE = re.compile(
    rb"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
)


def _failure(
    *,
    test_name: str = "Status code is 200",
    message: str = "expected 200 but got 401",
    request_name: str = "Login",
    method: str = "POST",
    url: str = "https://api.example.com/login",
) -> dict[str, Any]:
    return {
        "source": {"name": request_name, "request": {"url": {"raw": url}}},
        "parent": {"method": method, "url": {"raw": url}},
        "error": {"message": message, "test": test_name},
    }


def _execution(
    *,
    name: str = "GetUsers",
    method: str = "GET",
    url: str = "https://api.example.com/users",
    status: int = 502,
    body: str | None = None,
) -> dict[str, Any]:
    response: dict[str, Any] = {"code": status}
    if body is not None:
        response["stream"] = body
    return {
        "item": {"name": name},
        "request": {"method": method, "url": {"raw": url}},
        "response": response,
    }


def _payload(
    *,
    failures: list[dict[str, Any]] | None = None,
    executions: list[dict[str, Any]] | None = None,
) -> bytes:
    document: dict[str, Any] = {"run": {}}
    if failures is not None:
        document["run"]["failures"] = failures
    if executions is not None:
        document["run"]["executions"] = executions
    return json.dumps(document).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_postman_newman_json(b"", b"", tmp_path, "postman_newman") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "newman.json"
    canonical.write_bytes(_payload(failures=[_failure(test_name="canonical_test")]))
    decoy = _payload(failures=[_failure(test_name="decoy_test")])
    findings = parse_postman_newman_json(decoy, b"", tmp_path, "postman_newman")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "canonical_test" in sidecar
    assert "decoy_test" not in sidecar


def test_secret_leak_assertion_high_severity(tmp_path: Path) -> None:
    findings = parse_postman_newman_json(
        _payload(failures=[_failure(message="api key leak detected in body")]),
        b"",
        tmp_path,
        "postman_newman",
    )
    assert findings[0].category is FindingCategory.SECRET_LEAK
    assert findings[0].cvss_v3_score == pytest.approx(7.5)
    assert set(findings[0].cwe) == {200, 532}


def test_auth_assertion_routes_to_auth_with_cwe_287(tmp_path: Path) -> None:
    findings = parse_postman_newman_json(
        _payload(failures=[_failure(message="invalid auth token returned")]),
        b"",
        tmp_path,
        "postman_newman",
    )
    assert findings[0].category is FindingCategory.AUTH
    assert 287 in findings[0].cwe
    assert findings[0].cvss_v3_score == pytest.approx(7.5)


def test_security_keyword_routes_to_misconfig(tmp_path: Path) -> None:
    findings = parse_postman_newman_json(
        _payload(failures=[_failure(message="csrf check failed for endpoint")]),
        b"",
        tmp_path,
        "postman_newman",
    )
    assert findings[0].category is FindingCategory.MISCONFIG
    assert findings[0].cvss_v3_score == pytest.approx(5.0)


def test_generic_assertion_routes_to_other(tmp_path: Path) -> None:
    findings = parse_postman_newman_json(
        _payload(failures=[_failure(message="expected 200 but got 404")]),
        b"",
        tmp_path,
        "postman_newman",
    )
    assert findings[0].category is FindingCategory.OTHER
    assert 710 in findings[0].cwe
    assert findings[0].cvss_v3_score == pytest.approx(5.0)


def test_5xx_response_emits_error_handling_finding(tmp_path: Path) -> None:
    findings = parse_postman_newman_json(
        _payload(executions=[_execution(status=503)]),
        b"",
        tmp_path,
        "postman_newman",
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.OTHER
    assert 755 in findings[0].cwe
    assert findings[0].cvss_v3_score == pytest.approx(3.0)


def test_2xx_response_no_finding(tmp_path: Path) -> None:
    findings = parse_postman_newman_json(
        _payload(executions=[_execution(status=200)]),
        b"",
        tmp_path,
        "postman_newman",
    )
    assert findings == []


def test_bearer_token_redacted_in_response_preview(tmp_path: Path) -> None:
    body = (
        '{"error":"upstream","headers":{"Authorization":'
        '"Bearer eyJ0eXAiOiJKV1QifQ.payload.signature-12345"}}'
    )
    parse_postman_newman_json(
        _payload(executions=[_execution(status=502, body=body)]),
        b"",
        tmp_path,
        "postman_newman",
    )
    sidecar_bytes = (tmp_path / EVIDENCE_SIDECAR_NAME).read_bytes()
    assert b"REDACTED-TOKEN" in sidecar_bytes
    assert not _BEARER_RE.search(sidecar_bytes), (
        "raw bearer token leaked into postman newman sidecar"
    )


def test_jwt_redacted_in_response_preview(tmp_path: Path) -> None:
    body = '{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payloadblob.signaturebytes"}'
    parse_postman_newman_json(
        _payload(executions=[_execution(status=500, body=body)]),
        b"",
        tmp_path,
        "postman_newman",
    )
    sidecar_bytes = (tmp_path / EVIDENCE_SIDECAR_NAME).read_bytes()
    assert b"REDACTED-TOKEN" in sidecar_bytes
    assert not _JWT_RE.search(sidecar_bytes), (
        "raw JWT leaked into postman newman sidecar"
    )


def test_aws_key_redacted_in_response_preview(tmp_path: Path) -> None:
    body = '{"key":"AKIAIOSFODNN7EXAMPLE","msg":"oops"}'
    parse_postman_newman_json(
        _payload(executions=[_execution(status=500, body=body)]),
        b"",
        tmp_path,
        "postman_newman",
    )
    sidecar_bytes = (tmp_path / EVIDENCE_SIDECAR_NAME).read_bytes()
    assert not _AWS_KEY_RE.search(sidecar_bytes), (
        "raw AWS access key id leaked into postman newman sidecar"
    )
    assert b"REDACTED-TOKEN" in sidecar_bytes


def test_response_preview_truncated(tmp_path: Path) -> None:
    body = "X" * 1024
    parse_postman_newman_json(
        _payload(executions=[_execution(status=500, body=body)]),
        b"",
        tmp_path,
        "postman_newman",
    )
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert len(blob["response_preview"]) <= 210
    assert "…" in blob["response_preview"]


def test_envelope_not_object_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    canonical = tmp_path / "newman.json"
    canonical.write_bytes(b'["not", "envelope"]')
    with caplog.at_level("WARNING"):
        findings = parse_postman_newman_json(b"", b"", tmp_path, "postman_newman")
    assert findings == []
    assert any(
        "postman_newman_parser_envelope_not_object"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_missing_run_returns_empty(tmp_path: Path) -> None:
    payload = json.dumps({"collection": "x"}).encode("utf-8")
    assert parse_postman_newman_json(payload, b"", tmp_path, "postman_newman") == []


def test_findings_have_likely_confidence(tmp_path: Path) -> None:
    findings = parse_postman_newman_json(
        _payload(failures=[_failure()]), b"", tmp_path, "postman_newman"
    )
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(newman_module, "_MAX_FINDINGS", 2)
    payload = _payload(
        failures=[
            _failure(test_name=f"check-{i}", message=f"err-{i}") for i in range(5)
        ]
    )
    with caplog.at_level("WARNING"):
        findings = parse_postman_newman_json(payload, b"", tmp_path, "postman_newman")
    assert len(findings) == 2
    assert any(
        "postman_newman_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_dedup_collapses_duplicate_failures(tmp_path: Path) -> None:
    """Same (kind, request_name, status, message) collapses to one finding."""
    payload = _payload(failures=[_failure(), _failure()])
    findings = parse_postman_newman_json(payload, b"", tmp_path, "postman_newman")
    assert len(findings) == 1


def test_failure_not_object_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Failures that aren't objects are dropped with a debug log."""
    document: dict[str, Any] = {"run": {"failures": ["not-an-object", _failure()]}}
    with caplog.at_level("DEBUG", logger=newman_module._logger.name):
        findings = parse_postman_newman_json(
            json.dumps(document).encode("utf-8"), b"", tmp_path, "postman_newman"
        )
    assert len(findings) == 1
    assert any(
        "postman_newman_parser_failure_not_object"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_failure_without_error_dropped(tmp_path: Path) -> None:
    """A failure without a structured ``error`` body is uninformative — drop it."""
    document: dict[str, Any] = {
        "run": {"failures": [{"source": {"name": "X"}, "error": "string-not-dict"}]}
    }
    findings = parse_postman_newman_json(
        json.dumps(document).encode("utf-8"), b"", tmp_path, "postman_newman"
    )
    assert findings == []


def test_failure_without_message_or_test_dropped(tmp_path: Path) -> None:
    """A failure with empty error.message and error.test must be dropped."""
    document: dict[str, Any] = {
        "run": {"failures": [{"error": {}, "source": {"name": "X"}}]}
    }
    findings = parse_postman_newman_json(
        json.dumps(document).encode("utf-8"), b"", tmp_path, "postman_newman"
    )
    assert findings == []


def test_execution_not_object_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Executions that aren't objects are dropped with a debug log."""
    document: dict[str, Any] = {"run": {"executions": ["bad", _execution()]}}
    with caplog.at_level("DEBUG", logger=newman_module._logger.name):
        findings = parse_postman_newman_json(
            json.dumps(document).encode("utf-8"), b"", tmp_path, "postman_newman"
        )
    assert len(findings) == 1
    assert any(
        "postman_newman_parser_execution_not_object"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_execution_without_response_dropped(tmp_path: Path) -> None:
    """An execution missing the ``response`` object cannot be classified."""
    document: dict[str, Any] = {
        "run": {"executions": [{"item": {"name": "x"}, "request": {"method": "GET"}}]}
    }
    findings = parse_postman_newman_json(
        json.dumps(document).encode("utf-8"), b"", tmp_path, "postman_newman"
    )
    assert findings == []


def test_url_extracted_from_plain_string(tmp_path: Path) -> None:
    """``url`` may be a plain string (older newman builds)."""
    failure = _failure()
    failure["parent"] = {
        "method": "GET",
        "url": "https://api.example.com/legacy-shape",
    }
    document: dict[str, Any] = {"run": {"failures": [failure]}}
    parse_postman_newman_json(
        json.dumps(document).encode("utf-8"), b"", tmp_path, "postman_newman"
    )
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "https://api.example.com/legacy-shape" in sidecar


def test_url_unrecognised_shape_returns_none(tmp_path: Path) -> None:
    """If ``url`` is neither str nor dict, the parser must still run cleanly."""
    failure = _failure()
    failure["parent"] = {"method": "GET", "url": 12345}
    failure["source"] = {"name": "x", "request": {"url": 99999}}
    document: dict[str, Any] = {"run": {"failures": [failure]}}
    findings = parse_postman_newman_json(
        json.dumps(document).encode("utf-8"), b"", tmp_path, "postman_newman"
    )
    assert len(findings) == 1


def test_request_method_from_cursor_field(tmp_path: Path) -> None:
    """The ``cursor.httpRequest`` field is the method when ``parent`` is missing."""
    failure: dict[str, Any] = {
        "cursor": {"httpRequest": "PATCH"},
        "error": {"message": "bad", "test": "x"},
    }
    document: dict[str, Any] = {"run": {"failures": [failure]}}
    parse_postman_newman_json(
        json.dumps(document).encode("utf-8"), b"", tmp_path, "postman_newman"
    )
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["method"] == "PATCH"


def test_long_secret_string_redacted_via_secret_path(tmp_path: Path) -> None:
    """When a body contains the literal word ``secret`` and is long, the
    fallback ``redact_secret`` path collapses it entirely."""
    # 50 chars containing "secret" — exceeds the 32-char threshold and must be redacted.
    body = "Configured secret: SuperLongSecretValue1234567890ABC"
    payload = _payload(executions=[_execution(body=body)])
    parse_postman_newman_json(payload, b"", tmp_path, "postman_newman")
    sidecar_bytes = (tmp_path / EVIDENCE_SIDECAR_NAME).read_bytes()
    assert b"SuperLongSecretValue1234567890ABC" not in sidecar_bytes
    assert b"REDACTED" in sidecar_bytes
