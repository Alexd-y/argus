"""Tests for evidence redaction and diff bundling."""

from __future__ import annotations

import json

from src.playbooks.actions import HttpExchange, HttpRequestSpec, HttpResponse
from src.playbooks.evidence import (
    REDACTED,
    build_evidence_bundle,
    redact_body,
    redact_headers,
)
from src.playbooks.schema import HttpMethod

_SECRET_TOKEN = "eyJhbGciOiJub25lIn0.super-secret-jwt-value"
_SECRET_PASSWORD = "hunter2-plaintext"


def _exchange(
    *, status: int, body: str, headers: dict[str, str], req_headers: dict[str, str]
) -> HttpExchange:
    return HttpExchange(
        request=HttpRequestSpec(
            method=HttpMethod.POST,
            url="https://target/login?token=" + _SECRET_TOKEN,
            headers=req_headers,
            body=json.dumps({"username": "alice", "password": _SECRET_PASSWORD}),
        ),
        response=HttpResponse(status=status, body=body, headers=headers),
    )


def test_redact_headers_removes_secrets() -> None:
    redacted, count = redact_headers(
        {
            "Authorization": "Bearer " + _SECRET_TOKEN,
            "Cookie": "session=abc",
            "Content-Type": "application/json",
        }
    )
    assert redacted["Authorization"] == REDACTED
    assert redacted["Cookie"] == REDACTED
    assert redacted["Content-Type"] == "application/json"
    assert count == 2


def test_redact_body_json_removes_secret_values() -> None:
    body = json.dumps({"password": _SECRET_PASSWORD, "otp": "123456", "keep": "ok"})
    redacted, count = redact_body(body)
    assert redacted is not None
    assert _SECRET_PASSWORD not in redacted
    assert "123456" not in redacted
    assert "ok" in redacted
    assert count == 2


def test_redact_body_raw_form() -> None:
    redacted, count = redact_body("username=alice&password=" + _SECRET_PASSWORD)
    assert redacted is not None
    assert _SECRET_PASSWORD not in redacted
    assert count >= 1


def test_bundle_has_no_secrets_and_counts_redactions() -> None:
    baseline = _exchange(
        status=200,
        body=json.dumps({"email": "victim@x.com", "access_token": _SECRET_TOKEN}),
        headers={"Set-Cookie": "sid=" + _SECRET_TOKEN},
        req_headers={"Authorization": "Bearer " + _SECRET_TOKEN},
    )
    mutated = _exchange(
        status=200,
        body=json.dumps({"email": "victim@x.com", "access_token": _SECRET_TOKEN}),
        headers={"Set-Cookie": "sid=" + _SECRET_TOKEN},
        req_headers={"Authorization": "Bearer " + _SECRET_TOKEN},
    )
    bundle = build_evidence_bundle(baseline, mutated)

    serialized = bundle.canonical_json()
    assert _SECRET_TOKEN not in serialized
    assert _SECRET_PASSWORD not in serialized
    assert bundle.redactions_applied > 0
    # sha256 is stable and hex
    digest = bundle.sha256()
    assert len(digest) == 64
    assert digest == bundle.sha256()


def test_bundle_diff_detects_status_change() -> None:
    baseline = _exchange(status=200, body="{}", headers={}, req_headers={})
    mutated = _exchange(status=403, body="{}", headers={}, req_headers={})
    bundle = build_evidence_bundle(baseline, mutated)
    assert bundle.diff.status_changed is True
    assert bundle.diff.baseline_status == 200
    assert bundle.diff.mutated_status == 403
