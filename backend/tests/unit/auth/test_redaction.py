"""Secret redaction for session-shaped data (P3-AUTH-003, SI-3)."""

from __future__ import annotations

import json

from src.auth.redaction import (
    REDACTED,
    redact,
    redact_cookie,
    redact_cookie_map,
    redact_cookies,
    redact_headers,
    redact_storage_state,
)


def test_redact_cookie_keeps_metadata_hides_value() -> None:
    out = redact_cookie({"name": "sid", "value": "SECRET", "domain": "x", "path": "/"})
    assert out["value"] == REDACTED
    assert out["name"] == "sid"
    assert out["domain"] == "x"


def test_redact_cookies_list() -> None:
    out = redact_cookies([{"name": "a", "value": "V1"}, {"name": "b", "value": "V2"}])
    assert [c["value"] for c in out] == [REDACTED, REDACTED]
    assert redact_cookies(None) == []


def test_redact_cookie_map() -> None:
    out = redact_cookie_map({"sid": "SECRET"})
    assert out == {"sid": REDACTED}


def test_redact_headers_reuses_evidence_primitive() -> None:
    out, count = redact_headers(
        {"Authorization": "Bearer X", "X-CSRF-Token": "c", "Accept": "application/json"}
    )
    assert out["Authorization"] == REDACTED
    assert out["X-CSRF-Token"] == REDACTED
    assert out["Accept"] == "application/json"
    assert count == 2


def test_redact_storage_state() -> None:
    state = {
        "cookies": [{"name": "sess", "value": "COOKIE_SECRET"}],
        "origins": [
            {
                "origin": "https://app",
                "localStorage": [{"name": "jwt", "value": "LOCAL_SECRET"}],
            }
        ],
    }
    out = redact_storage_state(state)
    serialized = json.dumps(out)
    assert "COOKIE_SECRET" not in serialized
    assert "LOCAL_SECRET" not in serialized
    assert out["cookies"][0]["value"] == REDACTED
    assert out["origins"][0]["localStorage"][0]["value"] == REDACTED


def test_generic_redact_covers_password_token_otp() -> None:
    payload = {"password": "PW", "token": "TK", "otp": "123456", "safe": "keep"}
    serialized = json.dumps(redact(payload))
    assert "PW" not in serialized
    assert "TK" not in serialized
    assert "123456" not in serialized
    assert "keep" in serialized
