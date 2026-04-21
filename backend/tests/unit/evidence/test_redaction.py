"""Unit tests for :mod:`src.evidence.redaction`."""

from __future__ import annotations

import pytest

from src.evidence.redaction import (
    RedactedContent,
    RedactionReport,
    RedactionSpec,
    Redactor,
    default_specs,
)


# ---------------------------------------------------------------------------
# Construction / validation
# ---------------------------------------------------------------------------


def test_default_specs_immutable_tuple() -> None:
    specs = default_specs()
    assert isinstance(specs, tuple)
    assert all(isinstance(s, RedactionSpec) for s in specs)
    assert len(specs) >= 11


def test_invalid_regex_rejected_at_construction() -> None:
    with pytest.raises(ValueError):
        RedactionSpec(name="bad", pattern="[unclosed")


def test_spec_name_must_be_lowercase_snake() -> None:
    with pytest.raises(Exception):
        RedactionSpec(name="Bad-Name", pattern=r"foo")


def test_redactor_rejects_non_bytes() -> None:
    redactor = Redactor()
    with pytest.raises(TypeError):
        redactor.redact("not bytes")  # type: ignore[arg-type]


def test_empty_input_returns_empty() -> None:
    redactor = Redactor()
    out = redactor.redact(b"")
    assert isinstance(out, RedactedContent)
    assert out.content == b""
    assert out.redactions_applied == 0
    assert out.report == ()


# ---------------------------------------------------------------------------
# Default specs — positive cases (each spec must redact a representative match)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "snippet", "should_contain"),
    [
        (
            "bearer_token",
            b"Authorization: Bearer abc.def-XYZ_123\n",
            b"[REDACTED:bearer_token]",
        ),
        (
            "aws_access_key",
            b"key=AKIAABCDEFGHIJKLMNOP next",
            b"[REDACTED:aws_access_key]",
        ),
        ("github_pat", b"GH=ghp_ABCDEFGHIJKLMNOPQRSTUVWX", b"[REDACTED:github_pat]"),
        (
            "slack_token",
            b"slack=xoxb-1234567890-abcdefghij and",
            b"[REDACTED:slack_token]",
        ),
        (
            "private_key_pem",
            (
                b"prefix\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n"
                b"-----END RSA PRIVATE KEY-----\nsuffix"
            ),
            b"[REDACTED:private_key_pem]",
        ),
        (
            "set_cookie",
            b"Set-Cookie: SESSIONID=abc123; Path=/",
            b"[REDACTED:set_cookie]",
        ),
        (
            "cookie_header",
            b"Cookie: SESSIONID=abc123; theme=dark\nNext-Header: ok",
            b"[REDACTED:cookie_header]",
        ),
        (
            "password_in_url",
            b"https://admin:hunter2@example.com/api",
            b"[REDACTED:password_in_url]",
        ),
        ("password_kv", b"password=hunter2 next-field", b"[REDACTED:password_kv]"),
        (
            "jwt",
            b"token=eyJabc.eyJdef.signature123 next",
            b"[REDACTED:jwt]",
        ),
        ("openai_key", b"OPENAI=sk-1234567890abcdef1234ABCD", b"[REDACTED:openai_key]"),
    ],
)
def test_default_spec_positive(
    name: str, snippet: bytes, should_contain: bytes
) -> None:
    redactor = Redactor()
    out = redactor.redact(snippet)
    assert out.redactions_applied >= 1
    assert should_contain in out.content
    assert any(r.name == name for r in out.report)


# ---------------------------------------------------------------------------
# Default specs — negative cases (similar-looking but legitimate strings)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "snippet",
    [
        b"this Bearerbearer is not a token",
        b"AKIA12 short",
        b"ghp_short",
        b"xox unrelated",
        b"-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----",
        b"My password123 is a phrase, not assignment",
        b"sk-short",
        b"https://example.com/path?ratio=1:2",
        b"href https://example.com/safe",
        b"Cookies are tasty",
    ],
)
def test_negative_cases_not_redacted(snippet: bytes) -> None:
    redactor = Redactor()
    out = redactor.redact(snippet)
    assert out.content == snippet
    assert out.redactions_applied == 0


# ---------------------------------------------------------------------------
# Counts / reporting
# ---------------------------------------------------------------------------


def test_multiple_redactions_counted() -> None:
    redactor = Redactor()
    payload = (
        b"Authorization: Bearer abc.def\n"
        b"Authorization: Bearer xyz.123\n"
        b"key=AKIAABCDEFGHIJKLMNOP\n"
    )
    out = redactor.redact(payload)
    assert out.redactions_applied == 3
    by_name = {r.name: r.matches for r in out.report}
    assert by_name.get("bearer_token") == 2
    assert by_name.get("aws_access_key") == 1


def test_report_is_tuple_of_redaction_report() -> None:
    redactor = Redactor()
    out = redactor.redact(b"Bearer abc.def")
    assert isinstance(out.report, tuple)
    assert all(isinstance(r, RedactionReport) for r in out.report)


# ---------------------------------------------------------------------------
# Binary safety
# ---------------------------------------------------------------------------


def test_binary_input_with_high_bytes_does_not_crash() -> None:
    redactor = Redactor()
    payload = b"\xff\xfe\x00binary " + b"Bearer abc.def" + b"\xff\x00\xfe"
    out = redactor.redact(payload)
    assert b"[REDACTED:bearer_token]" in out.content
    assert out.redactions_applied >= 1


def test_invalid_utf8_in_jwt_pattern() -> None:
    redactor = Redactor()
    payload = b"\xff\xfe token=eyJabc.eyJdef.signature \x00"
    out = redactor.redact(payload)
    assert out.redactions_applied >= 1


# ---------------------------------------------------------------------------
# Spec overrides
# ---------------------------------------------------------------------------


def test_disabled_spec_skipped() -> None:
    spec = RedactionSpec(
        name="bearer_token", pattern=r"Bearer\s+[A-Za-z0-9._\-]+", enabled=False
    )
    redactor = Redactor(specs=[spec])
    out = redactor.redact(b"Authorization: Bearer abc.def")
    assert out.redactions_applied == 0
    assert b"Bearer abc.def" in out.content


def test_custom_spec_with_replacement() -> None:
    custom = RedactionSpec(
        name="api_key",
        pattern=r"X-Api-Key:\s*[A-Za-z0-9]+",
        replacement=b"X-Api-Key: SCRUBBED",
    )
    redactor = Redactor(specs=[custom])
    out = redactor.redact(b"GET /\nX-Api-Key: deadbeef\n")
    assert b"X-Api-Key: SCRUBBED" in out.content
    assert out.redactions_applied == 1


def test_per_call_specs_override_constructor() -> None:
    redactor = Redactor()
    payload = b"Authorization: Bearer abc.def\nkey=AKIAABCDEFGHIJKLMNOP"
    only_aws = (RedactionSpec(name="aws_access_key", pattern=r"AKIA[0-9A-Z]{16}"),)
    out = redactor.redact(payload, specs=only_aws)
    assert b"Bearer abc.def" in out.content
    assert b"[REDACTED:aws_access_key]" in out.content
    assert out.redactions_applied == 1


def test_replacement_default_includes_name() -> None:
    spec = RedactionSpec(name="generic_token", pattern=r"TKN-[0-9]+")
    redactor = Redactor(specs=[spec])
    out = redactor.redact(b"tok=TKN-12345 end")
    assert b"[REDACTED:generic_token]" in out.content


def test_redaction_dto_is_frozen() -> None:
    redactor = Redactor()
    out = redactor.redact(b"Bearer abc.def")
    with pytest.raises(Exception):
        out.redactions_applied = 0  # type: ignore[misc]


def test_redactor_specs_property() -> None:
    custom = (RedactionSpec(name="x", pattern=r"x"),)
    redactor = Redactor(specs=custom)
    assert redactor.specs == custom


def test_redactor_default_specs_when_none() -> None:
    redactor = Redactor()
    assert redactor.specs == default_specs()
