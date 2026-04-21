"""Unit tests for :mod:`src.payloads.encoders` (ARG-005, Backlog/dev1_md §7).

Encoder functions are pure — same input, same output, no I/O — so the
tests can be small, deterministic, and exhaustive over the registry.
"""

from __future__ import annotations

import base64
import urllib.parse

import pytest

from src.payloads.encoders import (
    ENCODER_NAMES,
    UnknownEncoderError,
    apply_pipeline,
    encode_base64,
    encode_double_url,
    encode_hex_concat,
    encode_hex_x,
    encode_html,
    encode_identity,
    encode_unicode_escape,
    encode_url,
    get_encoder,
)


# ---------------------------------------------------------------------------
# Registry shape
# ---------------------------------------------------------------------------


def test_encoder_registry_contains_expected_stages() -> None:
    """Spec change requires touching this test — guards against silent additions."""
    assert ENCODER_NAMES == frozenset(
        {
            "identity",
            "url",
            "url_double",
            "html",
            "base64",
            "unicode_escape",
            "hex_x",
            "hex_concat",
        }
    )


def test_get_encoder_unknown_stage_raises_with_named_attr() -> None:
    with pytest.raises(UnknownEncoderError) as exc_info:
        get_encoder("does-not-exist")
    assert exc_info.value.stage == "does-not-exist"


# ---------------------------------------------------------------------------
# Per-encoder behaviour
# ---------------------------------------------------------------------------


def test_encode_identity_is_pass_through() -> None:
    assert encode_identity("anything goes") == "anything goes"
    assert encode_identity("") == ""


@pytest.mark.parametrize(
    ("plain", "encoded"),
    [
        ("' OR '1'='1", "%27%20OR%20%271%27%3D%271"),
        ("hello world", "hello%20world"),
        ("a/b?c=d&e=f", "a%2Fb%3Fc%3Dd%26e%3Df"),
        ("safe.tilde~hyphen-_", "safe.tilde~hyphen-_"),
        ("", ""),
    ],
)
def test_encode_url_matches_rfc3986_unreserved_set(plain: str, encoded: str) -> None:
    assert encode_url(plain) == encoded
    # And the result is idempotent through urllib.parse.unquote.
    assert urllib.parse.unquote(encoded) == plain


def test_encode_double_url_decodes_twice_back_to_original() -> None:
    original = "<script>alert(1)</script>"
    twice = encode_double_url(original)
    assert urllib.parse.unquote(urllib.parse.unquote(twice)) == original


def test_encode_html_escapes_xss_metacharacters() -> None:
    assert (
        encode_html("<img src=x onerror=alert(1)>")
        == "&lt;img src&#x3D;x onerror&#x3D;alert(1)&gt;"
    )
    assert encode_html('"quoted\'text"') == "&quot;quoted&#x27;text&quot;"


def test_encode_base64_round_trips() -> None:
    plain = "hello {canary}!"
    enc = encode_base64(plain)
    assert base64.b64decode(enc).decode("utf-8") == plain


def test_encode_unicode_escape_renders_each_codepoint() -> None:
    assert encode_unicode_escape("Aa") == "\\u0041\\u0061"
    # Smoke test on a non-ASCII character (Cyrillic а — homoglyph).
    assert encode_unicode_escape("\u0430") == "\\u0430"


def test_encode_unicode_escape_handles_supplementary_plane() -> None:
    # U+1F600 (grinning face) -> surrogate pair.
    assert encode_unicode_escape("\U0001f600") == "\\ud83d\\ude00"


def test_encode_hex_x_renders_each_byte() -> None:
    assert encode_hex_x("Aa") == "\\x41\\x61"
    assert encode_hex_x("") == ""
    # Multi-byte UTF-8 expansion.
    assert encode_hex_x("\u00e9") == "\\xc3\\xa9"  # é


def test_encode_hex_concat_renders_sql_literal() -> None:
    assert encode_hex_concat("Aa") == "0x4161"
    assert encode_hex_concat("") == "0x"


# ---------------------------------------------------------------------------
# Pipeline composition
# ---------------------------------------------------------------------------


def test_apply_pipeline_with_no_stages_is_pass_through() -> None:
    assert apply_pipeline("anything", []) == "anything"


def test_apply_pipeline_chains_left_to_right() -> None:
    # url -> base64 means: first percent-encode, then base64-encode the result.
    out = apply_pipeline("a b", ["url", "base64"])
    expected = base64.b64encode(b"a%20b").decode("ascii")
    assert out == expected


def test_apply_pipeline_unknown_stage_raises_unknown_encoder_error() -> None:
    with pytest.raises(UnknownEncoderError):
        apply_pipeline("payload", ["url", "ghost"])
