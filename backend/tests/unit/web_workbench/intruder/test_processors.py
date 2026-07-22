"""Unit tests for the Intruder payload processor chain."""

from __future__ import annotations

import base64

import pytest

from src.web_workbench.intruder.processors import (
    Processor,
    ProcessorError,
    apply_processors,
)


def test_prefix_and_suffix() -> None:
    out = apply_processors(
        b"core",
        [Processor("prefix", {"value": "<"}), Processor("suffix", {"value": ">"})],
    )
    assert out == b"<core>"


def test_encode_url() -> None:
    assert apply_processors(b"a b&c", [Processor("encode", {"scheme": "url"})]) == b"a%20b%26c"


def test_encode_base64() -> None:
    out = apply_processors(b"payload", [Processor("encode", {"scheme": "base64"})])
    assert base64.b64decode(out) == b"payload"


def test_encode_hex() -> None:
    assert apply_processors(b"AB", [Processor("encode", {"scheme": "hex"})]) == b"4142"


def test_encode_html() -> None:
    assert apply_processors(b"<x>", [Processor("encode", {"scheme": "html"})]) == b"&lt;x&gt;"


def test_hash_sha256() -> None:
    out = apply_processors(b"", [Processor("hash", {"algorithm": "sha256"})])
    assert out == b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_regex_replace() -> None:
    out = apply_processors(
        b"id=123",
        [Processor("regex_replace", {"pattern": r"\d+", "replacement": "X"})],
    )
    assert out == b"id=X"


def test_regex_replace_with_count() -> None:
    out = apply_processors(
        b"aaa",
        [Processor("regex_replace", {"pattern": "a", "replacement": "b", "count": 2})],
    )
    assert out == b"bba"


def test_chain_order_is_respected() -> None:
    # base64 then prefix: prefix wraps the encoded value, not the raw payload.
    out = apply_processors(
        b"x",
        [Processor("encode", {"scheme": "base64"}), Processor("prefix", {"value": "P:"})],
    )
    assert out.startswith(b"P:")
    assert base64.b64decode(out[2:]) == b"x"


def test_unknown_kind_raises() -> None:
    with pytest.raises(ProcessorError, match="unknown processor kind"):
        apply_processors(b"x", [Processor("nope")])


def test_unknown_encode_scheme_raises() -> None:
    with pytest.raises(ProcessorError, match="unknown encode scheme"):
        apply_processors(b"x", [Processor("encode", {"scheme": "rot13"})])


def test_missing_param_raises() -> None:
    with pytest.raises(ProcessorError, match="string param"):
        apply_processors(b"x", [Processor("prefix")])


def test_negative_count_raises() -> None:
    with pytest.raises(ProcessorError, match="non-negative"):
        apply_processors(
            b"x",
            [Processor("regex_replace", {"pattern": "x", "replacement": "y", "count": -1})],
        )
