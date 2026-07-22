"""Unit tests for the Decoder transform engine (WB-P3a)."""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json

import pytest

from src.web_workbench.decoder.engine import (
    DecoderError,
    TransformContext,
    TransformStep,
    available_operations,
    run_pipeline,
)


def _step(operation: str, **options: str) -> TransformStep:
    return TransformStep(operation=operation, options=options)


def test_empty_pipeline_is_byte_exact_identity() -> None:
    data = b"\x00\x01\xfe\xff raw bytes"
    assert run_pipeline(data, []) == data


def test_url_round_trip() -> None:
    data = "a b&c=+%".encode()
    encoded = run_pipeline(data, [_step("url_encode")])
    assert b" " not in encoded
    assert run_pipeline(encoded, [_step("url_decode")]) == data


@pytest.mark.parametrize(
    ("enc", "dec"),
    [
        ("base64_encode", "base64_decode"),
        ("base64url_encode", "base64url_decode"),
        ("hex_encode", "hex_decode"),
    ],
)
def test_reversible_round_trips(enc: str, dec: str) -> None:
    data = b"\x00\xde\xad\xbe\xef payload"
    assert run_pipeline(run_pipeline(data, [_step(enc)]), [_step(dec)]) == data


def test_chained_pipeline_applies_in_order() -> None:
    data = b"hello"
    # base64 then hex-encode the base64 text.
    out = run_pipeline(data, [_step("base64_encode"), _step("hex_encode")])
    assert out == base64.b64encode(data).hex().encode("ascii")


def test_base64_decode_rejects_garbage() -> None:
    with pytest.raises(DecoderError):
        run_pipeline(b"!!!not base64!!!", [_step("base64_decode")])


def test_base64url_decode_tolerates_missing_padding() -> None:
    raw = b"\x01\x02\x03\x04\x05"
    no_pad = base64.urlsafe_b64encode(raw).rstrip(b"=")
    assert run_pipeline(no_pad, [_step("base64url_decode")]) == raw


def test_gzip_round_trip_and_bad_input() -> None:
    data = b"compress me" * 100
    blob = gzip.compress(data)
    assert run_pipeline(blob, [_step("gzip_decompress")]) == data
    assert run_pipeline(data, [_step("gzip_compress"), _step("gzip_decompress")]) == data
    with pytest.raises(DecoderError):
        run_pipeline(b"not-gzip", [_step("gzip_decompress")])


def test_html_round_trip() -> None:
    data = b"<script>alert(1)</script>"
    encoded = run_pipeline(data, [_step("html_encode")])
    assert b"<script>" not in encoded
    assert run_pipeline(encoded, [_step("html_decode")]) == data


def test_jwt_decode_extracts_header_and_payload_without_verifying() -> None:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=")
    payload = base64.urlsafe_b64encode(b'{"sub":"42","admin":true}').rstrip(b"=")
    token = header + b"." + payload + b".signaturebytes"
    decoded = json.loads(run_pipeline(token, [_step("jwt_decode")]))
    assert decoded["header"]["alg"] == "HS256"
    assert decoded["payload"]["sub"] == "42"
    assert decoded["signature_present"] is True
    assert decoded["signature_verified"] is False


def test_jwt_decode_rejects_non_jwt() -> None:
    with pytest.raises(DecoderError):
        run_pipeline(b"single-segment", [_step("jwt_decode")])


def test_unkeyed_hash_matches_hashlib() -> None:
    data = b"argus"
    out = run_pipeline(data, [_step("hash", algorithm="sha256")])
    assert out == hashlib.sha256(data).hexdigest().encode("ascii")


def test_hash_rejects_unknown_algorithm() -> None:
    with pytest.raises(DecoderError):
        run_pipeline(b"x", [_step("hash", algorithm="crc32")])


def test_hmac_requires_resolver_fail_closed() -> None:
    with pytest.raises(DecoderError, match="no secret resolver"):
        run_pipeline(b"x", [_step("hmac", algorithm="sha256", secret_ref="k1")])


def test_hmac_uses_resolved_secret() -> None:
    key = b"super-secret-key"
    ctx = TransformContext(secret_resolver=lambda ref: key if ref == "k1" else b"")
    data = b"message"
    out = run_pipeline(data, [_step("hmac", algorithm="sha256", secret_ref="k1")], context=ctx)
    assert out == hmac.new(key, data, "sha256").hexdigest().encode("ascii")


def test_hmac_requires_secret_ref() -> None:
    ctx = TransformContext(secret_resolver=lambda _ref: b"k")
    with pytest.raises(DecoderError, match="secret_ref"):
        run_pipeline(b"x", [_step("hmac", algorithm="sha256")], context=ctx)


def test_inline_secret_options_rejected() -> None:
    ctx = TransformContext(secret_resolver=lambda _ref: b"k")
    step = TransformStep(operation="hmac", options={"algorithm": "sha256", "key": "leak"})
    with pytest.raises(DecoderError, match="inline secret"):
        run_pipeline(b"x", [step], context=ctx)


def test_unknown_operation_rejected() -> None:
    with pytest.raises(DecoderError, match="unknown operation"):
        run_pipeline(b"x", [_step("rot13")])


def test_available_operations_is_sorted_and_complete() -> None:
    ops = available_operations()
    assert ops == tuple(sorted(ops))
    assert {"url_encode", "base64_decode", "jwt_decode", "hmac"}.issubset(ops)
