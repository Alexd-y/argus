"""Unit tests for proxy HTTP transport/normalization + bounded bodies (WB-P2a)."""

from __future__ import annotations

import hashlib

import pytest

from src.pipeline.contracts.tool_job import TargetKind
from src.web_workbench.proxy.transport import (
    DEFAULT_MAX_CAPTURE_BYTES,
    HttpMessageError,
    NormalizedRequest,
    NormalizedResponse,
    plan_body,
)


def test_request_head_round_trip_preserves_bytes() -> None:
    raw = (
        b"GET /a/b?x=1 HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"X-Dup: one\r\n"
        b"X-Dup: two\r\n"
        b"\r\n"
    )
    req = NormalizedRequest.parse(raw)
    assert req.method == "GET"
    assert req.target == "/a/b?x=1"
    # Duplicate headers and order are preserved.
    assert req.headers == (
        ("Host", "example.com"),
        ("X-Dup", "one"),
        ("X-Dup", "two"),
    )
    assert req.serialize_head() == raw


def test_request_header_lookup_is_case_insensitive() -> None:
    req = NormalizedRequest.parse(b"POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n")
    assert req.header("content-type") == "application/json"
    assert req.header("missing") is None


def test_to_target_spec_absolute_form() -> None:
    req = NormalizedRequest.parse(
        b"GET https://api.example.com/v1?q=1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
    )
    target, port = req.to_target_spec()
    assert target.kind is TargetKind.URL
    assert target.url == "https://api.example.com:443/v1?q=1"
    assert port == 443


def test_to_target_spec_origin_form_uses_host_header() -> None:
    req = NormalizedRequest.parse(b"GET /login HTTP/1.1\r\nHost: app.example.com:8443\r\n\r\n")
    target, port = req.to_target_spec()
    assert target.url == "https://app.example.com:8443/login"
    assert port == 8443


def test_to_target_spec_without_host_raises() -> None:
    req = NormalizedRequest.parse(b"GET /login HTTP/1.1\r\nAccept: */*\r\n\r\n")
    with pytest.raises(HttpMessageError):
        req.to_target_spec()


def test_malformed_request_line_raises() -> None:
    with pytest.raises(HttpMessageError):
        NormalizedRequest.parse(b"GET_ONLY\r\nHost: x\r\n\r\n")


def test_missing_start_line_raises() -> None:
    with pytest.raises(HttpMessageError):
        NormalizedRequest.parse(b"\r\nHost: x\r\n\r\n")


def test_response_round_trip() -> None:
    raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    resp = NormalizedResponse.parse(raw)
    assert resp.status_code == 404
    assert resp.reason == "Not Found"
    assert resp.serialize_head() == raw


def test_plan_body_inline() -> None:
    data = b"hello"
    plan = plan_body(data, max_inline_bytes=10, max_capture_bytes=100)
    assert plan.is_inline
    assert plan.content == data
    assert plan.spill is False
    assert plan.truncated is False
    assert plan.size == 5
    assert plan.sha256 == hashlib.sha256(data).hexdigest()


def test_plan_body_empty_is_inline() -> None:
    plan = plan_body(b"", max_inline_bytes=10, max_capture_bytes=100)
    assert plan.is_inline
    assert plan.content == b""
    assert plan.size == 0


def test_plan_body_spill() -> None:
    data = b"x" * 50
    plan = plan_body(data, max_inline_bytes=10, max_capture_bytes=100)
    assert plan.spill is True
    assert plan.content is None
    assert plan.truncated is False
    assert plan.is_inline is False


def test_plan_body_truncated_drops_body_but_keeps_digest() -> None:
    data = b"y" * 200
    plan = plan_body(data, max_inline_bytes=10, max_capture_bytes=100)
    assert plan.truncated is True
    assert plan.content is None
    assert plan.spill is False
    assert plan.size == 200
    assert plan.sha256 == hashlib.sha256(data).hexdigest()


def test_plan_body_rejects_inline_greater_than_capture() -> None:
    with pytest.raises(ValueError):
        plan_body(b"x", max_inline_bytes=100, max_capture_bytes=10)


def test_plan_body_default_capture_is_bounded() -> None:
    # A body just over the inline default still records size/digest without
    # requiring the full bytes to be retained inline.
    data = b"z" * (65 * 1024)
    plan = plan_body(data)
    assert plan.size == 65 * 1024
    assert plan.spill is True
    assert plan.size <= DEFAULT_MAX_CAPTURE_BYTES
