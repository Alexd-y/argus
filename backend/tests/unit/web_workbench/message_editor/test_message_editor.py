"""Unit tests for the message editor: raw/pretty/hex + byte-exact override (WB-P3b)."""

from __future__ import annotations

import pytest

from src.web_workbench.message_editor.engine import (
    HttpMessageError,
    RawHttpMessage,
    hex_dump,
    parse_request,
    pretty_request,
    pretty_response,
)

_RAW_REQUEST = (
    b"POST /login HTTP/1.1\r\n"
    b"Host: app.example.com\r\n"
    b"Content-Type: application/json\r\n"
    b"X-Dup: a\r\n"
    b"X-Dup: b\r\n"
    b"\r\n"
    b'{"user":"admin","pass":"x"}'
)

_RAW_RESPONSE = b"HTTP/1.1 200 OK\r\n" b"Content-Type: text/html\r\n" b"\r\n" b"<html>hi</html>"


def test_raw_message_splits_head_and_body_byte_exact() -> None:
    message = RawHttpMessage.from_bytes(_RAW_REQUEST)
    assert message.raw == _RAW_REQUEST
    assert message.body == b'{"user":"admin","pass":"x"}'
    assert message.head.startswith(b"POST /login HTTP/1.1")
    assert b"\r\n\r\n" not in message.head


def test_raw_message_no_body() -> None:
    raw = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    message = RawHttpMessage.from_bytes(raw)
    assert message.body == b""
    assert message.raw == raw


def test_with_body_preserves_head_bytes_exactly() -> None:
    message = RawHttpMessage.from_bytes(_RAW_REQUEST)
    edited = message.with_body(b"tampered")
    # Head bytes are identical; only the body changed (no Content-Length rewrite).
    assert edited.head == message.head
    assert edited.body == b"tampered"
    assert edited.raw == message.head + b"\r\n\r\n" + b"tampered"


def test_pretty_request_preserves_duplicate_headers_and_pretty_json() -> None:
    pretty = pretty_request(_RAW_REQUEST)
    assert pretty.startswith("POST /login HTTP/1.1")
    # Duplicate header preserved (order + both values).
    assert "X-Dup: a" in pretty
    assert "X-Dup: b" in pretty
    # JSON body indented.
    assert '"user": "admin"' in pretty


def test_pretty_response_renders_status_and_body() -> None:
    pretty = pretty_response(_RAW_RESPONSE)
    assert pretty.startswith("HTTP/1.1 200 OK")
    assert "<html>hi</html>" in pretty


def test_pretty_request_rejects_malformed_head() -> None:
    with pytest.raises(HttpMessageError):
        pretty_request(b"this is not http\r\n\r\n")


def test_parse_request_round_trips_head() -> None:
    request = parse_request(_RAW_REQUEST)
    # serialize_head reproduces the exact original head + CRLF-CRLF terminator.
    assert request.serialize_head() == RawHttpMessage.from_bytes(_RAW_REQUEST).head + b"\r\n\r\n"


def test_hex_dump_format() -> None:
    dump = hex_dump(b"ABC\x00\xff")
    assert dump.startswith("00000000  ")
    # Printable chars shown; non-printable become '.'.
    assert "|ABC..|" in dump


def test_hex_dump_multiple_rows_and_offsets() -> None:
    data = bytes(range(32))
    dump = hex_dump(data, width=16)
    rows = dump.splitlines()
    assert len(rows) == 2
    assert rows[1].startswith("00000010  ")


def test_hex_dump_rejects_bad_width() -> None:
    with pytest.raises(ValueError):
        hex_dump(b"x", width=0)
