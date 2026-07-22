"""Offline unit tests for :class:`HttpxSender` via ``httpx.MockTransport``.

No real network: a ``MockTransport`` handler captures the outgoing request and
returns a canned response, so we verify URL/method/header derivation, hop-by-hop
stripping, bounded response reads, and raw response serialization deterministically.
"""

from __future__ import annotations

import httpx
import pytest

from src.web_workbench.proxy.transport import NormalizedRequest
from src.web_workbench.repeater.sender import HttpxSender


def _request(raw: bytes) -> NormalizedRequest:
    return NormalizedRequest.parse(raw)


def test_send_derives_url_method_and_forwards_headers() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["x_test"] = request.headers.get("x-test")
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"ok")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    sender = HttpxSender(client=client)
    req = _request(
        b"GET http://in.example.com/path?q=1 HTTP/1.1\r\n"
        b"Host: in.example.com\r\nX-Test: yes\r\nContent-Length: 0\r\n\r\n"
    )

    resp = sender.send(req, b"")

    assert captured["method"] == "GET"
    assert captured["url"] == "http://in.example.com/path?q=1"
    assert captured["x_test"] == "yes"
    assert resp.status_code == 200
    assert resp.truncated is False
    assert resp.raw.startswith(b"HTTP/1.1 200 OK\r\n")
    assert resp.raw.endswith(b"ok")


def test_send_strips_framing_headers_to_avoid_corruption() -> None:
    seen: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        # A stale Transfer-Encoding/Content-Length from the edited request must
        # NOT be forwarded — httpx owns framing for the body we pass. (httpx adds
        # its own Connection header regardless, so that one is not asserted here.)
        seen["transfer_encoding"] = request.headers.get("transfer-encoding")
        # httpx recomputes Content-Length from the body (2 bytes), not the stale 999.
        seen["content_length"] = request.headers.get("content-length")
        return httpx.Response(204)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    sender = HttpxSender(client=client)
    req = _request(
        b"POST http://in.example.com/ HTTP/1.1\r\n"
        b"Host: in.example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\n\r\n"
    )

    sender.send(req, b"hi")

    assert seen["transfer_encoding"] is None
    assert seen["content_length"] == "2"


def test_send_bounds_response_body_and_flags_truncation() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"A" * 100)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    sender = HttpxSender(client=client, max_response_bytes=10)
    req = _request(b"GET http://in.example.com/ HTTP/1.1\r\nHost: in.example.com\r\n\r\n")

    resp = sender.send(req, b"")

    assert resp.truncated is True
    # Head + at most 10 body bytes retained.
    assert resp.raw.endswith(b"A" * 10)
    assert b"A" * 11 not in resp.raw


def test_send_small_body_not_truncated() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"hello")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    sender = HttpxSender(client=client, max_response_bytes=1024)
    req = _request(b"GET http://in.example.com/ HTTP/1.1\r\nHost: in.example.com\r\n\r\n")

    resp = sender.send(req, b"")

    assert resp.truncated is False
    assert resp.raw.endswith(b"hello")


def test_negative_cap_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        HttpxSender(max_response_bytes=-1)
