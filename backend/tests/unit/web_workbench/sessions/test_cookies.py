"""Unit tests for session cookie helpers (WB-P6b, pure)."""

from __future__ import annotations

from src.web_workbench.proxy.transport import NormalizedResponse
from src.web_workbench.sessions.cookies import (
    cookie_header_value,
    inject_cookie_header,
    merge_cookie_header,
    parse_set_cookies,
)


def _response(*set_cookies: str) -> NormalizedResponse:
    headers = tuple(("Set-Cookie", value) for value in set_cookies)
    return NormalizedResponse(
        http_version="HTTP/1.1", status_code=200, reason="OK", headers=headers
    )


def test_parse_set_cookies_strips_attributes() -> None:
    resp = _response("session=abc; Path=/; HttpOnly", "csrf=zzz; Secure")
    assert parse_set_cookies(resp) == {"session": "abc", "csrf": "zzz"}


def test_parse_set_cookies_last_wins() -> None:
    resp = _response("session=old; Path=/", "session=new; Path=/")
    assert parse_set_cookies(resp) == {"session": "new"}


def test_merge_cookie_header_new_cookies_win() -> None:
    merged = merge_cookie_header("a=1; b=2", {"b": "9", "c": "3"})
    assert merged == "a=1; b=9; c=3"


def test_cookie_header_value_renders_jar() -> None:
    assert cookie_header_value({"a": "1", "b": "2"}) == "a=1; b=2"


def test_inject_cookie_header_replaces_existing_and_keeps_body() -> None:
    raw = b"POST /login HTTP/1.1\r\nHost: app.example.com\r\nCookie: stale=1\r\n\r\nbody=1"
    out = inject_cookie_header(raw, "session=abc")
    assert b"Cookie: session=abc" in out
    assert b"stale=1" not in out
    assert out.endswith(b"\r\n\r\nbody=1")
    assert b"Host: app.example.com" in out


def test_inject_cookie_header_noop_on_empty_value() -> None:
    raw = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    assert inject_cookie_header(raw, "") == raw
