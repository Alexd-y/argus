"""Cookie helpers for session macro replay + authorization diffing (WB-P6b).

Pure, deterministic helpers to (a) extract cookies from a captured response's
``Set-Cookie`` headers and (b) inject a ``Cookie`` header into a raw request head
while preserving every other byte. Session macro replay uses these to carry a
freshly-established session across steps and to fire the authorization target
request as each principal.

Cookie *values* here are session artefacts obtained during the engagement (not
long-lived secrets from the secret plane); they are handled in-memory and are
never logged.
"""

from __future__ import annotations

from src.web_workbench.proxy.transport import NormalizedResponse

_CRLF = b"\r\n"
_HEADER_SEP = b"\r\n\r\n"


def parse_set_cookies(response: NormalizedResponse) -> dict[str, str]:
    """Return ``{name: value}`` for every ``Set-Cookie`` header (last wins).

    Only the ``name=value`` pair before the first ``;`` is kept; attributes
    (``Path``/``Secure``/``HttpOnly``/…) are irrelevant for replaying the cookie
    back to the same origin and are dropped.
    """
    cookies: dict[str, str] = {}
    for name, value in response.headers:
        if name.lower() != "set-cookie":
            continue
        pair = value.split(";", 1)[0].strip()
        key, sep, val = pair.partition("=")
        if sep and key:
            cookies[key.strip()] = val.strip()
    return cookies


def merge_cookie_header(existing: str | None, cookies: dict[str, str]) -> str:
    """Merge ``cookies`` into an existing ``Cookie`` header value (cookies win)."""
    jar: dict[str, str] = {}
    if existing:
        for chunk in existing.split(";"):
            key, sep, val = chunk.strip().partition("=")
            if sep and key:
                jar[key.strip()] = val.strip()
    jar.update(cookies)
    return "; ".join(f"{k}={v}" for k, v in jar.items())


def cookie_header_value(cookies: dict[str, str]) -> str:
    """Render a ``Cookie`` header value from a cookie jar."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def inject_cookie_header(raw: bytes, cookie_value: str) -> bytes:
    """Return ``raw`` with its ``Cookie`` header set to ``cookie_value``.

    Any existing ``Cookie`` header lines are replaced; every other byte of the
    head is preserved and the body is untouched. If ``cookie_value`` is empty
    the request is returned unchanged.
    """
    if not cookie_value:
        return raw
    sep_index = raw.find(_HEADER_SEP)
    head = raw if sep_index == -1 else raw[:sep_index]
    body = b"" if sep_index == -1 else raw[sep_index + len(_HEADER_SEP) :]
    lines = head.split(_CRLF)
    if not lines:
        return raw
    start_line = lines[0]
    kept: list[bytes] = [
        line for line in lines[1:] if line and not line.lower().startswith(b"cookie:")
    ]
    kept.append(b"Cookie: " + cookie_value.encode("latin-1"))
    rebuilt_head = _CRLF.join([start_line, *kept])
    return rebuilt_head + _HEADER_SEP + body


__all__ = [
    "cookie_header_value",
    "inject_cookie_header",
    "merge_cookie_header",
    "parse_set_cookies",
]
