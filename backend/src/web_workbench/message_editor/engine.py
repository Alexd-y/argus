"""Message editor: raw / pretty / hex views with byte-exact raw-override (WB-P3b).

The workbench analogue of Burp's message editor tabs. The cardinal invariant is
**byte-exact raw fidelity**: the editor never reconstructs a message from its
normalized view for transport — it preserves the exact raw bytes the operator
sees/edits, so replay is faithful (a manually crafted malformed request stays
malformed on the wire). The pretty/hex views are *derived, read-only*
projections for human inspection only.

* ``RawHttpMessage`` splits a raw message into head + body at the first CRLF-CRLF
  while retaining the original bytes verbatim; ``with_body`` swaps the body but
  keeps the head bytes exactly (no Content-Length auto-rewrite — the operator is
  in control).
* :func:`pretty_request` / :func:`pretty_response` render a normalized,
  human-readable view (JSON bodies are indented when the content type says so).
* :func:`hex_dump` renders a classic offset/hex/ASCII dump.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from src.web_workbench.proxy.transport import (
    HttpMessageError,
    NormalizedRequest,
    NormalizedResponse,
)

_HEADER_SEP: bytes = b"\r\n\r\n"
#: Cap the pretty body preview so a huge body never balloons a JSON response.
_MAX_BODY_PREVIEW: int = 64 * 1024


@dataclass(frozen=True)
class RawHttpMessage:
    """A raw HTTP message split into head + body with the original bytes kept."""

    raw: bytes
    head: bytes
    body: bytes

    @classmethod
    def from_bytes(cls, raw: bytes) -> RawHttpMessage:
        """Split ``raw`` at the first CRLF-CRLF (body is empty if none present)."""
        index = raw.find(_HEADER_SEP)
        if index == -1:
            return cls(raw=raw, head=raw, body=b"")
        head = raw[:index]
        body = raw[index + len(_HEADER_SEP) :]
        return cls(raw=raw, head=head, body=body)

    def with_body(self, new_body: bytes) -> RawHttpMessage:
        """Return a copy with ``new_body`` but the head bytes preserved exactly."""
        return RawHttpMessage.from_bytes(self.head + _HEADER_SEP + new_body)


def _content_type(headers: tuple[tuple[str, str], ...]) -> str:
    for name, value in headers:
        if name.lower() == "content-type":
            return value.lower()
    return ""


def _render_body(body: bytes, content_type: str) -> str:
    if not body:
        return ""
    preview = body[:_MAX_BODY_PREVIEW]
    if "json" in content_type:
        try:
            parsed = json.loads(preview)
            return json.dumps(parsed, ensure_ascii=False, indent=2)
        except json.JSONDecodeError:
            pass
    text = preview.decode("utf-8", "replace")
    if len(body) > _MAX_BODY_PREVIEW:
        text += f"\n... [{len(body) - _MAX_BODY_PREVIEW} more bytes truncated]"
    return text


def parse_request(raw: bytes) -> NormalizedRequest:
    """Parse the request head into a normalized view (raises on malformed head)."""
    return NormalizedRequest.parse(raw)


def parse_response(raw: bytes) -> NormalizedResponse:
    """Parse the response head into a normalized view (raises on malformed head)."""
    return NormalizedResponse.parse(raw)


def pretty_request(raw: bytes) -> str:
    """Render a human-readable request view (raises :class:`HttpMessageError`)."""
    request = NormalizedRequest.parse(raw)
    message = RawHttpMessage.from_bytes(raw)
    lines = [f"{request.method} {request.target} {request.http_version}"]
    lines.extend(f"{name}: {value}" for name, value in request.headers)
    body = _render_body(message.body, _content_type(request.headers))
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines)


def pretty_response(raw: bytes) -> str:
    """Render a human-readable response view (raises :class:`HttpMessageError`)."""
    response = NormalizedResponse.parse(raw)
    message = RawHttpMessage.from_bytes(raw)
    reason = f" {response.reason}" if response.reason else ""
    lines = [f"{response.http_version} {response.status_code}{reason}"]
    lines.extend(f"{name}: {value}" for name, value in response.headers)
    body = _render_body(message.body, _content_type(response.headers))
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines)


def hex_dump(data: bytes, *, width: int = 16) -> str:
    """Render a classic ``offset  hex  |ascii|`` dump of ``data``."""
    if width <= 0:
        raise ValueError("width must be positive")
    rows: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        rows.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")
    return "\n".join(rows)


__all__ = [
    "HttpMessageError",
    "RawHttpMessage",
    "hex_dump",
    "parse_request",
    "parse_response",
    "pretty_request",
    "pretty_response",
]
