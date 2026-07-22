"""HTTP message normalization with byte-exact raw preservation (WB-P2a, ADR-WB-3).

The workbench stores every captured message in *two* representations:

* the **raw** bytes exactly as they crossed the wire (never mutated — required
  for faithful replay and evidence), and
* a **normalized** view (method, target, headers as an ordered list) that tools
  reason over.

This module parses raw HTTP/1.x head sections into the normalized view while
guaranteeing a lossless round-trip of the *head* (:func:`NormalizedRequest.
serialize_head` reproduces the original head bytes). Header order and duplicate
headers are preserved; names are matched case-insensitively but the on-wire
casing is retained.

Bodies are handled by :func:`plan_body`, which enforces the "no unbounded
in-memory bodies" invariant: every body is hashed (sha256) and size-measured,
small bodies are retained inline, medium bodies are marked for object-store
spill, and bodies larger than a hard capture cap are dropped (digest + size
still recorded, ``truncated=True``) rather than buffered without bound.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from src.pipeline.contracts.tool_job import TargetKind, TargetSpec

_CRLF: bytes = b"\r\n"
_HEADER_SEP: bytes = b"\r\n\r\n"
_MAX_HEAD_BYTES: int = 256 * 1024  # 256 KiB head cap — defends against abuse.

#: Default inline retention cap (bytes). Bodies at or below this are stored
#: inline in the DB; larger ones spill to the object store.
DEFAULT_MAX_INLINE_BYTES: int = 64 * 1024
#: Default hard capture cap (bytes). Bodies above this are dropped (only the
#: sha256 + size are retained) — the proxy never buffers them without bound.
DEFAULT_MAX_CAPTURE_BYTES: int = 32 * 1024 * 1024


class HttpMessageError(ValueError):
    """Raised when a raw HTTP head cannot be parsed into the normalized view."""


# ---------------------------------------------------------------------------
# Header primitives — order + on-wire casing preserving.
# ---------------------------------------------------------------------------


HeaderPair = tuple[str, str]


def _parse_head(raw: bytes) -> tuple[bytes, tuple[HeaderPair, ...]]:
    """Split ``raw`` at the blank line and parse the start line + headers.

    Returns ``(start_line_bytes, header_pairs)``. Raises
    :class:`HttpMessageError` on a missing separator, an oversized head, an
    empty start line, or a malformed header line.
    """
    if len(raw) > _MAX_HEAD_BYTES and _HEADER_SEP not in raw[:_MAX_HEAD_BYTES]:
        raise HttpMessageError("http head exceeds maximum size")
    sep_index = raw.find(_HEADER_SEP)
    head = raw if sep_index == -1 else raw[:sep_index]
    if len(head) > _MAX_HEAD_BYTES:
        raise HttpMessageError("http head exceeds maximum size")
    lines = head.split(_CRLF)
    if not lines or not lines[0]:
        raise HttpMessageError("missing http start line")
    start_line = lines[0]
    headers: list[HeaderPair] = []
    for line in lines[1:]:
        if not line:
            continue
        name, colon, value = line.partition(b":")
        if not colon or not name:
            raise HttpMessageError("malformed http header line")
        try:
            headers.append((name.decode("latin-1"), value.strip().decode("latin-1")))
        except UnicodeDecodeError as exc:  # pragma: no cover - latin-1 is total
            raise HttpMessageError("undecodable http header") from exc
    return start_line, tuple(headers)


def _header_lines(headers: tuple[HeaderPair, ...]) -> bytes:
    return b"".join(f"{name}: {value}".encode("latin-1") + _CRLF for name, value in headers)


def _find_header(headers: tuple[HeaderPair, ...], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers:
        if key.lower() == lowered:
            return value
    return None


# ---------------------------------------------------------------------------
# Normalized request / response
# ---------------------------------------------------------------------------


class NormalizedRequest(BaseModel):
    """Normalized HTTP request head (body handled separately by ``plan_body``)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: StrictStr = Field(min_length=1, max_length=32)
    target: StrictStr = Field(min_length=1, max_length=8192)
    http_version: StrictStr = Field(max_length=16)
    headers: tuple[HeaderPair, ...] = Field(default_factory=tuple)

    @classmethod
    def parse(cls, raw: bytes) -> NormalizedRequest:
        """Parse the head of a raw HTTP/1.x request."""
        start_line, headers = _parse_head(raw)
        parts = start_line.split(b" ")
        if len(parts) != 3:
            raise HttpMessageError("malformed http request line")
        method, target, version = parts
        return cls(
            method=method.decode("latin-1"),
            target=target.decode("latin-1"),
            http_version=version.decode("latin-1"),
            headers=headers,
        )

    def serialize_head(self) -> bytes:
        """Reproduce the raw head bytes (lossless round-trip of the head)."""
        start = f"{self.method} {self.target} {self.http_version}".encode("latin-1")
        return start + _CRLF + _header_lines(self.headers) + _CRLF

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup (first match, on-wire value)."""
        return _find_header(self.headers, name)

    def host_header(self) -> str | None:
        return self.header("Host")

    def to_target_spec(self, *, default_scheme: str = "https") -> tuple[TargetSpec, int]:
        """Derive a :class:`TargetSpec` (+port) for the scope gate.

        Uses the absolute request target when present (proxy-form), otherwise
        combines the ``Host`` header with the origin-form path. The returned
        :class:`TargetSpec` is always ``kind=URL`` so it round-trips through
        the shared :class:`~src.policy.scope.ScopeEngine`.
        """
        target = self.target
        if target.startswith(("http://", "https://")):
            split = urlsplit(target)
        else:
            host = self.host_header()
            if not host:
                raise HttpMessageError("cannot derive target: no Host header")
            split = urlsplit(f"{default_scheme}://{host}{target}")
        scheme = split.scheme or default_scheme
        hostname = split.hostname
        if not hostname:
            raise HttpMessageError("cannot derive target host")
        port = split.port or (443 if scheme == "https" else 80)
        url = f"{scheme}://{hostname}:{port}{split.path or '/'}"
        if split.query:
            url = f"{url}?{split.query}"
        return TargetSpec(kind=TargetKind.URL, url=url), port


class NormalizedResponse(BaseModel):
    """Normalized HTTP response head."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    http_version: StrictStr = Field(max_length=16)
    status_code: StrictInt = Field(ge=100, le=599)
    reason: StrictStr = Field(default="", max_length=256)
    headers: tuple[HeaderPair, ...] = Field(default_factory=tuple)

    @classmethod
    def parse(cls, raw: bytes) -> NormalizedResponse:
        """Parse the head of a raw HTTP/1.x response."""
        start_line, headers = _parse_head(raw)
        version, _, rest = start_line.partition(b" ")
        code_bytes, _, reason = rest.partition(b" ")
        try:
            status_code = int(code_bytes)
        except ValueError as exc:
            raise HttpMessageError("malformed http status line") from exc
        return cls(
            http_version=version.decode("latin-1"),
            status_code=status_code,
            reason=reason.decode("latin-1"),
            headers=headers,
        )

    def serialize_head(self) -> bytes:
        reason = f" {self.reason}" if self.reason else ""
        start = f"{self.http_version} {self.status_code}{reason}".encode("latin-1")
        return start + _CRLF + _header_lines(self.headers) + _CRLF

    def header(self, name: str) -> str | None:
        return _find_header(self.headers, name)


# ---------------------------------------------------------------------------
# Bounded body handling — "no unbounded in-memory bodies".
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BodyPlan:
    """Retention plan for a message body.

    * ``content`` is present only for inline-retained bodies (``<= max_inline``).
    * ``spill`` is ``True`` when the body must be streamed to the object store.
    * ``truncated`` is ``True`` when the body exceeded the hard capture cap and
      was dropped — ``sha256`` + ``size`` are still recorded for provenance.

    Exactly one of {inline (content not None), spill, truncated} is the active
    disposition; an empty body is inline with ``content=b""``.
    """

    sha256: str
    size: int
    content: bytes | None
    spill: bool
    truncated: bool

    @property
    def is_inline(self) -> bool:
        return self.content is not None and not self.truncated


def plan_body(
    data: bytes,
    *,
    max_inline_bytes: int = DEFAULT_MAX_INLINE_BYTES,
    max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
) -> BodyPlan:
    """Digest, measure and decide the retention disposition for ``data``.

    Raises :class:`ValueError` if ``max_inline_bytes > max_capture_bytes`` (a
    misconfiguration that would make the inline branch unreachable-by-cap).
    """
    if max_inline_bytes < 0 or max_capture_bytes < 0:
        raise ValueError("body caps must be non-negative")
    if max_inline_bytes > max_capture_bytes:
        raise ValueError("max_inline_bytes must not exceed max_capture_bytes")
    size = len(data)
    digest = hashlib.sha256(data).hexdigest()
    if size > max_capture_bytes:
        return BodyPlan(sha256=digest, size=size, content=None, spill=False, truncated=True)
    if size <= max_inline_bytes:
        return BodyPlan(sha256=digest, size=size, content=data, spill=False, truncated=False)
    return BodyPlan(sha256=digest, size=size, content=None, spill=True, truncated=False)


__all__ = [
    "DEFAULT_MAX_CAPTURE_BYTES",
    "DEFAULT_MAX_INLINE_BYTES",
    "BodyPlan",
    "HeaderPair",
    "HttpMessageError",
    "NormalizedRequest",
    "NormalizedResponse",
    "plan_body",
]
