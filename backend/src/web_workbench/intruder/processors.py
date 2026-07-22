"""Payload processors — ordered, byte-exact transforms (WB-P4a).

A processor chain is applied to each payload *before* it is injected into an
insertion point. Processors operate on ``bytes`` so injection stays byte-exact.
Supported kinds mirror the classic fuzzer processor set: ``prefix`` / ``suffix``
(literal add), ``encode`` (url / base64 / hex / html), ``hash`` (md5 / sha1 /
sha256, hex digest) and ``regex_replace``.

The chain is pure and deterministic; it never sources payloads itself — payload
sets are supplied by the caller (which MUST materialise them through the signed
:class:`~src.payloads.builder.PayloadBuilder` / ``PayloadRegistry``, SI-5).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from html import escape
from typing import Final
from urllib.parse import quote_from_bytes

_ENCODERS: Final = ("url", "base64", "hex", "html")
_HASHES: Final = ("md5", "sha1", "sha256")


class ProcessorError(Exception):
    """Raised for an unknown processor kind or invalid processor parameters."""


@dataclass(frozen=True)
class Processor:
    """One transform step.

    ``kind`` selects the transform; ``params`` carries its arguments:

    * ``prefix`` / ``suffix`` — ``{"value": <str>}`` (added as UTF-8 bytes).
    * ``encode`` — ``{"scheme": "url"|"base64"|"hex"|"html"}``.
    * ``hash`` — ``{"algorithm": "md5"|"sha1"|"sha256"}``.
    * ``regex_replace`` — ``{"pattern": <str>, "replacement": <str>, "count": <int>?}``.
    """

    kind: str
    params: dict[str, object] = field(default_factory=dict)


def _param_str(processor: Processor, key: str) -> str:
    value = processor.params.get(key)
    if not isinstance(value, str):
        raise ProcessorError(f"processor {processor.kind!r} requires string param {key!r}")
    return value


def _apply_one(payload: bytes, processor: Processor) -> bytes:
    kind = processor.kind
    if kind == "prefix":
        return _param_str(processor, "value").encode("utf-8") + payload
    if kind == "suffix":
        return payload + _param_str(processor, "value").encode("utf-8")
    if kind == "encode":
        return _encode(payload, _param_str(processor, "scheme"))
    if kind == "hash":
        return _hash(payload, _param_str(processor, "algorithm"))
    if kind == "regex_replace":
        return _regex_replace(payload, processor)
    raise ProcessorError(f"unknown processor kind {kind!r}")


def _encode(payload: bytes, scheme: str) -> bytes:
    if scheme == "url":
        return quote_from_bytes(payload, safe=b"").encode("ascii")
    if scheme == "base64":
        return base64.b64encode(payload)
    if scheme == "hex":
        return binascii.hexlify(payload)
    if scheme == "html":
        return escape(payload.decode("latin-1")).encode("latin-1")
    raise ProcessorError(f"unknown encode scheme {scheme!r}; expected one of {_ENCODERS}")


def _hash(payload: bytes, algorithm: str) -> bytes:
    if algorithm not in _HASHES:
        raise ProcessorError(f"unknown hash algorithm {algorithm!r}; expected one of {_HASHES}")
    return hashlib.new(algorithm, payload).hexdigest().encode("ascii")


def _regex_replace(payload: bytes, processor: Processor) -> bytes:
    pattern = _param_str(processor, "pattern").encode("latin-1")
    replacement = _param_str(processor, "replacement").encode("latin-1")
    raw_count = processor.params.get("count", 0)
    if not isinstance(raw_count, int) or isinstance(raw_count, bool) or raw_count < 0:
        raise ProcessorError("regex_replace 'count' must be a non-negative int")
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ProcessorError(f"invalid regex_replace pattern: {exc}") from exc
    return compiled.sub(replacement, payload, count=raw_count)


def apply_processors(payload: bytes, processors: Sequence[Processor]) -> bytes:
    """Apply an ordered processor chain to ``payload``."""
    result = payload
    for processor in processors:
        result = _apply_one(result, processor)
    return result


__all__ = [
    "Processor",
    "ProcessorError",
    "apply_processors",
]
