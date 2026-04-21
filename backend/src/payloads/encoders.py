"""Encoding pipelines for ARGUS payload materialisation (Backlog/dev1_md §7).

The encoder layer applies one or more transformation stages (URL-encoding,
HTML-entity, base64, hex, unicode-escape) on top of a payload after the
mutation layer has done its work. Encoders are PURE functions: same input,
same output, no I/O, no global state.

Encoders are deliberately kept tiny and side-effect free so the
:class:`~src.payloads.builder.PayloadBuilder` can chain them deterministically
and so any mutation/encoder regression is caught by a one-liner unit test.

Stage names live in :data:`ENCODER_NAMES` and are referenced from each
``EncodingPipeline`` declared in a signed payload-family YAML. An unknown
stage name raises :class:`UnknownEncoderError` — the registry rejects such
descriptors at startup so this should never fire in production.
"""

from __future__ import annotations

import base64
import binascii
import html
import urllib.parse
from collections.abc import Callable, Mapping
from typing import Final


class UnknownEncoderError(KeyError):
    """Raised when an encoding pipeline references a stage that is not registered.

    Holds the offending stage name on :attr:`stage` so callers can log a
    structured event without echoing the payload value.
    """

    def __init__(self, stage: str) -> None:
        super().__init__(stage)
        self.stage = stage


# ---------------------------------------------------------------------------
# Pure encoder functions
# ---------------------------------------------------------------------------


def encode_url(payload: str) -> str:
    """Percent-encode a payload using the conservative RFC 3986 unreserved set.

    Equivalent to ``urllib.parse.quote(payload, safe="")`` — every character
    outside ``[A-Za-z0-9._~-]`` is percent-encoded. Idempotent only when the
    input is already fully encoded.
    """
    return urllib.parse.quote(payload, safe="")


def encode_double_url(payload: str) -> str:
    """Apply :func:`encode_url` twice (WAF-bypass attempt against double-decoders)."""
    return encode_url(encode_url(payload))


def encode_html(payload: str) -> str:
    """HTML-entity-encode the standard XSS metacharacters (``& < > " '``).

    Also escapes ``=`` so attribute-context XSS payloads keep their shape on
    a server that auto-decodes entities only for canonical sinks.
    """
    return html.escape(payload, quote=True).replace("=", "&#x3D;")


def encode_base64(payload: str) -> str:
    """Base64-encode the UTF-8 bytes of ``payload`` (standard alphabet)."""
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")


def encode_unicode_escape(payload: str) -> str:
    r"""Render every character as a ``\uXXXX`` Python/JS escape sequence.

    Surrogate pairs are produced for code points outside the BMP — JS engines
    accept these natively in string literals.
    """
    pieces: list[str] = []
    for ch in payload:
        cp = ord(ch)
        if cp <= 0xFFFF:
            pieces.append(f"\\u{cp:04x}")
        else:
            cp -= 0x10000
            high = 0xD800 + (cp >> 10)
            low = 0xDC00 + (cp & 0x3FF)
            pieces.append(f"\\u{high:04x}\\u{low:04x}")
    return "".join(pieces)


def encode_hex_x(payload: str) -> str:
    r"""Render every byte as a ``\xHH`` escape sequence (Python/PHP/SQL friendly).

    Operates on UTF-8 bytes; multi-byte characters expand into multiple
    ``\xHH`` escapes.
    """
    raw = payload.encode("utf-8")
    return "".join(f"\\x{byte:02x}" for byte in raw)


def encode_hex_concat(payload: str) -> str:
    """Render a SQL-style ``0xDEADBEEF`` literal of the UTF-8 hex bytes."""
    raw = payload.encode("utf-8")
    return "0x" + binascii.hexlify(raw).decode("ascii")


def encode_identity(payload: str) -> str:
    """No-op encoder; useful as a pipeline placeholder in tests / canary YAMLs."""
    return payload


# ---------------------------------------------------------------------------
# Encoder registry
# ---------------------------------------------------------------------------


_EncoderFn = Callable[[str], str]


_ENCODERS: Final[Mapping[str, _EncoderFn]] = {
    "identity": encode_identity,
    "url": encode_url,
    "url_double": encode_double_url,
    "html": encode_html,
    "base64": encode_base64,
    "unicode_escape": encode_unicode_escape,
    "hex_x": encode_hex_x,
    "hex_concat": encode_hex_concat,
}


ENCODER_NAMES: Final[frozenset[str]] = frozenset(_ENCODERS.keys())
"""Public set of all encoder stage names that may appear in YAMLs."""


def get_encoder(stage: str) -> _EncoderFn:
    """Return the encoder function for ``stage`` or raise :class:`UnknownEncoderError`."""
    try:
        return _ENCODERS[stage]
    except KeyError as exc:
        raise UnknownEncoderError(stage) from exc


def apply_pipeline(payload: str, stages: list[str]) -> str:
    """Chain the named encoders in order, left-to-right.

    Empty ``stages`` returns ``payload`` unchanged. The encoder layer is
    deliberately deterministic — callers that want randomness should drive
    it via the mutation layer instead.
    """
    out = payload
    for stage in stages:
        out = get_encoder(stage)(out)
    return out


__all__ = [
    "ENCODER_NAMES",
    "UnknownEncoderError",
    "apply_pipeline",
    "encode_base64",
    "encode_double_url",
    "encode_hex_concat",
    "encode_hex_x",
    "encode_html",
    "encode_identity",
    "encode_unicode_escape",
    "encode_url",
    "get_encoder",
]
