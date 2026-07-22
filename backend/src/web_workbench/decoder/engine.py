"""Decoder: chainable, byte-exact encode/decode/hash transforms (WB-P3a).

A pure, offline transform engine for manual analysis (the workbench analogue of
Burp's Decoder). A request flows through an ordered list of :class:`TransformStep`
where each step maps ``bytes -> bytes``. Everything is deterministic and has no
network or filesystem side effects.

Security invariants:

* **No inline secrets.** Keyed operations (HMAC) resolve their key through an
  injected :class:`SecretResolver` given a ``secret_ref`` — never from an inline
  option. Passing raw ``key``/``secret`` material is rejected.
* **Fail-closed.** A keyed operation with no resolver configured raises rather
  than silently degrading to an unkeyed digest.
* **Bounded.** Callers cap input size before invoking the engine; decoding never
  amplifies unboundedly (gzip decompression is size-limited).
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import hmac
import html
import json
import zlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import quote_from_bytes, unquote_to_bytes

#: Resolves a ``secret_ref`` (an opaque handle into the secret plane) to key
#: bytes. Never receives or returns inline secret material from the request.
SecretResolver = Callable[[str], bytes]

#: Hard cap on gzip/zlib inflate output to prevent decompression bombs (16 MiB).
_MAX_INFLATE_BYTES = 16 * 1024 * 1024

_UNKEYED_HASHES = frozenset({"md5", "sha1", "sha256", "sha384", "sha512"})
_HMAC_HASHES = frozenset({"sha1", "sha256", "sha384", "sha512"})
#: Option keys that would smuggle inline secret material — always rejected.
_FORBIDDEN_SECRET_OPTIONS = frozenset({"key", "secret", "password", "hmac_key"})


class DecoderError(Exception):
    """Raised on an invalid transform, malformed input, or policy violation."""


@dataclass(frozen=True)
class TransformStep:
    """One operation in a decoder pipeline.

    ``options`` are operation-specific, string-valued knobs (e.g. ``algorithm``
    or ``secret_ref``). Inline secret material in ``options`` is rejected.
    """

    operation: str
    options: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class TransformContext:
    """Ambient capabilities for a pipeline run (dependency injection)."""

    secret_resolver: SecretResolver | None = None


def _inflate(raw: bytes, decompressor: Callable[[bytes], bytes]) -> bytes:
    out = decompressor(raw)
    if len(out) > _MAX_INFLATE_BYTES:
        raise DecoderError("decompressed output exceeds the size limit")
    return out


def _op_url_encode(data: bytes, _o: Mapping[str, str], _c: TransformContext) -> bytes:
    return quote_from_bytes(data, safe=b"").encode("ascii")


def _op_url_decode(data: bytes, _o: Mapping[str, str], _c: TransformContext) -> bytes:
    return unquote_to_bytes(data)


def _op_base64_encode(data: bytes, _o: Mapping[str, str], _c: TransformContext) -> bytes:
    return base64.b64encode(data)


def _op_base64_decode(data: bytes, _o: Mapping[str, str], _c: TransformContext) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecoderError("invalid base64 input") from exc


def _op_base64url_encode(data: bytes, _o: Mapping[str, str], _c: TransformContext) -> bytes:
    return base64.urlsafe_b64encode(data)


def _op_base64url_decode(data: bytes, _o: Mapping[str, str], _c: TransformContext) -> bytes:
    padded = data + b"=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise DecoderError("invalid base64url input") from exc


def _op_hex_encode(data: bytes, _o: Mapping[str, str], _c: TransformContext) -> bytes:
    return binascii.hexlify(data)


def _op_hex_decode(data: bytes, _o: Mapping[str, str], _c: TransformContext) -> bytes:
    try:
        return binascii.unhexlify(b"".join(data.split()))
    except (binascii.Error, ValueError) as exc:
        raise DecoderError("invalid hex input") from exc


def _op_html_encode(data: bytes, _o: Mapping[str, str], _c: TransformContext) -> bytes:
    return html.escape(data.decode("utf-8", "replace")).encode("utf-8")


def _op_html_decode(data: bytes, _o: Mapping[str, str], _c: TransformContext) -> bytes:
    return html.unescape(data.decode("utf-8", "replace")).encode("utf-8")


def _op_gzip_compress(data: bytes, _o: Mapping[str, str], _c: TransformContext) -> bytes:
    return gzip.compress(data)


def _op_gzip_decompress(data: bytes, _o: Mapping[str, str], _c: TransformContext) -> bytes:
    try:
        return _inflate(data, gzip.decompress)
    except (OSError, EOFError, zlib.error) as exc:
        raise DecoderError("invalid gzip input") from exc


def _op_jwt_decode(data: bytes, _o: Mapping[str, str], _c: TransformContext) -> bytes:
    """Decode a JWT's header+payload (NO signature verification — analysis only)."""
    parts = data.split(b".")
    if len(parts) not in (2, 3):
        raise DecoderError("input is not a JWT (expected 2-3 dot-separated parts)")

    def _seg(segment: bytes) -> object:
        raw = _op_base64url_decode(segment, {}, _c)
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise DecoderError("JWT segment is not valid JSON") from exc

    decoded = {
        "header": _seg(parts[0]),
        "payload": _seg(parts[1]),
        "signature_present": len(parts) == 3 and bool(parts[2]),
        "signature_verified": False,
    }
    return json.dumps(decoded, ensure_ascii=False, sort_keys=True).encode("utf-8")


def _op_hash(data: bytes, options: Mapping[str, str], _c: TransformContext) -> bytes:
    algorithm = options.get("algorithm", "sha256").lower()
    if algorithm not in _UNKEYED_HASHES:
        raise DecoderError(f"unsupported hash algorithm: {algorithm}")
    return hashlib.new(algorithm, data).hexdigest().encode("ascii")


def _op_hmac(data: bytes, options: Mapping[str, str], ctx: TransformContext) -> bytes:
    algorithm = options.get("algorithm", "sha256").lower()
    if algorithm not in _HMAC_HASHES:
        raise DecoderError(f"unsupported hmac algorithm: {algorithm}")
    secret_ref = options.get("secret_ref")
    if not secret_ref:
        raise DecoderError("hmac requires a secret_ref (inline keys are forbidden)")
    if ctx.secret_resolver is None:
        raise DecoderError("hmac requested but no secret resolver is configured")
    key = ctx.secret_resolver(secret_ref)
    if not key:
        raise DecoderError("secret_ref did not resolve to key material")
    return hmac.new(key, data, algorithm).hexdigest().encode("ascii")


#: Registry of pure operations. Extend here — never branch on op name elsewhere.
_OPERATIONS: dict[str, Callable[[bytes, Mapping[str, str], TransformContext], bytes]] = {
    "url_encode": _op_url_encode,
    "url_decode": _op_url_decode,
    "base64_encode": _op_base64_encode,
    "base64_decode": _op_base64_decode,
    "base64url_encode": _op_base64url_encode,
    "base64url_decode": _op_base64url_decode,
    "hex_encode": _op_hex_encode,
    "hex_decode": _op_hex_decode,
    "html_encode": _op_html_encode,
    "html_decode": _op_html_decode,
    "gzip_compress": _op_gzip_compress,
    "gzip_decompress": _op_gzip_decompress,
    "jwt_decode": _op_jwt_decode,
    "hash": _op_hash,
    "hmac": _op_hmac,
}


def available_operations() -> tuple[str, ...]:
    """Return the sorted names of every supported operation."""
    return tuple(sorted(_OPERATIONS))


def _validate_options(step: TransformStep) -> None:
    forbidden = _FORBIDDEN_SECRET_OPTIONS.intersection(step.options)
    if forbidden:
        raise DecoderError(
            f"inline secret options are forbidden: {sorted(forbidden)}; use secret_ref"
        )


def run_pipeline(
    data: bytes,
    steps: Sequence[TransformStep],
    *,
    context: TransformContext | None = None,
) -> bytes:
    """Apply ``steps`` left-to-right to ``data`` and return the final bytes.

    Raises :class:`DecoderError` for unknown operations, malformed input, or a
    policy violation (inline secrets / missing resolver). An empty pipeline
    returns ``data`` unchanged (byte-exact identity).
    """
    ctx = context or TransformContext()
    current = data
    for step in steps:
        operation = _OPERATIONS.get(step.operation)
        if operation is None:
            raise DecoderError(f"unknown operation: {step.operation}")
        _validate_options(step)
        current = operation(current, step.options, ctx)
    return current


__all__ = [
    "DecoderError",
    "SecretResolver",
    "TransformContext",
    "TransformStep",
    "available_operations",
    "run_pipeline",
]
