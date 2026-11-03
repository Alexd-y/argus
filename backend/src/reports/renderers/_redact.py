"""Client-facing redaction for canonical renderers (C-29).

A canonical report format is a client deliverable and must never carry an internal
MinIO storage key (``<tenant-uuid>/<scan-uuid>/.../<uuid>.json``) — that leaks the
tenant/scan ids and the internal object layout. The immutable snapshot keeps the real
key for internal consumers (the evidence gate, the artifact ledger, the verification
kit); only the *rendered* output is redacted, and every format applies the SAME
transform so cross-format parity holds.

The pattern is imported from :mod:`src.reports.report_content_parity` so the redaction
removes exactly what the C-29 parity check flags — the two can never drift apart.
"""

from __future__ import annotations

from src.reports.report_content_parity import _INTERNAL_PATH_RE


def redact_internal_paths(text: str) -> str:
    """Replace each leaked internal storage path with its basename.

    ``<tenant>/<scan>/poc/<uuid>.json`` → ``<uuid>.json`` (no slash → no longer matches
    C-29). A bare id, an opaque ``E-001`` evidence id, or a plain URL is left untouched.
    Idempotent and safe to apply to any format's final string (JSON values, XML/HTML
    text and attributes all keep valid shorter strings).
    """
    if not text:
        return text
    return _INTERNAL_PATH_RE.sub(lambda m: m.group(0).rsplit("/", 1)[-1], text)
