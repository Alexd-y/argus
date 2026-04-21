"""Shared building blocks for ARG-032 browser-family parsers.

The Cycle 4 browser batch (``playwright_runner`` / ``puppeteer_screens`` /
``chrome_csp_probe`` / ``webanalyze`` / ``gowitness`` / ``whatweb``)
shares two concerns:

1. Many tools persist a HAR (HTTP Archive) sidecar in
   ``artifacts_dir/<tool>/index.har``.  HAR entries carry request /
   response headers that legitimately contain ``Cookie`` /
   ``Set-Cookie`` / ``Authorization`` values.  A naive HAR walker
   would surface those tokens into FindingDTO fields and trip the
   C12 evidence-redaction contract.  :func:`iter_har_entries` is the
   single chokepoint that loads + redacts HAR records before any
   per-tool parser sees them.

2. Every browser tool emits a *directory* of artifacts (HAR +
   screenshots + DOM snapshot + console log).  :func:`browse_artifact_dir`
   resolves the canonical artifact-directory under ``artifacts_dir``
   defensively (no ``..`` traversal, must be a real directory) and
   :func:`load_first_existing` reads the first present file from a
   prioritised list.

Every helper is **pure** — no global state, no logging side-effect
beyond structured warnings on I/O failure — so per-tool parsers can
compose them freely without leak channels.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

from src.sandbox.parsers._base import (
    MAX_STDOUT_BYTES,
    safe_load_json,
)
from src.sandbox.parsers._jsonl_base import safe_join_artifact
from src.sandbox.parsers._text_base import (
    REDACTED_BEARER_MARKER,
    REDACTED_COOKIE_MARKER,
    redact_http_secrets,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


# HAR header names whose values are scrubbed wholesale (token replaces value).
# Lowercased for comparison after `header.get("name", "").lower()`.
_REDACT_HEADER_NAMES: Final[frozenset[str]] = frozenset(
    {"cookie", "set-cookie", "authorization", "proxy-authorization"}
)

# Map of header name -> replacement marker so the operator still sees
# *which* class of secret was masked.
_HEADER_REDACTION_MARKERS: Final[dict[str, str]] = {
    "cookie": REDACTED_COOKIE_MARKER,
    "set-cookie": REDACTED_COOKIE_MARKER,
    "authorization": REDACTED_BEARER_MARKER,
    "proxy-authorization": REDACTED_BEARER_MARKER,
}


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def browse_artifact_dir(artifacts_dir: Path, name: str) -> Path | None:
    """Resolve ``artifacts_dir / name`` iff ``name`` is a real subdirectory.

    Refuses path-traversal segments and non-directory targets so a
    malicious YAML cannot point at an arbitrary host filesystem path.
    """
    candidate = safe_join_artifact(artifacts_dir, name)
    if candidate is None or not candidate.is_dir():
        return None
    return candidate


def load_first_existing(candidates: Sequence[Path], *, tool_id: str) -> bytes:
    """Return the bytes of the first regular file in ``candidates``.

    Best-effort: returns ``b""`` for missing files / OSError.
    """
    for path in candidates:
        if not path.is_file():
            continue
        try:
            return path.read_bytes()
        except OSError as exc:
            _logger.warning(
                "browser_base.read_failed",
                extra={
                    "event": "browser_base_read_failed",
                    "tool_id": tool_id,
                    "path": str(path),
                    "error_type": type(exc).__name__,
                },
            )
            return b""
    return b""


# ---------------------------------------------------------------------------
# HAR helpers
# ---------------------------------------------------------------------------


def _redact_har_headers(headers: object) -> list[dict[str, str]]:
    """Return a NEW header list with sensitive values masked.

    The HAR spec says headers are ``[{"name": ..., "value": ...}, ...]``.
    This helper:

    * Drops malformed entries (non-dict, missing ``name``).
    * Replaces values for ``Cookie`` / ``Set-Cookie`` / ``Authorization``
      / ``Proxy-Authorization`` with the canonical redaction marker so
      the operator still sees that the header was present without
      leaking the token.
    * Defensively scrubs ``Bearer …`` / inline cookies that may appear
      in OTHER headers (e.g. a custom ``X-Auth-Token: Bearer …``).
    """
    if not isinstance(headers, list):
        return []
    cleaned: list[dict[str, str]] = []
    for entry in headers:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        value = entry.get("value")
        if not isinstance(name, str) or not name:
            continue
        if not isinstance(value, str):
            value = ""
        lowered = name.lower()
        if lowered in _REDACT_HEADER_NAMES:
            cleaned.append(
                {
                    "name": name,
                    "value": _HEADER_REDACTION_MARKERS[lowered],
                }
            )
            continue
        cleaned.append({"name": name, "value": redact_http_secrets(value)})
    return cleaned


def _redact_post_data(post_data: object) -> dict[str, str] | None:
    """Return a redacted copy of ``request.postData`` or ``None`` if missing.

    HAR ``postData`` can carry form fields including credentials.  Only
    the canonical ``mimeType`` is preserved; the raw text is replaced
    with a length marker so the operator can spot truncated bodies but
    no payload contents leak.
    """
    if not isinstance(post_data, dict):
        return None
    mime = post_data.get("mimeType")
    text = post_data.get("text")
    out: dict[str, str] = {}
    if isinstance(mime, str) and mime:
        out["mimeType"] = mime
    if isinstance(text, str):
        out["bodyLength"] = str(len(text))
    return out or None


def _redact_url(url: object) -> str:
    """Return ``url`` with inline credentials masked.

    HAR ``request.url`` may be a string with ``https://user:pw@host``
    embeds; :func:`redact_http_secrets` covers the bearer/cookie case
    but not the credentials-in-URL case, so we route the value through
    :func:`redact_password_in_text` indirectly via a dedicated pass.
    """
    if not isinstance(url, str):
        return ""
    # ``redact_http_secrets`` doesn't strip URL credentials but the
    # parent text-base ``redact_password_in_text`` does.  We import
    # locally to avoid an import cycle at module top-level.
    from src.sandbox.parsers._text_base import redact_password_in_text

    return redact_password_in_text(url)


def safe_url_parts(url: str) -> tuple[str, str]:
    """Return ``(hostname, path)`` for ``url`` even when redacted.

    Python 3.12+ ``urlsplit`` rejects netlocs containing brackets that
    aren't valid IPv6 literals.  After ``_redact_url`` injects the
    ``[REDACTED-PASSWORD]`` marker into the userinfo segment, the raw
    redacted URL trips this validation.

    To preserve correct host/path extraction we strip credentials
    *before* parsing — the marker (and any leftover ``user:pw@``
    fragment) is removed, then the bracket-free URL is parsed safely.
    The returned values lose any user / password metadata but retain
    enough information for dedup keys and evidence aggregation.
    """
    if not isinstance(url, str) or not url:
        return "", "/"
    # Strip any inline credentials (raw or redacted) before parsing so
    # urlsplit's bracket-validation does not blow up on the marker.
    scheme_idx = url.find("://")
    if scheme_idx >= 0:
        prefix = url[: scheme_idx + 3]
        rest = url[scheme_idx + 3 :]
        at_idx = rest.find("@")
        if at_idx >= 0:
            slash_idx = rest.find("/")
            if slash_idx == -1 or at_idx < slash_idx:
                rest = rest[at_idx + 1 :]
        cleaned = prefix + rest
    else:
        cleaned = url
    try:
        parts = urlsplit(cleaned)
    except ValueError:
        return "", "/"
    return (parts.hostname or "").lower(), parts.path or "/"


def iter_har_entries(
    har_payload: Any,
    *,
    tool_id: str,
    limit: int = 5_000,
) -> Iterator[dict[str, object]]:
    """Yield redacted HAR entries from ``har_payload``.

    Each yielded record has the shape::

        {
          "method": "GET",
          "url": "https://example.com/api",
          "status": 200,
          "request_headers": [{"name": "...", "value": "..."}],
          "response_headers": [...],
          "post_data": {"mimeType": "...", "bodyLength": "..."},
          "started_date_time": "2026-04-19T12:00:00Z",
        }

    Cookies, authorization headers, and bearer tokens are redacted at
    this layer; per-tool parsers never see the raw values.
    """
    if not isinstance(har_payload, dict):
        return
    log = har_payload.get("log")
    if not isinstance(log, dict):
        return
    entries = log.get("entries")
    if not isinstance(entries, list):
        return
    seen = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if seen >= limit:
            _logger.warning(
                "browser_base.har_cap_reached",
                extra={
                    "event": "browser_base_har_cap_reached",
                    "tool_id": tool_id,
                    "limit": limit,
                },
            )
            return
        raw_request = entry.get("request")
        request: dict[str, Any] = raw_request if isinstance(raw_request, dict) else {}
        raw_response = entry.get("response")
        response: dict[str, Any] = (
            raw_response if isinstance(raw_response, dict) else {}
        )
        method = request.get("method")
        url = request.get("url")
        status = response.get("status")
        if not isinstance(method, str) or not isinstance(url, str):
            continue
        try:
            status_int = int(status) if status is not None else 0
        except (TypeError, ValueError):
            status_int = 0
        # Extract host/path BEFORE the URL is redacted so downstream
        # parsers can dedup on stable keys without ever seeing the raw
        # credentials.
        host, path = safe_url_parts(url)
        record: dict[str, object] = {
            "method": method.upper(),
            "url": _redact_url(url),
            "host": host,
            "path": path,
            "status": status_int,
            "request_headers": _redact_har_headers(request.get("headers")),
            "response_headers": _redact_har_headers(response.get("headers")),
        }
        post_data = _redact_post_data(request.get("postData"))
        if post_data is not None:
            record["post_data"] = post_data
        started = entry.get("startedDateTime")
        if isinstance(started, str) and started:
            record["started_date_time"] = started
        yield record
        seen += 1


def load_har_payload(
    paths: Sequence[Path],
    *,
    tool_id: str,
    stdout: bytes = b"",
) -> Any:
    """Resolve a HAR JSON payload from the first existing path or stdout.

    Returns the parsed JSON value or ``None`` if no source yielded a
    valid object.
    """
    raw = load_first_existing(paths, tool_id=tool_id)
    if raw.strip():
        payload = safe_load_json(raw, tool_id=tool_id, limit=MAX_STDOUT_BYTES)
        if payload is not None:
            return payload
    if stdout and stdout.strip():
        return safe_load_json(stdout, tool_id=tool_id, limit=MAX_STDOUT_BYTES)
    return None


__all__ = [
    "browse_artifact_dir",
    "iter_har_entries",
    "load_first_existing",
    "load_har_payload",
    "safe_url_parts",
]
