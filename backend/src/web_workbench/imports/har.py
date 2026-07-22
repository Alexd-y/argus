"""HAR (HTTP Archive) importer for the Web Workbench (WB-P10a, pure).

Converts a HAR 1.2 archive (as exported by browser devtools / proxies) into a
list of :class:`ImportedExchange` objects built on the workbench's own
:class:`~src.web_workbench.proxy.transport.NormalizedRequest` /
:class:`~src.web_workbench.proxy.transport.NormalizedResponse`. Imported traffic
can then feed the proxy history, Repeater, passive analyzer, or the declarative
check DSL — same as live-captured traffic.

The importer is **pure** (no I/O/network/DB) and offline-testable. It is
**fail-closed** and **bounded**:

* malformed HAR (bad JSON, wrong shape) → :class:`HarImportError` (no stack
  trace leaks to callers, per the error-handling policy);
* the entry count and per-message body sizes are capped (HAR files can be
  huge — DoS guard), with a ``truncated`` marker on the exchange;
* header names/values containing CR/LF are dropped (header-injection guard);
* entries whose response status is absent/``0`` (failed/aborted requests)
  import with ``response=None`` rather than fabricating a status.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from urllib.parse import urlsplit

from src.web_workbench.proxy.transport import NormalizedRequest, NormalizedResponse

#: Maximum number of HAR entries imported in one call (DoS guard).
_MAX_ENTRIES = 20_000
#: Maximum per-message body size retained (bytes); larger bodies are truncated.
_MAX_BODY = 5_242_880  # 5 MiB
#: Fallback HTTP version when the archive omits it.
_DEFAULT_HTTP_VERSION = "HTTP/1.1"


class HarImportError(ValueError):
    """Raised when a HAR archive cannot be parsed (fail-closed)."""


@dataclass(frozen=True)
class ImportedExchange:
    """One imported request/response pair (response optional)."""

    url: str
    request: NormalizedRequest
    request_body: bytes
    response: NormalizedResponse | None
    response_body: bytes
    started_at: str | None
    truncated: bool


def _clean_headers(raw: object) -> tuple[tuple[str, str], ...]:
    """Convert HAR ``headers`` list into ordered pairs (injection-safe)."""
    if not isinstance(raw, list):
        return ()
    pairs: list[tuple[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        value = item.get("value", "")
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        if not name or name.startswith(":"):  # skip HTTP/2 pseudo-headers
            continue
        if any(c in name or c in value for c in ("\r", "\n")):
            continue  # header-injection guard
        pairs.append((name, value))
    return tuple(pairs)


def _origin_form(url: str) -> tuple[str, str | None]:
    """Return ``(target, host)`` — origin-form path?query + host authority."""
    split = urlsplit(url)
    path = split.path or "/"
    target = f"{path}?{split.query}" if split.query else path
    return target, (split.netloc or None)


def _ensure_host(
    headers: tuple[tuple[str, str], ...], host: str | None
) -> tuple[tuple[str, str], ...]:
    if host and not any(name.lower() == "host" for name, _ in headers):
        return (("Host", host), *headers)
    return headers


def _bounded(data: bytes) -> tuple[bytes, bool]:
    if len(data) > _MAX_BODY:
        return data[:_MAX_BODY], True
    return data, False


def _request_body(post_data: object) -> bytes:
    if not isinstance(post_data, dict):
        return b""
    text = post_data.get("text")
    if isinstance(text, str):
        return text.encode("utf-8", errors="replace")
    return b""


def _response_body(content: object) -> bytes:
    if not isinstance(content, dict):
        return b""
    text = content.get("text")
    if not isinstance(text, str) or not text:
        return b""
    if content.get("encoding") == "base64":
        try:
            return base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            return b""
    return text.encode("utf-8", errors="replace")


def _http_version(value: object) -> str:
    if isinstance(value, str) and value:
        return value[:16]
    return _DEFAULT_HTTP_VERSION


def _build_request(entry_request: dict[str, object]) -> tuple[NormalizedRequest, bytes, str]:
    method = entry_request.get("method")
    url = entry_request.get("url")
    if not isinstance(method, str) or not method:
        raise HarImportError("entry request is missing a method")
    if not isinstance(url, str) or not url:
        raise HarImportError("entry request is missing a url")
    target, host = _origin_form(url)
    headers = _ensure_host(_clean_headers(entry_request.get("headers")), host)
    try:
        request = NormalizedRequest(
            method=method,
            target=target,
            http_version=_http_version(entry_request.get("httpVersion")),
            headers=headers,
        )
    except ValueError as exc:
        raise HarImportError(f"invalid request head: {exc.__class__.__name__}") from exc
    return request, _request_body(entry_request.get("postData")), url


def _build_response(entry_response: object) -> tuple[NormalizedResponse | None, bytes]:
    if not isinstance(entry_response, dict):
        return None, b""
    status = entry_response.get("status")
    if not isinstance(status, int) or not (100 <= status <= 599):
        # 0 / missing status = failed or aborted request; no response captured.
        return None, b""
    reason = entry_response.get("statusText")
    headers = _clean_headers(entry_response.get("headers"))
    try:
        response = NormalizedResponse(
            http_version=_http_version(entry_response.get("httpVersion")),
            status_code=status,
            reason=reason[:256] if isinstance(reason, str) else "",
            headers=headers,
        )
    except ValueError as exc:
        raise HarImportError(f"invalid response head: {exc.__class__.__name__}") from exc
    return response, _response_body(entry_response.get("content"))


def import_har(raw: bytes | str) -> list[ImportedExchange]:
    """Parse a HAR archive into a list of :class:`ImportedExchange`.

    Raises :class:`HarImportError` on any structural problem. Entries beyond
    :data:`_MAX_ENTRIES` are ignored; oversized bodies are truncated and the
    exchange is flagged ``truncated=True``.
    """
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HarImportError(f"HAR is not valid JSON: {exc.__class__.__name__}") from exc

    if not isinstance(document, dict):
        raise HarImportError("HAR root must be a JSON object")
    log = document.get("log")
    if not isinstance(log, dict):
        raise HarImportError("HAR is missing the 'log' object")
    entries = log.get("entries")
    if not isinstance(entries, list):
        raise HarImportError("HAR 'log.entries' must be an array")

    exchanges: list[ImportedExchange] = []
    for entry in entries[:_MAX_ENTRIES]:
        if not isinstance(entry, dict):
            raise HarImportError("HAR entry must be an object")
        entry_request = entry.get("request")
        if not isinstance(entry_request, dict):
            raise HarImportError("HAR entry is missing the 'request' object")

        request, request_body, url = _build_request(entry_request)
        response, response_body = _build_response(entry.get("response"))

        request_body, req_trunc = _bounded(request_body)
        response_body, resp_trunc = _bounded(response_body)
        started_at = entry.get("startedDateTime")

        exchanges.append(
            ImportedExchange(
                url=url,
                request=request,
                request_body=request_body,
                response=response,
                response_body=response_body,
                started_at=started_at if isinstance(started_at, str) else None,
                truncated=req_trunc or resp_trunc,
            )
        )
    return exchanges


__all__ = [
    "HarImportError",
    "ImportedExchange",
    "import_har",
]
