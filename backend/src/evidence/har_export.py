"""HAR 1.2 exporter — the inverse of :mod:`src.web_workbench.imports.har`.

Wave 2a (R-5.2.3). Most requests to a target are made by tools, not a browser,
so the ``HAR`` evidence kind needs a producer that serialises captured
request/response exchanges into a valid HAR archive. This is written as the
inverse of the importer and reuses its :class:`ImportedExchange` /
``NormalizedRequest`` / ``NormalizedResponse`` representations — no third
exchange model. ``export_har`` → :func:`import_har` round-trips without loss.

Redaction: HAR carries whole headers (including the values authentication is
performed with), so sensitive header values and bodies are scrubbed here
explicitly — the generic byte redactor in the evidence pipeline is a second
layer but cannot reliably see structured HAR fields.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit

from src.web_workbench.imports.har import ImportedExchange
from src.web_workbench.proxy.transport import NormalizedRequest, NormalizedResponse

_HAR_VERSION = "1.2"
_REDACTED = "[REDACTED]"

#: Header names (lowercased) whose values are secrets — scrubbed on export.
_SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-amz-security-token",
        "x-csrf-token",
        "authentication",
    }
)

#: Default placeholder so every entry has a spec-required startedDateTime.
_DEFAULT_STARTED_AT = "1970-01-01T00:00:00.000Z"


def _query_string(url: str) -> list[dict[str, str]]:
    query = urlsplit(url).query
    out: list[dict[str, str]] = []
    if not query:
        return out
    for pair in query.split("&"):
        name, _, value = pair.partition("=")
        out.append({"name": name, "value": value})
    return out


def _mime_type(headers: Sequence[tuple[str, str]]) -> str:
    for name, value in headers:
        if name.lower() == "content-type":
            return value
    return ""


def _har_headers(headers: Sequence[tuple[str, str]], *, redact: bool) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for name, value in headers:
        safe = _REDACTED if (redact and name.lower() in _SENSITIVE_HEADERS) else value
        out.append({"name": name, "value": safe})
    return out


def _request_entry(
    exchange: ImportedExchange, *, redact: bool
) -> dict[str, object]:
    req = exchange.request
    body = exchange.request_body
    entry: dict[str, object] = {
        "method": req.method,
        "url": exchange.url,
        "httpVersion": req.http_version or "HTTP/1.1",
        "headers": _har_headers(req.headers, redact=redact),
        "queryString": _query_string(exchange.url),
        "cookies": [],
        "headersSize": -1,
        "bodySize": len(body),
    }
    if body:
        # The importer reads postData.text as UTF-8 text. Redact the body bytes
        # through the generic redactor first so secrets in form/JSON bodies go too.
        text = _redact_body(body) if redact else body
        entry["postData"] = {
            "mimeType": _mime_type(req.headers) or "application/octet-stream",
            "text": text.decode("utf-8", errors="replace"),
        }
    return entry


def _response_entry(
    exchange: ImportedExchange, *, redact: bool
) -> dict[str, object]:
    resp = exchange.response
    if resp is None:
        # Failed / aborted request — the importer maps status 0 back to None.
        return {
            "status": 0,
            "statusText": "",
            "httpVersion": "",
            "headers": [],
            "cookies": [],
            "content": {"size": 0, "mimeType": ""},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": 0,
        }
    body = exchange.response_body
    stored = _redact_body(body) if redact else body
    return {
        "status": resp.status_code,
        "statusText": resp.reason,
        "httpVersion": resp.http_version or "HTTP/1.1",
        "headers": _har_headers(resp.headers, redact=redact),
        "cookies": [],
        # Response bodies may be binary → base64 (the importer decodes it back).
        "content": {
            "size": len(stored),
            "mimeType": _mime_type(resp.headers),
            "text": base64.b64encode(stored).decode("ascii"),
            "encoding": "base64",
        },
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": len(stored),
    }


def _redact_body(body: bytes) -> bytes:
    from src.evidence.redaction import Redactor

    return Redactor().redact(body).content


def export_har(exchanges: Sequence[ImportedExchange], *, redact: bool = True) -> str:
    """Serialise captured exchanges into a HAR 1.2 archive (JSON string)."""
    entries: list[dict[str, object]] = []
    for exchange in exchanges:
        entries.append(
            {
                "startedDateTime": exchange.started_at or _DEFAULT_STARTED_AT,
                "time": 0,
                "request": _request_entry(exchange, redact=redact),
                "response": _response_entry(exchange, redact=redact),
                "cache": {},
                "timings": {"send": 0, "wait": 0, "receive": 0},
            }
        )
    document = {
        "log": {
            "version": _HAR_VERSION,
            "creator": {"name": "ARGUS", "version": "1.0"},
            "entries": entries,
        }
    }
    return json.dumps(document, ensure_ascii=False, separators=(",", ":"))


def exchange_from_http_evidence(ev: object) -> ImportedExchange:
    """Build an :class:`ImportedExchange` from an ``HttpEvidence`` record."""
    method = str(getattr(ev, "request_method", "GET") or "GET")
    url = str(getattr(ev, "request_url", "") or "")
    req_headers = _as_pairs(getattr(ev, "request_headers", {}))
    target, host = _origin_form(url)
    if host and not any(n.lower() == "host" for n, _ in req_headers):
        req_headers = (("Host", host), *req_headers)
    request = NormalizedRequest(
        method=method,
        target=target,
        http_version="HTTP/1.1",
        headers=req_headers,
    )
    status = getattr(ev, "response_status", None)
    response: NormalizedResponse | None = None
    if isinstance(status, int) and 100 <= status <= 599:
        response = NormalizedResponse(
            http_version="HTTP/1.1",
            status_code=status,
            reason="",
            headers=_as_pairs(getattr(ev, "response_headers", {})),
        )
    req_body = str(getattr(ev, "request_body", "") or "").encode("utf-8", errors="replace")
    resp_body = str(getattr(ev, "response_body_snippet", "") or "").encode("utf-8", errors="replace")
    return ImportedExchange(
        url=url,
        request=request,
        request_body=req_body,
        response=response,
        response_body=resp_body,
        started_at=str(getattr(ev, "timestamp", "") or "") or None,
        truncated=False,
    )


def _as_pairs(headers: object) -> tuple[tuple[str, str], ...]:
    if isinstance(headers, Mapping):
        return tuple((str(k), str(v)) for k, v in headers.items())
    return ()


def _origin_form(url: str) -> tuple[str, str | None]:
    split = urlsplit(url)
    path = split.path or "/"
    target = f"{path}?{split.query}" if split.query else path
    return target, (split.netloc or None)


__all__ = ["exchange_from_http_evidence", "export_har"]
