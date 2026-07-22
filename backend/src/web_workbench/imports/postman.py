"""Postman Collection v2.1 importer for the Web Workbench (WB-P10c, pure).

Converts a Postman Collection (schema v2.1.0) into a list of
:class:`~src.web_workbench.imports.har.ImportedExchange` objects built on the
workbench's own :class:`~src.web_workbench.proxy.transport.NormalizedRequest`
(request-only; ``response=None``). Imported requests seed the same surfaces as
live/HAR traffic — scope, scanner targets, Repeater, passive analyzer, DSL.

Pure (no I/O/network/DB), offline-testable, **fail-closed**
(:class:`PostmanImportError`) and **bounded** (request count capped, bodies
truncated). Nested folders are walked depth-first; ``{{variable}}`` references
are resolved from the collection ``variable`` array, request-level path
variables, and an optional caller-supplied override map. Header names/values
with CR/LF are dropped (header-injection guard); sample material is taken
verbatim from the collection (never fabricated secrets).
"""

from __future__ import annotations

import re
from typing import Final
from urllib.parse import urlencode, urlsplit

import yaml

from src.web_workbench.imports.har import (
    ImportedExchange,
    _bounded,
    _ensure_host,
    _origin_form,
)
from src.web_workbench.proxy.transport import NormalizedRequest

_HTTP_METHODS: Final[frozenset[str]] = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"}
)
#: Maximum number of requests imported in one call (DoS guard).
_MAX_REQUESTS: Final[int] = 20_000
#: Maximum folder nesting depth walked (recursion guard).
_MAX_DEPTH: Final[int] = 64
#: Maximum ``{{var}}`` substitution passes (guards against cyclic references).
_MAX_SUBST_PASSES: Final[int] = 8
_DEFAULT_HTTP_VERSION: Final[str] = "HTTP/1.1"
_MULTIPART_BOUNDARY: Final[str] = "----ArgusWorkbenchFormBoundary"
_VAR_RE: Final[re.Pattern[str]] = re.compile(r"\{\{([^{}]+)\}\}")


class PostmanImportError(ValueError):
    """Raised when a Postman collection cannot be imported (fail-closed)."""


def _load_document(raw: bytes | str) -> dict[str, object]:
    try:
        document = yaml.safe_load(raw)  # JSON is a subset of YAML
    except yaml.YAMLError as exc:
        raise PostmanImportError(
            f"collection is not valid JSON/YAML: {exc.__class__.__name__}"
        ) from exc
    if not isinstance(document, dict):
        raise PostmanImportError("collection root must be a mapping")
    return document


def _collect_variables(
    document: dict[str, object], override: dict[str, str] | None
) -> dict[str, str]:
    variables: dict[str, str] = {}
    raw_vars = document.get("variable")
    if isinstance(raw_vars, list):
        for item in raw_vars:
            if not isinstance(item, dict):
                continue
            key = item.get("key")
            value = item.get("value")
            if isinstance(key, str) and isinstance(value, (str, int, float, bool)):
                variables[key] = str(value)
    if override:
        variables.update(override)
    return variables


def _substitute(text: str, variables: dict[str, str]) -> str:
    """Resolve ``{{var}}`` references (bounded passes; unknown vars left as-is)."""
    if not variables:
        return text
    current = text
    for _ in range(_MAX_SUBST_PASSES):
        replaced = _VAR_RE.sub(lambda m: variables.get(m.group(1).strip(), m.group(0)), current)
        if replaced == current:
            break
        current = replaced
    return current


def _has_crlf(text: str) -> bool:
    return "\r" in text or "\n" in text


def _url_query_from_object(url_obj: dict[str, object], variables: dict[str, str]) -> str:
    query = url_obj.get("query")
    if not isinstance(query, list):
        return ""
    pairs: list[tuple[str, str]] = []
    for item in query:
        if not isinstance(item, dict) or item.get("disabled") is True:
            continue
        key = item.get("key")
        if not isinstance(key, str) or not key:
            continue
        value = item.get("value")
        value_str = (
            _substitute(str(value), variables) if isinstance(value, (str, int, float, bool)) else ""
        )
        pairs.append((_substitute(key, variables), value_str))
    return urlencode(pairs)


def _raw_url(url: object, variables: dict[str, str]) -> str:
    """Return a resolved raw URL string from a Postman ``url`` field."""
    if isinstance(url, str):
        return _substitute(url, variables)
    if not isinstance(url, dict):
        raise PostmanImportError("request 'url' must be a string or object")

    # Path variables (`:id`) resolve from url.variable, then collection vars.
    local_vars = dict(variables)
    raw_var = url.get("variable")
    if isinstance(raw_var, list):
        for item in raw_var:
            if isinstance(item, dict):
                key = item.get("key")
                value = item.get("value")
                if isinstance(key, str) and isinstance(value, (str, int, float, bool)):
                    local_vars[key] = str(value)

    raw = url.get("raw")
    if isinstance(raw, str) and raw:
        resolved = _substitute(raw, local_vars)
    else:
        protocol = url.get("protocol")
        scheme = protocol if isinstance(protocol, str) and protocol else "https"
        host = url.get("host")
        host_str = ".".join(str(h) for h in host) if isinstance(host, list) else str(host or "")
        path = url.get("path")
        path_str = "/".join(str(p) for p in path) if isinstance(path, list) else str(path or "")
        resolved = _substitute(f"{scheme}://{host_str}/{path_str}", local_vars)
        query = _url_query_from_object(url, variables)
        if query:
            resolved = f"{resolved}?{query}"
    # Resolve path-var placeholders like `/users/:id` when a matching var exists.
    for key, value in local_vars.items():
        resolved = resolved.replace(f":{key}", value)
    return resolved


def _headers(request: dict[str, object], variables: dict[str, str]) -> tuple[tuple[str, str], ...]:
    raw = request.get("header")
    if not isinstance(raw, list):
        return ()
    pairs: list[tuple[str, str]] = []
    for item in raw:
        if not isinstance(item, dict) or item.get("disabled") is True:
            continue
        key = item.get("key")
        value = item.get("value", "")
        if not isinstance(key, str) or not key or not isinstance(value, (str, int, float, bool)):
            continue
        name = _substitute(key, variables)
        val = _substitute(str(value), variables)
        if _has_crlf(name) or _has_crlf(val):
            continue
        pairs.append((name, val))
    return tuple(pairs)


def _has_header(headers: tuple[tuple[str, str], ...], name: str) -> bool:
    lowered = name.lower()
    return any(h.lower() == lowered for h, _ in headers)


def _body(request: dict[str, object], variables: dict[str, str]) -> tuple[bytes, str | None]:
    """Return ``(body_bytes, content_type|None)`` from a Postman request body."""
    body = request.get("body")
    if not isinstance(body, dict):
        return b"", None
    mode = body.get("mode")

    if mode == "raw":
        text = body.get("raw")
        if not isinstance(text, str) or not text:
            return b"", None
        resolved = _substitute(text, variables)
        options = body.get("options")
        language = None
        if isinstance(options, dict):
            raw_opts = options.get("raw")
            if isinstance(raw_opts, dict):
                language = raw_opts.get("language")
        content_type = "application/json" if language == "json" else None
        return resolved.encode("utf-8", errors="replace"), content_type

    if mode == "urlencoded":
        entries = body.get("urlencoded")
        pairs = _kv_pairs(entries, variables)
        return (
            urlencode(pairs).encode("utf-8"),
            "application/x-www-form-urlencoded",
        )

    if mode == "formdata":
        entries = body.get("formdata")
        pairs = _kv_pairs(entries, variables)
        rendered = _render_multipart(pairs)
        return (
            rendered,
            f"multipart/form-data; boundary={_MULTIPART_BOUNDARY}",
        )

    return b"", None


def _kv_pairs(entries: object, variables: dict[str, str]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if not isinstance(entries, list):
        return pairs
    for item in entries:
        if not isinstance(item, dict) or item.get("disabled") is True:
            continue
        key = item.get("key")
        if not isinstance(key, str) or not key:
            continue
        value = item.get("value")
        value_str = (
            _substitute(str(value), variables) if isinstance(value, (str, int, float, bool)) else ""
        )
        pairs.append((_substitute(key, variables), value_str))
    return pairs


def _render_multipart(pairs: list[tuple[str, str]]) -> bytes:
    if not pairs:
        return b""
    lines: list[str] = []
    for name, value in pairs:
        # Field names are sanitised to keep the multipart framing well-formed.
        safe_name = name.replace('"', "").replace("\r", "").replace("\n", "")
        lines.append(f"--{_MULTIPART_BOUNDARY}")
        lines.append(f'Content-Disposition: form-data; name="{safe_name}"')
        lines.append("")
        lines.append(value.replace("\r\n", "\n"))
    lines.append(f"--{_MULTIPART_BOUNDARY}--")
    lines.append("")
    return "\r\n".join(lines).encode("utf-8", errors="replace")


def _build_exchange(item_request: dict[str, object], variables: dict[str, str]) -> ImportedExchange:
    method = item_request.get("method")
    if not isinstance(method, str) or method.upper() not in _HTTP_METHODS:
        raise PostmanImportError("request has a missing/unsupported HTTP method")

    raw_url = _raw_url(item_request.get("url"), variables)
    if not raw_url:
        raise PostmanImportError("request has an empty url")
    if "{{" in raw_url:
        raise PostmanImportError(
            "request url has unresolved {{variable}} (supply via variables=...)"
        )
    split = urlsplit(raw_url if "://" in raw_url else f"https://{raw_url}")
    if not split.netloc:
        raise PostmanImportError("request url has no host authority (define {{base_url}})")

    target, host = _origin_form(split.geturl())
    body, content_type = _body(item_request, variables)
    headers = _headers(item_request, variables)
    if content_type and not _has_header(headers, "content-type"):
        headers = (*headers, ("Content-Type", content_type))
    headers = _ensure_host(headers, host)

    try:
        request = NormalizedRequest(
            method=method.upper(),
            target=target,
            http_version=_DEFAULT_HTTP_VERSION,
            headers=headers,
        )
    except ValueError as exc:
        raise PostmanImportError(
            f"invalid synthetic request head: {exc.__class__.__name__}"
        ) from exc

    body, truncated = _bounded(body)
    return ImportedExchange(
        url=split.geturl(),
        request=request,
        request_body=body,
        response=None,
        response_body=b"",
        started_at=None,
        truncated=truncated,
    )


def _walk_items(
    items: object,
    variables: dict[str, str],
    exchanges: list[ImportedExchange],
    depth: int,
) -> None:
    if not isinstance(items, list) or depth > _MAX_DEPTH:
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        if len(exchanges) >= _MAX_REQUESTS:
            return
        nested = item.get("item")
        if isinstance(nested, list):
            _walk_items(nested, variables, exchanges, depth + 1)
            continue
        item_request = item.get("request")
        if isinstance(item_request, dict):
            exchanges.append(_build_exchange(item_request, variables))
        elif isinstance(item_request, str):
            exchanges.append(_build_exchange({"method": "GET", "url": item_request}, variables))


def import_postman(
    raw: bytes | str, *, variables: dict[str, str] | None = None
) -> list[ImportedExchange]:
    """Import a Postman Collection v2.1 into synthetic exchanges.

    ``variables`` overrides/augments the collection's own ``variable`` map
    (e.g. to supply ``base_url``). Raises :class:`PostmanImportError` on any
    structural problem. Requests beyond :data:`_MAX_REQUESTS` are ignored.
    """
    document = _load_document(raw)
    info = document.get("info")
    if not isinstance(info, dict):
        raise PostmanImportError("collection is missing the 'info' object")
    items = document.get("item")
    if not isinstance(items, list):
        raise PostmanImportError("collection 'item' must be an array")

    resolved_vars = _collect_variables(document, variables)
    exchanges: list[ImportedExchange] = []
    _walk_items(items, resolved_vars, exchanges, depth=0)
    return exchanges


__all__ = [
    "PostmanImportError",
    "import_postman",
]
