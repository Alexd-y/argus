"""OpenAPI / Swagger importer for the Web Workbench (WB-P10b, pure).

Turns an OpenAPI 3.x or Swagger 2.0 document into synthetic
:class:`~src.web_workbench.imports.har.ImportedExchange` entries — one per
operation — so an API spec can seed the workbench (scope, scanner targets,
Repeater) the same way captured traffic does. Only the **request** side is
synthesised (``response=None``); path / query / header parameters and a JSON
request body are filled from declared examples or minimal type-based samples.

Pure (no I/O/network/DB), offline-testable, **fail-closed**
(:class:`OpenApiImportError`), and **bounded** (operation count capped). Header
names/values with CR/LF are dropped (header-injection guard). Sample values are
never secrets — they come from the spec's own examples or neutral placeholders.
"""

from __future__ import annotations

import json
from typing import Final
from urllib.parse import urlencode, urlsplit

import yaml

from src.web_workbench.imports.har import ImportedExchange
from src.web_workbench.proxy.transport import NormalizedRequest

_HTTP_METHODS: Final[frozenset[str]] = frozenset(
    {"get", "post", "put", "patch", "delete", "options", "head"}
)
#: Maximum number of operations imported in one call (DoS guard).
_MAX_OPERATIONS: Final[int] = 5_000
_DEFAULT_HTTP_VERSION: Final[str] = "HTTP/1.1"


class OpenApiImportError(ValueError):
    """Raised when an OpenAPI/Swagger document cannot be imported (fail-closed)."""


def _load_document(raw: bytes | str) -> dict[str, object]:
    try:
        document = yaml.safe_load(raw)  # superset of JSON, handles both
    except yaml.YAMLError as exc:
        raise OpenApiImportError(f"spec is not valid JSON/YAML: {exc.__class__.__name__}") from exc
    if not isinstance(document, dict):
        raise OpenApiImportError("spec root must be a mapping")
    return document


def _resolve_base(document: dict[str, object], base_url: str | None) -> tuple[str, str]:
    """Return ``(host, path_prefix)`` for building request targets.

    Resolution order: explicit ``base_url`` → OpenAPI 3 ``servers[0].url`` →
    Swagger 2 ``schemes/host/basePath``. Raises when no host can be resolved
    (a target without an authority cannot pass the workbench scope gate).
    """
    candidate: str | None = base_url
    if candidate is None:
        servers = document.get("servers")
        if isinstance(servers, list) and servers and isinstance(servers[0], dict):
            url = servers[0].get("url")
            if isinstance(url, str):
                candidate = url
    if candidate is None and isinstance(document.get("host"), str):
        host = str(document["host"])
        schemes = document.get("schemes")
        scheme = "https"
        if isinstance(schemes, list) and schemes and isinstance(schemes[0], str):
            scheme = schemes[0]
        base_path = document.get("basePath")
        prefix = base_path if isinstance(base_path, str) else ""
        candidate = f"{scheme}://{host}{prefix}"

    if not candidate:
        raise OpenApiImportError("cannot resolve server host; pass base_url explicitly")

    split = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
    if not split.netloc:
        raise OpenApiImportError("resolved server url has no host authority")
    prefix = split.path.rstrip("/")
    return split.netloc, prefix


def _sample_for_schema(param: dict[str, object]) -> str:
    """Return a neutral sample string for a parameter (example > enum > type)."""
    if isinstance(param.get("example"), (str, int, float, bool)):
        return str(param["example"])
    schema = param.get("schema")
    schema = schema if isinstance(schema, dict) else param  # swagger2 inlines type
    if isinstance(schema.get("example"), (str, int, float, bool)):
        return str(schema["example"])
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return str(enum[0])
    kind = schema.get("type")
    if kind in ("integer", "number"):
        return "1"
    if kind == "boolean":
        return "true"
    return "example"


def _has_crlf(text: str) -> bool:
    return "\r" in text or "\n" in text


def _collect_params(
    path_item: dict[str, object], operation: dict[str, object]
) -> list[dict[str, object]]:
    params: list[dict[str, object]] = []
    for source in (path_item.get("parameters"), operation.get("parameters")):
        if isinstance(source, list):
            params.extend(p for p in source if isinstance(p, dict))
    return params


def _build_target(raw_path: str, prefix: str, params: list[dict[str, object]]) -> str:
    path = raw_path
    query_pairs: list[tuple[str, str]] = []
    for param in params:
        name = param.get("name")
        location = param.get("in")
        if not isinstance(name, str) or not name:
            continue
        if location == "path":
            path = path.replace(f"{{{name}}}", _sample_for_schema(param))
        elif location == "query" and param.get("required") is True:
            query_pairs.append((name, _sample_for_schema(param)))
    target = f"{prefix}{path}"
    if not target.startswith("/"):
        target = "/" + target
    if query_pairs:
        target = f"{target}?{urlencode(query_pairs)}"
    return target


def _build_headers(
    host: str, params: list[dict[str, object]], has_json_body: bool
) -> tuple[tuple[str, str], ...]:
    headers: list[tuple[str, str]] = [("Host", host)]
    for param in params:
        if param.get("in") != "header":
            continue
        name = param.get("name")
        if not isinstance(name, str) or not name or _has_crlf(name):
            continue
        value = _sample_for_schema(param)
        if _has_crlf(value):
            continue
        headers.append((name, value))
    if has_json_body:
        headers.append(("Content-Type", "application/json"))
    return tuple(headers)


def _request_body(operation: dict[str, object]) -> bytes:
    """Extract a JSON request-body sample from an OpenAPI 3 ``requestBody``."""
    request_body = operation.get("requestBody")
    if not isinstance(request_body, dict):
        return b""
    content = request_body.get("content")
    if not isinstance(content, dict):
        return b""
    json_media = content.get("application/json")
    if not isinstance(json_media, dict):
        return b""
    if "example" in json_media:
        return json.dumps(json_media["example"]).encode("utf-8")
    schema = json_media.get("schema")
    if isinstance(schema, dict) and "example" in schema:
        return json.dumps(schema["example"]).encode("utf-8")
    return b"{}"


def import_openapi(raw: bytes | str, *, base_url: str | None = None) -> list[ImportedExchange]:
    """Import an OpenAPI 3.x / Swagger 2.0 spec into synthetic exchanges.

    ``base_url`` overrides the server host/prefix (useful when the spec uses a
    relative ``servers`` url). Raises :class:`OpenApiImportError` on any
    structural problem. Operations beyond :data:`_MAX_OPERATIONS` are ignored.
    """
    document = _load_document(raw)
    if "openapi" not in document and "swagger" not in document:
        raise OpenApiImportError("spec is missing the 'openapi'/'swagger' version field")
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise OpenApiImportError("spec 'paths' must be a mapping")

    host, prefix = _resolve_base(document, base_url)

    exchanges: list[ImportedExchange] = []
    for raw_path, path_item in paths.items():
        if not isinstance(raw_path, str) or not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if not isinstance(method, str) or method.lower() not in _HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue
            if len(exchanges) >= _MAX_OPERATIONS:
                return exchanges

            params = _collect_params(path_item, operation)
            body = _request_body(operation)
            target = _build_target(raw_path, prefix, params)
            headers = _build_headers(host, params, has_json_body=bool(body))
            try:
                request = NormalizedRequest(
                    method=method.upper(),
                    target=target,
                    http_version=_DEFAULT_HTTP_VERSION,
                    headers=headers,
                )
            except ValueError as exc:
                raise OpenApiImportError(
                    f"invalid synthetic request for {method.upper()} {raw_path}: "
                    f"{exc.__class__.__name__}"
                ) from exc

            exchanges.append(
                ImportedExchange(
                    url=f"https://{host}{target}",
                    request=request,
                    request_body=body,
                    response=None,
                    response_body=b"",
                    started_at=None,
                    truncated=False,
                )
            )
    return exchanges


__all__ = [
    "OpenApiImportError",
    "import_openapi",
]
