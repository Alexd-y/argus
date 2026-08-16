"""OpenAPI / Swagger ingest for API surface modeling (Stage E)."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Final
from urllib.parse import urlsplit
from uuid import uuid4

import yaml

from src.api_surface.schemas import (
    ApiDocumentDTO,
    AuthRequirementDTO,
    AuthSchemeKind,
    EndpointDTO,
    FuzzPointDTO,
    ParameterDTO,
    ParameterLocation,
)
from src.execution_mode.mode import ExecutionMode, parse_execution_mode

_HTTP_METHODS: Final[frozenset[str]] = frozenset(
    {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
)
_MAX_OPERATIONS: Final[int] = 5_000
_MAX_DOCUMENT_BYTES: Final[int] = 8 * 1024 * 1024
_MAX_REF_DEPTH: Final[int] = 32
_EXTERNAL_REF_RE: Final[re.Pattern[str]] = re.compile(r"^https?://", re.IGNORECASE)


class OpenApiIngestError(ValueError):
    """Raised when an OpenAPI document cannot be ingested."""


class OpenApiParseIsolationError(OpenApiIngestError):
    """Raised when parse isolation catches a document-level failure."""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stable_endpoint_id(
    *,
    asset_id: str,
    method: str,
    normalized_path: str,
    operation_id: str | None,
) -> str:
    canonical = json.dumps(
        {
            "asset": asset_id,
            "method": method.upper(),
            "path": normalized_path,
            "operationId": operation_id or "",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _stable_fuzz_point_id(endpoint_id: str, parameter: ParameterDTO) -> str:
    canonical = f"{endpoint_id}:{parameter.location.value}:{parameter.name}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _load_document(raw: bytes | str) -> dict[str, Any]:
    if isinstance(raw, str):
        payload = raw.encode("utf-8")
    else:
        payload = raw
    if len(payload) > _MAX_DOCUMENT_BYTES:
        raise OpenApiIngestError(
            f"document exceeds max size of {_MAX_DOCUMENT_BYTES} bytes"
        )
    try:
        document = yaml.safe_load(payload)
    except yaml.YAMLError as exc:
        raise OpenApiIngestError("document is not valid JSON/YAML") from exc
    if not isinstance(document, dict):
        raise OpenApiIngestError("document root must be a mapping")
    return document


def _detect_spec_version(document: dict[str, Any]) -> str:
    if isinstance(document.get("openapi"), str):
        return str(document["openapi"])
    if isinstance(document.get("swagger"), str):
        return f"swagger/{document['swagger']}"
    raise OpenApiIngestError("unsupported spec: missing openapi/swagger version")


def _scan_external_refs(node: Any) -> list[str]:
    """Collect external http(s) $ref values anywhere in the document tree."""
    refs: list[str] = []
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and _EXTERNAL_REF_RE.match(ref.strip()):
            refs.append(ref.strip())
        for value in node.values():
            refs.extend(_scan_external_refs(value))
    elif isinstance(node, list):
        for item in node:
            refs.extend(_scan_external_refs(item))
    return refs


def _enforce_production_ref_policy(document: dict[str, Any]) -> None:
    external_refs = _scan_external_refs(document)
    if external_refs:
        raise OpenApiIngestError(
            "production mode blocks external http(s) $ref resolution"
        )


def _reject_unsafe_external_ref(ref: str, *, mode: ExecutionMode) -> None:
    if mode is ExecutionMode.PRODUCTION and _EXTERNAL_REF_RE.match(ref.strip()):
        raise OpenApiIngestError(
            "production mode blocks external http(s) $ref resolution"
        )


def _resolve_ref(
    document: dict[str, Any],
    ref: str,
    *,
    mode: ExecutionMode,
    depth: int,
    warnings: list[str],
) -> Any:
    if depth > _MAX_REF_DEPTH:
        raise OpenApiIngestError("maximum $ref recursion depth exceeded")
    _reject_unsafe_external_ref(ref, mode=mode)
    if not ref.startswith("#/"):
        if mode is ExecutionMode.LAB_UNRESTRICTED:
            warnings.append(f"skipped unresolved external ref: {ref[:120]}")
            return {}
        raise OpenApiIngestError(f"unsupported external ref: {ref[:120]}")
    parts = ref[2:].split("/")
    node: Any = document
    for part in parts:
        if not isinstance(node, dict) or part not in node:
            if mode is ExecutionMode.LAB_UNRESTRICTED:
                warnings.append(f"broken ref path: {ref}")
                return {}
            raise OpenApiIngestError(f"broken ref path: {ref}")
        node = node[part]
    if isinstance(node, dict) and "$ref" in node:
        return _resolve_ref(
            document,
            str(node["$ref"]),
            mode=mode,
            depth=depth + 1,
            warnings=warnings,
        )
    return node


def _deref(
    document: dict[str, Any],
    obj: Any,
    *,
    mode: ExecutionMode,
    depth: int,
    warnings: list[str],
) -> Any:
    if isinstance(obj, dict) and "$ref" in obj:
        return _resolve_ref(
            document,
            str(obj["$ref"]),
            mode=mode,
            depth=depth,
            warnings=warnings,
        )
    return obj


def _resolve_servers(document: dict[str, Any], base_url: str | None) -> tuple[str, ...]:
    servers: list[str] = []
    if base_url:
        servers.append(base_url)
    raw_servers = document.get("servers")
    if isinstance(raw_servers, list):
        for entry in raw_servers:
            if isinstance(entry, dict) and isinstance(entry.get("url"), str):
                servers.append(entry["url"])
    if not servers and isinstance(document.get("host"), str):
        host = str(document["host"])
        schemes = document.get("schemes")
        scheme = "https"
        if isinstance(schemes, list) and schemes and isinstance(schemes[0], str):
            scheme = schemes[0]
        base_path = document.get("basePath")
        prefix = base_path if isinstance(base_path, str) else ""
        servers.append(f"{scheme}://{host}{prefix}")
    deduped: list[str] = []
    seen: set[str] = set()
    for server in servers:
        if server not in seen:
            seen.add(server)
            deduped.append(server)
    return tuple(deduped)


def _normalize_path(path: str, *, prefix: str = "") -> str:
    combined = f"{prefix.rstrip('/')}/{path.lstrip('/')}" if prefix else path
    if not combined.startswith("/"):
        combined = f"/{combined}"
    return re.sub(r"/{2,}", "/", combined)


def _schema_type(schema: dict[str, Any] | None) -> tuple[str | None, str | None]:
    if not schema:
        return None, None
    schema_type = schema.get("type")
    schema_format = schema.get("format")
    return (
        str(schema_type) if isinstance(schema_type, str) else None,
        str(schema_format) if isinstance(schema_format, str) else None,
    )


def _parse_parameters(
    document: dict[str, Any],
    raw_params: list[Any] | None,
    *,
    mode: ExecutionMode,
    warnings: list[str],
    source_ref: str,
) -> tuple[ParameterDTO, ...]:
    if not raw_params:
        return ()
    parsed: list[ParameterDTO] = []
    for raw in raw_params:
        if not isinstance(raw, dict):
            if mode is ExecutionMode.LAB_UNRESTRICTED:
                warnings.append(f"skipped malformed parameter in {source_ref}")
                continue
            raise OpenApiIngestError(f"malformed parameter in {source_ref}")
        param = _deref(document, raw, mode=mode, depth=0, warnings=warnings)
        if not isinstance(param, dict):
            continue
        name = param.get("name")
        location = param.get("in")
        if not isinstance(name, str) or not isinstance(location, str):
            if mode is ExecutionMode.LAB_UNRESTRICTED:
                warnings.append(f"skipped parameter without name/in in {source_ref}")
                continue
            raise OpenApiIngestError(f"parameter missing name/in in {source_ref}")
        try:
            loc = ParameterLocation(location)
        except ValueError:
            if mode is ExecutionMode.LAB_UNRESTRICTED:
                warnings.append(f"skipped unknown parameter location {location!r}")
                continue
            raise OpenApiIngestError(f"unknown parameter location: {location}") from None
        schema = param.get("schema")
        schema_dict = schema if isinstance(schema, dict) else None
        if schema_dict is None and isinstance(param.get("type"), str):
            schema_dict = {"type": param["type"]}
        schema_type, schema_format = _schema_type(schema_dict)
        parsed.append(
            ParameterDTO(
                name=name,
                location=loc,
                required=bool(param.get("required", False)),
                schema_type=schema_type,
                schema_format=schema_format,
                example=param.get("example"),
                source_ref=source_ref,
            )
        )
    return tuple(parsed)


def _parse_auth(
    document: dict[str, Any],
    operation: dict[str, Any],
    *,
    mode: ExecutionMode,
    warnings: list[str],
) -> tuple[AuthRequirementDTO, ...]:
    security_defs = document.get("securityDefinitions") or document.get("components", {})
    schemes_container = security_defs
    if isinstance(security_defs, dict) and "securitySchemes" in security_defs:
        schemes_container = security_defs["securitySchemes"]
    if not isinstance(schemes_container, dict):
        schemes_container = {}

    requirements: list[AuthRequirementDTO] = []
    security = operation.get("security", document.get("security"))
    if not isinstance(security, list):
        return ()
    for requirement in security:
        if not isinstance(requirement, dict):
            continue
        for scheme_name, scopes in requirement.items():
            raw_scheme = schemes_container.get(scheme_name, {})
            scheme = _deref(document, raw_scheme, mode=mode, depth=0, warnings=warnings)
            if not isinstance(scheme, dict):
                if mode is ExecutionMode.LAB_UNRESTRICTED:
                    warnings.append(f"unknown auth scheme {scheme_name}")
                    scheme = {}
                else:
                    raise OpenApiIngestError(f"unknown auth scheme: {scheme_name}")
            kind_raw = str(scheme.get("type") or "custom")
            try:
                kind = AuthSchemeKind(kind_raw)
            except ValueError:
                kind = AuthSchemeKind.CUSTOM
            scope_tuple = tuple(str(s) for s in scopes) if isinstance(scopes, list) else ()
            requirements.append(
                AuthRequirementDTO(
                    scheme_name=str(scheme_name),
                    kind=kind,
                    scopes=scope_tuple,
                    in_location=(
                        str(scheme["in"]) if isinstance(scheme.get("in"), str) else None
                    ),
                    param_name=(
                        str(scheme["name"])
                        if isinstance(scheme.get("name"), str)
                        else None
                    ),
                )
            )
    return tuple(requirements)


def _content_types(operation: dict[str, Any]) -> tuple[str, ...]:
    request_body = operation.get("requestBody")
    if isinstance(request_body, dict):
        content = request_body.get("content")
        if isinstance(content, dict):
            return tuple(str(k) for k in content.keys())
    consumes = operation.get("consumes")
    if isinstance(consumes, list):
        return tuple(str(c) for c in consumes)
    return ()


def _risk_hints(operation: dict[str, Any], parameters: tuple[ParameterDTO, ...]) -> tuple[str, ...]:
    hints: list[str] = []
    tags = operation.get("tags")
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag.strip():
                hints.append(f"tag:{tag.strip().lower()}")
    for param in parameters:
        lowered = param.name.lower()
        if any(token in lowered for token in ("password", "token", "secret", "apikey")):
            hints.append("sensitive_parameter")
        if param.location is ParameterLocation.BODY and param.schema_type == "object":
            hints.append("json_body")
    return tuple(dict.fromkeys(hints))


def _fuzz_points(endpoint_id: str, parameters: tuple[ParameterDTO, ...]) -> tuple[FuzzPointDTO, ...]:
    points: list[FuzzPointDTO] = []
    for param in parameters:
        points.append(
            FuzzPointDTO(
                id=_stable_fuzz_point_id(endpoint_id, param),
                endpoint_id=endpoint_id,
                parameter_name=param.name,
                location=param.location,
                risk_hint="sensitive" if "password" in param.name.lower() else None,
            )
        )
    return tuple(points)


def _iter_operations(
    document: dict[str, Any],
    *,
    mode: ExecutionMode,
    warnings: list[str],
) -> list[tuple[str, str, dict[str, Any]]]:
    paths = document.get("paths")
    if not isinstance(paths, dict):
        if mode is ExecutionMode.LAB_UNRESTRICTED:
            warnings.append("missing paths section")
            return []
        raise OpenApiIngestError("missing paths section")
    operations: list[tuple[str, str, dict[str, Any]]] = []
    for path, path_item in paths.items():
        if not isinstance(path, str) or not isinstance(path_item, dict):
            if mode is ExecutionMode.LAB_UNRESTRICTED:
                warnings.append("skipped malformed path entry")
                continue
            raise OpenApiIngestError("malformed path entry")
        path_item = _deref(document, path_item, mode=mode, depth=0, warnings=warnings)
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                if mode is ExecutionMode.LAB_UNRESTRICTED:
                    warnings.append(f"skipped malformed operation {method.upper()} {path}")
                    continue
                raise OpenApiIngestError(f"malformed operation {method.upper()} {path}")
            operation = _deref(document, operation, mode=mode, depth=0, warnings=warnings)
            if isinstance(operation, dict):
                operations.append((path, method.upper(), operation))
            if len(operations) > _MAX_OPERATIONS:
                raise OpenApiIngestError(f"operation count exceeds {_MAX_OPERATIONS}")
    return operations


def ingest_openapi(
    raw: bytes | str,
    *,
    tenant_id: str,
    asset_id: str,
    mode: ExecutionMode | str | None = ExecutionMode.PRODUCTION,
    base_url: str | None = None,
    document_id: str | None = None,
) -> ApiDocumentDTO:
    """Parse OpenAPI 3.x or Swagger 2.0 into structured API surface DTOs."""
    resolved_mode = parse_execution_mode(mode)
    payload = raw.encode("utf-8") if isinstance(raw, str) else raw
    source_sha256 = _sha256_bytes(payload)
    warnings: list[str] = []

    try:
        document = _load_document(payload)
        spec_version = _detect_spec_version(document)
        if resolved_mode is ExecutionMode.PRODUCTION:
            _enforce_production_ref_policy(document)
        else:
            for ref in _scan_external_refs(document):
                warnings.append(f"skipped unresolved external ref: {ref[:120]}")
        servers = _resolve_servers(document, base_url)
        if resolved_mode is ExecutionMode.PRODUCTION and not servers:
            raise OpenApiIngestError("production ingest requires resolvable servers")

        prefix = ""
        if servers:
            split = urlsplit(servers[0] if "://" in servers[0] else f"https://{servers[0]}")
            prefix = split.path.rstrip("/")

        endpoints: list[EndpointDTO] = []
        for path, method, operation in _iter_operations(
            document, mode=resolved_mode, warnings=warnings
        ):
            source_ref = f"{method} {path}"
            path_params = _parse_parameters(
                document,
                operation.get("parameters") if isinstance(operation.get("parameters"), list) else [],
                mode=resolved_mode,
                warnings=warnings,
                source_ref=source_ref,
            )
            operation_id = (
                str(operation["operationId"])
                if isinstance(operation.get("operationId"), str)
                else None
            )
            normalized_path = _normalize_path(path, prefix=prefix)
            endpoint_id = _stable_endpoint_id(
                asset_id=asset_id,
                method=method,
                normalized_path=normalized_path,
                operation_id=operation_id,
            )
            parameters = path_params
            auth_requirements = _parse_auth(
                document, operation, mode=resolved_mode, warnings=warnings
            )
            content_types = _content_types(operation)
            risk_hints = _risk_hints(operation, parameters)
            fuzz_points = _fuzz_points(endpoint_id, parameters)
            endpoints.append(
                EndpointDTO(
                    id=endpoint_id,
                    asset_id=asset_id,
                    method=method,
                    normalized_path=normalized_path,
                    operation_id=operation_id,
                    content_types=content_types,
                    parameters=parameters,
                    auth_requirements=auth_requirements,
                    source_ref=source_ref,
                    risk_hints=risk_hints,
                    fuzz_points=fuzz_points,
                )
            )

        return ApiDocumentDTO(
            id=document_id or str(uuid4()),
            tenant_id=tenant_id,
            asset_id=asset_id,
            title=str(document.get("info", {}).get("title"))
            if isinstance(document.get("info"), dict)
            and isinstance(document["info"].get("title"), str)
            else None,
            version=str(document.get("info", {}).get("version"))
            if isinstance(document.get("info"), dict)
            and isinstance(document["info"].get("version"), str)
            else None,
            spec_version=spec_version,
            servers=servers,
            endpoints=tuple(endpoints),
            parse_warnings=tuple(warnings),
            source_sha256=source_sha256,
        )
    except OpenApiIngestError:
        raise
    except Exception as exc:
        if resolved_mode is ExecutionMode.LAB_UNRESTRICTED:
            raise OpenApiParseIsolationError(
                "lab ingest isolated parse failure"
            ) from exc
        raise OpenApiIngestError("openapi ingest failed") from exc
