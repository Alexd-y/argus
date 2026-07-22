"""GraphQL introspection importer for the Web Workbench (WB-P10d, pure).

Turns a GraphQL introspection result (``__schema``) into synthetic
:class:`~src.web_workbench.imports.har.ImportedExchange` entries — one HTTP
``POST`` per root ``Query``/``Mutation`` field — so a GraphQL endpoint can seed
the workbench (scope, scanner targets, Repeater) the same way HAR/OpenAPI/Postman
imports do. Only the **request** side is synthesised (``response=None``); the
POST body is a standard ``{"query": "..."}`` document with a depth-bounded
selection set and scalar/enum argument samples.

Pure (no I/O/network/DB), offline-testable, **fail-closed**
(:class:`GraphQLImportError`) and **bounded** (root-field count, selection depth,
and fields-per-level all capped — introspection graphs can be deep/cyclic).
Sample argument values are neutral placeholders (never fabricated secrets).
"""

from __future__ import annotations

import json
from typing import Final
from urllib.parse import urlsplit

import yaml

from src.web_workbench.imports.har import ImportedExchange, _ensure_host, _origin_form
from src.web_workbench.proxy.transport import NormalizedRequest

_LEAF_KINDS: Final[frozenset[str]] = frozenset({"SCALAR", "ENUM"})
_COMPOSITE_KINDS: Final[frozenset[str]] = frozenset({"OBJECT", "INTERFACE"})
_WRAPPER_KINDS: Final[frozenset[str]] = frozenset({"NON_NULL", "LIST"})
#: Maximum number of root operations (Query + Mutation fields) imported.
_MAX_OPERATIONS: Final[int] = 2_000
#: Maximum selection-set nesting depth (recursion guard for cyclic schemas).
_MAX_DEPTH: Final[int] = 4
#: Maximum leaf/composite fields selected per level (fan-out guard).
_MAX_FIELDS_PER_LEVEL: Final[int] = 50
_DEFAULT_HTTP_VERSION: Final[str] = "HTTP/1.1"


class GraphQLImportError(ValueError):
    """Raised when a GraphQL introspection document cannot be imported (fail-closed)."""


def _load_schema(raw: bytes | str) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    """Return ``(schema, type_map)`` from an introspection document."""
    try:
        document = yaml.safe_load(raw)  # JSON is a subset of YAML
    except yaml.YAMLError as exc:
        raise GraphQLImportError(
            f"introspection is not valid JSON/YAML: {exc.__class__.__name__}"
        ) from exc
    if not isinstance(document, dict):
        raise GraphQLImportError("introspection root must be a mapping")

    schema = document.get("__schema")
    if schema is None and isinstance(document.get("data"), dict):
        schema = document["data"].get("__schema")
    if not isinstance(schema, dict):
        raise GraphQLImportError("introspection is missing '__schema'")

    raw_types = schema.get("types")
    if not isinstance(raw_types, list):
        raise GraphQLImportError("'__schema.types' must be an array")

    type_map: dict[str, dict[str, object]] = {}
    for entry in raw_types:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            type_map[str(entry["name"])] = entry
    return schema, type_map


def _unwrap(type_ref: object) -> dict[str, object] | None:
    """Peel ``NON_NULL``/``LIST`` wrappers to the innermost named type."""
    current = type_ref
    for _ in range(16):  # bounded unwrap
        if not isinstance(current, dict):
            return None
        if current.get("kind") in _WRAPPER_KINDS:
            current = current.get("ofType")
            continue
        return current
    return None


def _is_required(type_ref: object) -> bool:
    return isinstance(type_ref, dict) and type_ref.get("kind") == "NON_NULL"


def _has_required_args(field: dict[str, object]) -> bool:
    args = field.get("args")
    if not isinstance(args, list):
        return False
    return any(isinstance(a, dict) and _is_required(a.get("type")) for a in args)


def _scalar_literal(named: dict[str, object], type_map: dict[str, dict[str, object]]) -> str | None:
    """Return a GraphQL literal for a scalar/enum type, or ``None`` if unsupported."""
    kind = named.get("kind")
    name = named.get("name")
    if kind == "ENUM":
        resolved = type_map.get(str(name))
        values = resolved.get("enumValues") if isinstance(resolved, dict) else None
        if isinstance(values, list):
            for value in values:
                if isinstance(value, dict) and isinstance(value.get("name"), str):
                    return str(value["name"])  # enum literals are unquoted
        return None
    if kind != "SCALAR":
        return None
    if name == "Int":
        return "1"
    if name == "Float":
        return "1.0"
    if name == "Boolean":
        return "true"
    if name == "ID":
        return '"1"'
    # String and custom scalars are treated as quoted strings.
    return '"example"'


def _build_args(
    field: dict[str, object], type_map: dict[str, dict[str, object]]
) -> tuple[str, bool]:
    """Return ``(arg_string, ok)``; ``ok`` is ``False`` if a required arg is non-scalar.

    Only *required* arguments are emitted (optional args are omitted). When a
    required argument's type is a composite/input object we cannot synthesise a
    valid literal, so the whole operation is skipped to keep the query valid.
    """
    args = field.get("args")
    if not isinstance(args, list):
        return "", True
    parts: list[str] = []
    for arg in args:
        if not isinstance(arg, dict) or not _is_required(arg.get("type")):
            continue
        name = arg.get("name")
        named = _unwrap(arg.get("type"))
        if not isinstance(name, str) or named is None:
            return "", False
        literal = _scalar_literal(named, type_map)
        if literal is None:
            return "", False
        parts.append(f"{name}: {literal}")
    if not parts:
        return "", True
    return "(" + ", ".join(parts) + ")", True


def _selection_set(
    type_name: str,
    type_map: dict[str, dict[str, object]],
    depth: int,
    visited: frozenset[str],
) -> str:
    """Build a depth-bounded selection set for a composite type."""
    type_def = type_map.get(type_name)
    if not isinstance(type_def, dict) or type_def.get("kind") not in _COMPOSITE_KINDS:
        return ""
    fields = type_def.get("fields")
    if not isinstance(fields, list):
        return "__typename"

    parts: list[str] = []
    for field in fields:
        if len(parts) >= _MAX_FIELDS_PER_LEVEL:
            break
        if not isinstance(field, dict) or _has_required_args(field):
            continue
        name = field.get("name")
        named = _unwrap(field.get("type"))
        if not isinstance(name, str) or named is None:
            continue
        kind = named.get("kind")
        if kind in _LEAF_KINDS:
            parts.append(name)
        elif kind in _COMPOSITE_KINDS and depth < _MAX_DEPTH:
            child_name = named.get("name")
            if isinstance(child_name, str) and child_name not in visited:
                sub = _selection_set(child_name, type_map, depth + 1, visited | {child_name})
                if sub:
                    parts.append(f"{name} {{ {sub} }}")
    if not parts:
        return "__typename"
    return " ".join(parts)


def _build_operation(
    operation: str,
    field: dict[str, object],
    type_map: dict[str, dict[str, object]],
) -> str | None:
    """Return a full ``query``/``mutation`` document for a root field, or ``None``."""
    name = field.get("name")
    if not isinstance(name, str) or not name:
        return None
    args_str, ok = _build_args(field, type_map)
    if not ok:
        return None
    named = _unwrap(field.get("type"))
    selection = ""
    if named is not None and named.get("kind") in _COMPOSITE_KINDS:
        child = named.get("name")
        if isinstance(child, str):
            body = _selection_set(child, type_map, depth=1, visited=frozenset({child}))
            selection = f" {{ {body} }}"
        # A composite field with no resolvable name cannot be selected → skip.
        if not selection:
            return None
    return f"{operation} {name}{args_str}{selection}"


def _root_fields(
    schema: dict[str, object], type_map: dict[str, dict[str, object]], root_key: str
) -> list[dict[str, object]]:
    root_ref = schema.get(root_key)
    if not isinstance(root_ref, dict):
        return []
    root_name = root_ref.get("name")
    if not isinstance(root_name, str):
        return []
    root_type = type_map.get(root_name)
    if not isinstance(root_type, dict):
        return []
    fields = root_type.get("fields")
    return [f for f in fields if isinstance(f, dict)] if isinstance(fields, list) else []


def import_graphql_introspection(raw: bytes | str, *, endpoint_url: str) -> list[ImportedExchange]:
    """Import a GraphQL introspection result into synthetic POST exchanges.

    ``endpoint_url`` is the GraphQL HTTP endpoint (introspection carries no URL).
    Raises :class:`GraphQLImportError` on any structural problem. Operations
    beyond :data:`_MAX_OPERATIONS` are ignored.
    """
    if not endpoint_url or not endpoint_url.strip():
        raise GraphQLImportError("endpoint_url is required")
    split = urlsplit(endpoint_url if "://" in endpoint_url else f"https://{endpoint_url}")
    if not split.netloc:
        raise GraphQLImportError("endpoint_url has no host authority")

    schema, type_map = _load_schema(raw)
    target, host = _origin_form(split.geturl())

    operations: list[str] = []
    for root_key, keyword in (("queryType", "query"), ("mutationType", "mutation")):
        for field in _root_fields(schema, type_map, root_key):
            if len(operations) >= _MAX_OPERATIONS:
                break
            document = _build_operation(keyword, field, type_map)
            if document is not None:
                operations.append(document)

    if not operations:
        raise GraphQLImportError("no importable root fields found in schema")

    headers = _ensure_host((("Content-Type", "application/json"),), host)
    exchanges: list[ImportedExchange] = []
    for document in operations:
        body = json.dumps({"query": document}).encode("utf-8")
        try:
            request = NormalizedRequest(
                method="POST",
                target=target,
                http_version=_DEFAULT_HTTP_VERSION,
                headers=headers,
            )
        except ValueError as exc:  # pragma: no cover - target validated above
            raise GraphQLImportError(
                f"invalid synthetic request head: {exc.__class__.__name__}"
            ) from exc
        exchanges.append(
            ImportedExchange(
                url=split.geturl(),
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
    "GraphQLImportError",
    "import_graphql_introspection",
]
