"""OpenAPI 3.1 emitter for the ARGUS MCP-tools surface (ARG-039).

Walks the live :class:`mcp.server.fastmcp.FastMCP` registry — tools,
resources, resource templates, and prompts — and emits a self-contained
OpenAPI 3.1 document with every Pydantic-derived JSON Schema lifted into
``components.schemas``.

The emitter is **pure** and **deterministic**: the same FastMCP instance
always produces a byte-identical YAML document when serialised with
``yaml.safe_dump(..., sort_keys=True, default_flow_style=False,
allow_unicode=False)``. This is the contract the
``mcp-openapi-drift`` CI gate relies on.

Mapping rules:

* ``@mcp.tool(name="x.y")``  → ``POST /rpc/x.y`` (operationId ``call_x_y``)
* ``@mcp.resource("argus://x/y")`` → ``GET /resources/x/y``
  (operationId ``read_argus_x_y``)
* Resource template ``argus://x/{id}``  → ``GET /resources/x/{id}`` with
  the path parameter explicitly declared.
* ``@mcp.prompt(name="x.y")`` → ``POST /prompts/x.y`` (operationId
  ``render_x_y``) with a synthesised JSON Schema body that mirrors the
  declared :class:`mcp.types.PromptArgument` list.

Local Pydantic ``$defs`` are lifted to ``components.schemas`` and every
``$ref`` is rewritten from ``#/$defs/X`` to ``#/components/schemas/X`` so
the spec is self-contained — a strict OpenAPI 3.1 validator (and
``openapi-typescript-codegen``) can resolve every reference without
needing access to the original Pydantic models.
"""

from __future__ import annotations

import asyncio
import copy
import re
from typing import Any, Final, cast

from mcp.server.fastmcp import FastMCP
from mcp.types import Prompt, PromptArgument, Resource, ResourceTemplate, Tool

OPENAPI_VERSION: Final[str] = "3.1.0"
ARGUS_API_VERSION: Final[str] = "0.4.0"  # Cycle 4 release
SERVER_TITLE: Final[str] = "ARGUS MCP Server"
SERVER_DESCRIPTION: Final[str] = (
    "Model Context Protocol surface for ARGUS — generated from FastMCP "
    "Pydantic schemas; do not edit by hand. Regenerate via "
    "`python -m scripts.export_mcp_openapi --out ../docs/mcp-server-openapi.yaml`."
)
RESOURCE_URI_PREFIX: Final[str] = "argus://"
RESOURCE_PATH_PREFIX: Final[str] = "/resources/"
TOOL_PATH_PREFIX: Final[str] = "/rpc/"
PROMPT_PATH_PREFIX: Final[str] = "/prompts/"
TOOL_TAG: Final[str] = "mcp-tool"
RESOURCE_TAG: Final[str] = "mcp-resource"
PROMPT_TAG: Final[str] = "mcp-prompt"
LOCAL_DEFS_PREFIX: Final[str] = "#/$defs/"
GLOBAL_DEFS_PREFIX: Final[str] = "#/components/schemas/"
PATH_PARAM_RE: Final[re.Pattern[str]] = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
IDENTIFIER_SAFE_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9]+")


def build_openapi_spec(app: FastMCP) -> dict[str, Any]:
    """Build a complete OpenAPI 3.1 spec from a wired FastMCP application.

    The returned dict is JSON-serialisable and key-stable: callers can
    safely round-trip it through ``yaml.safe_dump(..., sort_keys=True)``
    or ``json.dumps(..., sort_keys=True)`` without tripping the drift
    gate.
    """
    snapshot = _collect_runtime_snapshot(app)
    schemas: dict[str, dict[str, Any]] = {}

    paths: dict[str, Any] = {}
    paths.update(_build_tool_paths(snapshot.tools, schemas))
    paths.update(_build_resource_paths(snapshot.resources))
    paths.update(_build_resource_template_paths(snapshot.templates))
    paths.update(_build_prompt_paths(snapshot.prompts, schemas))

    return {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": SERVER_TITLE,
            "version": ARGUS_API_VERSION,
            "description": SERVER_DESCRIPTION,
            "contact": {
                "name": "ARGUS Engineering",
                "url": "https://github.com/argus/argus",
            },
            "license": {"name": "Proprietary"},
        },
        "servers": [
            {
                "url": "https://argus.example.com/mcp",
                "description": "Production (streamable-http transport)",
            },
            {
                "url": "http://localhost:8765/mcp",
                "description": "Local development (stdio + streamable-http)",
            },
        ],
        "tags": [
            {"name": TOOL_TAG, "description": "MCP tool calls (JSON-RPC over POST)."},
            {"name": RESOURCE_TAG, "description": "MCP resources (read-only views)."},
            {"name": PROMPT_TAG, "description": "MCP prompt templates."},
        ],
        "paths": paths,
        "components": {
            "schemas": dict(sorted(schemas.items())),
            "securitySchemes": {
                "bearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": (
                        "Static token, JWT access token, or HMAC-issued bearer "
                        "(see backend/src/mcp/auth.py)."
                    ),
                },
                "apiKey": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "API key from ARGUS_API_KEYS or ADMIN_API_KEY.",
                },
            },
        },
        "security": [{"bearer": []}, {"apiKey": []}],
    }


# ---------------------------------------------------------------------------
# Snapshot collection
# ---------------------------------------------------------------------------


class _RuntimeSnapshot:
    """Sorted, immutable view of the FastMCP capability surface."""

    __slots__ = ("tools", "resources", "templates", "prompts")

    def __init__(
        self,
        *,
        tools: list[Tool],
        resources: list[Resource],
        templates: list[ResourceTemplate],
        prompts: list[Prompt],
    ) -> None:
        self.tools = tools
        self.resources = resources
        self.templates = templates
        self.prompts = prompts


def _collect_runtime_snapshot(app: FastMCP) -> _RuntimeSnapshot:
    """Pull tools / resources / prompts from FastMCP via its public async API.

    FastMCP exposes the registry exclusively through async methods because
    the MCP wire-protocol requires async handlers. The underlying lookup
    is in-memory and synchronous, so wrapping with ``asyncio.run`` is
    cheap and has no I/O. Callers already inside a running event loop
    must use :func:`build_openapi_spec_async` instead.
    """
    return asyncio.run(_collect_runtime_snapshot_async(app))


async def _collect_runtime_snapshot_async(app: FastMCP) -> _RuntimeSnapshot:
    tools = sorted(await app.list_tools(), key=lambda t: t.name)
    resources = sorted(await app.list_resources(), key=lambda r: r.name)
    templates = sorted(await app.list_resource_templates(), key=lambda t: t.name)
    prompts = sorted(await app.list_prompts(), key=lambda p: p.name)
    return _RuntimeSnapshot(
        tools=tools, resources=resources, templates=templates, prompts=prompts
    )


# ---------------------------------------------------------------------------
# Path builders
# ---------------------------------------------------------------------------


def _build_tool_paths(
    tools: list[Tool], schemas: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for tool in tools:
        path = f"{TOOL_PATH_PREFIX}{tool.name}"
        request_ref = _register_schema(tool.inputSchema, schemas)
        response_ref = _register_optional_schema(tool.outputSchema, schemas)
        operation: dict[str, Any] = {
            "operationId": _operation_id("call", tool.name),
            "summary": (tool.title or tool.name).strip(),
            "description": (tool.description or "(no description)").strip(),
            "tags": [TOOL_TAG],
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {"$ref": request_ref},
                    }
                },
            },
            "responses": _build_responses(response_ref),
        }
        paths[path] = {"post": operation}
    return paths


def _build_resource_paths(resources: list[Resource]) -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for resource in resources:
        path = _uri_to_path(str(resource.uri))
        operation: dict[str, Any] = {
            "operationId": _operation_id("read", resource.name),
            "summary": (resource.title or resource.name).strip(),
            "description": (resource.description or "(no description)").strip(),
            "tags": [RESOURCE_TAG],
            "responses": _build_resource_responses(resource.mimeType),
        }
        paths[path] = {"get": operation}
    return paths


def _build_resource_template_paths(templates: list[ResourceTemplate]) -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for template in templates:
        path = _uri_to_path(template.uriTemplate)
        params = _extract_path_params(path)
        operation: dict[str, Any] = {
            "operationId": _operation_id("read", template.name),
            "summary": (template.title or template.name).strip(),
            "description": (template.description or "(no description)").strip(),
            "tags": [RESOURCE_TAG],
            "parameters": [_path_param(name) for name in params],
            "responses": _build_resource_responses(template.mimeType),
        }
        paths[path] = {"get": operation}
    return paths


def _build_prompt_paths(
    prompts: list[Prompt], schemas: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for prompt in prompts:
        path = f"{PROMPT_PATH_PREFIX}{prompt.name}"
        body_schema = _prompt_arguments_to_schema(prompt)
        body_schema_name = f"{_camel_case(prompt.name)}PromptArguments"
        schemas[body_schema_name] = body_schema
        operation: dict[str, Any] = {
            "operationId": _operation_id("render", prompt.name),
            "summary": (prompt.title or prompt.name).strip(),
            "description": (prompt.description or "(no description)").strip(),
            "tags": [PROMPT_TAG],
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {"$ref": GLOBAL_DEFS_PREFIX + body_schema_name},
                    }
                },
            },
            "responses": {
                "200": {
                    "description": "Rendered prompt as a list of MCP messages.",
                    "content": {"application/json": {"schema": {"type": "object"}}},
                },
                "400": _validation_error_response(),
                "401": _unauthorized_response(),
            },
        }
        paths[path] = {"post": operation}
    return paths


# ---------------------------------------------------------------------------
# Schema helpers — lift $defs and rewrite $ref strings.
# ---------------------------------------------------------------------------


def _register_schema(
    schema: dict[str, Any], registry: dict[str, dict[str, Any]]
) -> str:
    """Lift `schema` into `registry` (deep-copied) and return a `$ref` URL."""
    name = _schema_name(schema)
    lifted = _lift_and_rewrite(schema, registry)
    registry[name] = lifted
    return GLOBAL_DEFS_PREFIX + name


def _register_optional_schema(
    schema: dict[str, Any] | None, registry: dict[str, dict[str, Any]]
) -> str | None:
    if schema is None:
        return None
    return _register_schema(schema, registry)


def _lift_and_rewrite(
    schema: dict[str, Any], registry: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Return a copy of `schema` with `$defs` hoisted into `registry`.

    Recursively walks nested `$defs`. Existing entries in `registry` are
    NOT overwritten — Pydantic emits the same definition shape for the
    same model name, so collisions on the second occurrence are no-ops.
    """
    schema_copy = copy.deepcopy(schema)
    nested_defs = schema_copy.pop("$defs", None)
    if isinstance(nested_defs, dict):
        for def_name, def_schema in nested_defs.items():
            if not isinstance(def_schema, dict):
                continue
            lifted = _lift_and_rewrite(def_schema, registry)
            registry.setdefault(def_name, lifted)
    return cast(dict[str, Any], _rewrite_refs(schema_copy))


def _rewrite_refs(node: Any) -> Any:
    """Rewrite `#/$defs/X` refs to `#/components/schemas/X` recursively."""
    if isinstance(node, dict):
        result: dict[str, Any] = {}
        for key, value in node.items():
            if (
                key == "$ref"
                and isinstance(value, str)
                and value.startswith(LOCAL_DEFS_PREFIX)
            ):
                result[key] = GLOBAL_DEFS_PREFIX + value[len(LOCAL_DEFS_PREFIX) :]
            else:
                result[key] = _rewrite_refs(value)
        return result
    if isinstance(node, list):
        return [_rewrite_refs(item) for item in node]
    return node


def _schema_name(schema: dict[str, Any]) -> str:
    """Best-effort stable name for a Pydantic-emitted JSON Schema."""
    title = schema.get("title")
    if isinstance(title, str) and title.strip():
        return title.strip()
    return "AnonymousSchema"


# ---------------------------------------------------------------------------
# Prompt schema synthesis
# ---------------------------------------------------------------------------


def _prompt_arguments_to_schema(prompt: Prompt) -> dict[str, Any]:
    """Synthesise a JSON Schema for the `arguments` of a prompt."""
    properties: dict[str, Any] = {}
    required: list[str] = []
    for argument in prompt.arguments or []:
        properties[argument.name] = _prompt_argument_property(argument)
        if argument.required:
            required.append(argument.name)
    schema: dict[str, Any] = {
        "type": "object",
        "title": f"{_camel_case(prompt.name)}PromptArguments",
        "description": f"Arguments for the `{prompt.name}` MCP prompt.",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = sorted(required)
    return schema


def _prompt_argument_property(argument: PromptArgument) -> dict[str, Any]:
    prop: dict[str, Any] = {"type": "string"}
    if argument.description:
        prop["description"] = argument.description
    return prop


# ---------------------------------------------------------------------------
# Path / parameter helpers
# ---------------------------------------------------------------------------


def _uri_to_path(uri: str) -> str:
    """Convert an `argus://x/y` URI (template) into an OpenAPI path."""
    if uri.startswith(RESOURCE_URI_PREFIX):
        tail = uri[len(RESOURCE_URI_PREFIX) :]
    else:
        tail = uri.lstrip("/")
    if not tail.startswith("/"):
        tail = "/" + tail
    return RESOURCE_PATH_PREFIX.rstrip("/") + tail


def _extract_path_params(path: str) -> list[str]:
    return PATH_PARAM_RE.findall(path)


def _path_param(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "in": "path",
        "required": True,
        "schema": {"type": "string"},
    }


def _operation_id(verb: str, name: str) -> str:
    """Build a stable, identifier-safe operationId."""
    suffix = IDENTIFIER_SAFE_RE.sub("_", name).strip("_")
    return f"{verb}_{suffix}" if suffix else verb


def _camel_case(name: str) -> str:
    """Convert `scan.create` → `ScanCreate`, `vulnerability.explainer` → `VulnerabilityExplainer`."""
    parts = [p for p in IDENTIFIER_SAFE_RE.split(name) if p]
    return "".join(part[:1].upper() + part[1:] for part in parts)


# ---------------------------------------------------------------------------
# Response builders
# ---------------------------------------------------------------------------


def _build_responses(response_ref: str | None) -> dict[str, Any]:
    """Standard tool-call response set (200 / 400 / 401 / 403 / 404 / 422 / 429 / 500)."""
    success: dict[str, Any] = {"description": "OK — tool call accepted and executed."}
    if response_ref is not None:
        success["content"] = {"application/json": {"schema": {"$ref": response_ref}}}
    else:
        success["content"] = {"application/json": {"schema": {"type": "object"}}}
    return {
        "200": success,
        "400": _validation_error_response(),
        "401": _unauthorized_response(),
        "403": _forbidden_response(),
        "404": {"description": "Resource not found (anti-enumeration response)."},
        "422": _validation_error_response(),
        "429": {"description": "Rate limit exceeded."},
        "500": {
            "description": "Internal MCP error (server-side stack trace redacted)."
        },
    }


def _build_resource_responses(mime_type: str | None) -> dict[str, Any]:
    content_type = mime_type or "application/json"
    return {
        "200": {
            "description": "OK",
            "content": {content_type: {"schema": {"type": "object"}}},
        },
        "401": _unauthorized_response(),
        "403": _forbidden_response(),
        "404": {"description": "Resource not found (anti-enumeration response)."},
    }


def _validation_error_response() -> dict[str, Any]:
    return {"description": "Invalid arguments — validation error."}


def _unauthorized_response() -> dict[str, Any]:
    return {"description": "Unauthorized (missing or invalid bearer / API key)."}


def _forbidden_response() -> dict[str, Any]:
    return {
        "description": "Forbidden — tenant mismatch, scope violation, or policy denial."
    }


__all__ = [
    "ARGUS_API_VERSION",
    "GLOBAL_DEFS_PREFIX",
    "LOCAL_DEFS_PREFIX",
    "OPENAPI_VERSION",
    "build_openapi_spec",
]
