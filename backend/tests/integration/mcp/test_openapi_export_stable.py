"""ARG-039 — OpenAPI 3.1 export round-trip + stability invariants.

Three contracts protect the docs/SDK pipeline:

1.  **Snapshot stability** — the freshly-generated spec must equal the
    YAML committed at ``docs/mcp-server-openapi.yaml``. Drift here
    means somebody changed an MCP tool/resource/prompt without
    regenerating the spec; CI's ``mcp-openapi-drift`` job will fail
    with the same error.
2.  **Coverage** — every tool, resource, and prompt the FastMCP runtime
    exposes must appear under its canonical OpenAPI path
    (``/rpc/{tool}``, ``/resources/{path}``, ``/prompts/{name}``).
3.  **Self-containment** — every ``$ref`` in the rendered spec must
    resolve into ``components.schemas`` (no dangling refs, no leaked
    ``#/$defs/*`` pointers from Pydantic).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Final

import yaml

from src.mcp.openapi_emitter import (
    GLOBAL_DEFS_PREFIX,
    LOCAL_DEFS_PREFIX,
    OPENAPI_VERSION,
    build_openapi_spec,
)
from src.mcp.server import build_app

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[4]
COMMITTED_SPEC: Final[Path] = REPO_ROOT / "docs" / "mcp-server-openapi.yaml"


def _build_spec() -> dict[str, Any]:
    app = build_app(name="argus-openapi-test", log_level="WARNING")
    return build_openapi_spec(app)


def _list_runtime() -> tuple[list[str], list[str], list[str], list[str]]:
    """Return (tool_names, resource_uris, template_uris, prompt_names)."""
    app = build_app(name="argus-openapi-test", log_level="WARNING")

    async def _gather() -> tuple[list[str], list[str], list[str], list[str]]:
        tools = await app.list_tools()
        resources = await app.list_resources()
        templates = await app.list_resource_templates()
        prompts = await app.list_prompts()
        return (
            [t.name for t in tools],
            [str(r.uri) for r in resources],
            [t.uriTemplate for t in templates],
            [p.name for p in prompts],
        )

    return asyncio.run(_gather())


def _collect_refs(node: Any, refs: set[str]) -> None:
    """Walk a JSON-Schema-shaped tree and collect every ``$ref`` URL."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                refs.add(value)
            else:
                _collect_refs(value, refs)
    elif isinstance(node, list):
        for item in node:
            _collect_refs(item, refs)


def test_committed_spec_matches_generated() -> None:
    """The committed YAML must round-trip equal to a fresh build.

    Failure recipe:
        cd backend
        python -m scripts.export_mcp_openapi --out ../docs/mcp-server-openapi.yaml
    """
    assert COMMITTED_SPEC.exists(), (
        f"Committed spec missing: {COMMITTED_SPEC}. "
        "Run: python -m scripts.export_mcp_openapi --out "
        "../docs/mcp-server-openapi.yaml"
    )
    on_disk = yaml.safe_load(COMMITTED_SPEC.read_text(encoding="utf-8"))
    generated = _build_spec()
    assert on_disk == generated, (
        "Drift detected between docs/mcp-server-openapi.yaml and src/mcp. "
        "Regenerate via: python -m scripts.export_mcp_openapi --out "
        "../docs/mcp-server-openapi.yaml"
    )


def test_spec_declares_openapi_3_1_metadata() -> None:
    spec = _build_spec()
    assert spec["openapi"] == OPENAPI_VERSION
    info = spec["info"]
    assert "title" in info and info["title"]
    assert "version" in info and info["version"]
    components = spec.get("components", {})
    assert "schemas" in components, "Expected components.schemas in spec"
    assert components["schemas"], "components.schemas should be non-empty"
    sec_schemes = components.get("securitySchemes", {})
    assert "bearer" in sec_schemes and "apiKey" in sec_schemes


def test_spec_paths_cover_all_runtime_entities() -> None:
    """Every registered tool / resource / template / prompt has a path."""
    tools, resources, templates, prompts = _list_runtime()
    spec = _build_spec()
    paths = spec["paths"]

    for name in tools:
        path = f"/rpc/{name}"
        assert path in paths, f"Tool '{name}' missing OpenAPI path {path}"
        assert "post" in paths[path], f"Tool '{name}' must be POST"

    for uri in resources:
        path = uri.replace("argus://", "/resources/")
        if not path.startswith("/resources/"):
            path = "/resources/" + path.lstrip("/")
        assert path in paths, f"Resource {uri} missing OpenAPI path {path}"
        assert "get" in paths[path], f"Resource {uri} must be GET"

    for uri in templates:
        path = uri.replace("argus://", "/resources/")
        assert path in paths, f"Resource template {uri} missing OpenAPI path {path}"
        assert "get" in paths[path], f"Resource template {uri} must be GET"
        assert "parameters" in paths[path]["get"], (
            f"Resource template {uri} must declare path parameters"
        )

    for name in prompts:
        path = f"/prompts/{name}"
        assert path in paths, f"Prompt '{name}' missing OpenAPI path {path}"
        assert "post" in paths[path], f"Prompt '{name}' must be POST"


def test_every_ref_resolves_into_components_schemas() -> None:
    """All ``$ref`` pointers must target ``#/components/schemas/*``.

    This guards against two kinds of regression:
      * Dangling ref — schema name not registered globally.
      * Leaked ``#/$defs/*`` ref — emitter forgot to rewrite a Pydantic
        local definition pointer.
    """
    spec = _build_spec()
    refs: set[str] = set()
    _collect_refs(spec, refs)

    schemas = spec["components"]["schemas"]
    leaked_local = sorted(r for r in refs if r.startswith(LOCAL_DEFS_PREFIX))
    assert not leaked_local, (
        f"Leaked Pydantic local refs (should have been rewritten): {leaked_local}"
    )

    dangling: list[str] = []
    for ref in sorted(refs):
        assert ref.startswith(GLOBAL_DEFS_PREFIX), (
            f"Unexpected ref scheme (only {GLOBAL_DEFS_PREFIX}* allowed): {ref}"
        )
        name = ref[len(GLOBAL_DEFS_PREFIX) :]
        if name not in schemas:
            dangling.append(ref)
    assert not dangling, f"Dangling refs (not in components.schemas): {dangling}"


def test_tool_operations_have_request_response_bodies() -> None:
    """Every POST /rpc/* operation must define request + response payloads."""
    spec = _build_spec()
    rpc_paths = {p: ops for p, ops in spec["paths"].items() if p.startswith("/rpc/")}
    assert rpc_paths, "No /rpc/* paths found — tool surface is empty"
    for path, operations in rpc_paths.items():
        op = operations["post"]
        assert "operationId" in op, f"{path}: missing operationId"
        assert op["operationId"].startswith("call_"), (
            f"{path}: operationId must start with 'call_': {op['operationId']!r}"
        )
        request = op["requestBody"]["content"]["application/json"]["schema"]
        assert "$ref" in request, f"{path}: requestBody must reference a schema"
        assert "200" in op["responses"], f"{path}: missing 200 response"
        assert "401" in op["responses"], f"{path}: missing 401 response"


def test_prompt_operations_have_synthetic_argument_schemas() -> None:
    """Each /prompts/* path body must reference a generated arguments schema."""
    spec = _build_spec()
    prompt_paths = {
        p: ops for p, ops in spec["paths"].items() if p.startswith("/prompts/")
    }
    assert prompt_paths, "No /prompts/* paths found — prompt surface is empty"
    schemas = spec["components"]["schemas"]
    for path, operations in prompt_paths.items():
        op = operations["post"]
        body = op["requestBody"]["content"]["application/json"]["schema"]
        assert "$ref" in body, f"{path}: prompt body must reference a schema"
        ref_name = body["$ref"].split("/")[-1]
        assert ref_name.endswith("PromptArguments"), (
            f"{path}: expected synthetic *PromptArguments schema, got {ref_name!r}"
        )
        assert ref_name in schemas, f"{path}: ref {ref_name} not in components.schemas"
