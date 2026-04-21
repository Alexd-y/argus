"""ARG-039 — every public MCP tool/resource/prompt must carry a meaningful description.

The MCP wire-protocol exposes ``description`` (not Python ``__doc__``) to
downstream LLM clients — that is the field that ends up in the OpenAPI
spec and the auto-generated TypeScript SDK. We therefore enforce a hard
floor of ``MIN_DESCRIPTION_CHARS`` (30) on the FastMCP-visible field for
all tools, resources, resource templates, and prompts.

Failure here means the corresponding ``@mcp.tool`` / ``@mcp.resource`` /
``@mcp.prompt`` registration silently shipped without enough context for
agents (and, by extension, for the SDK consumers reading
``operationId.description`` in the generated spec). Fix the description
inline in the tool/resource/prompt module — do **not** suppress this
gate.
"""

from __future__ import annotations

import asyncio
from typing import Final

import pytest
from mcp.types import Prompt, Resource, ResourceTemplate, Tool

from src.mcp.server import build_app

MIN_DESCRIPTION_CHARS: Final[int] = 30


def _collect_surface() -> tuple[
    list[Tool], list[Resource], list[ResourceTemplate], list[Prompt]
]:
    """Build the FastMCP app once and return its complete capability surface.

    Building the app touches the importable code path of every MCP
    tool / resource / prompt module — that import alone is the
    registration trigger.
    """
    app = build_app(name="argus-docstring-gate", log_level="WARNING")

    async def _gather() -> tuple[
        list[Tool], list[Resource], list[ResourceTemplate], list[Prompt]
    ]:
        return (
            await app.list_tools(),
            await app.list_resources(),
            await app.list_resource_templates(),
            await app.list_prompts(),
        )

    return asyncio.run(_gather())


# Collected once at import time so pytest can render meaningful node IDs
# (e.g. ``test_mcp_tool_has_description[scan.create]``). ``build_app`` is
# pure sync registration with no I/O, so this is cheap.
_TOOLS, _RESOURCES, _TEMPLATES, _PROMPTS = _collect_surface()


@pytest.mark.parametrize("tool", _TOOLS, ids=[t.name for t in _TOOLS])
def test_mcp_tool_has_description(tool: Tool) -> None:
    """Tool descriptions are surfaced verbatim to LLM clients and the SDK."""
    description = (tool.description or "").strip()
    assert description, f"MCP tool '{tool.name}' is missing a description"
    assert len(description) >= MIN_DESCRIPTION_CHARS, (
        f"MCP tool '{tool.name}' description too short "
        f"({len(description)} < {MIN_DESCRIPTION_CHARS} chars): {description!r}"
    )


@pytest.mark.parametrize("resource", _RESOURCES, ids=[r.name for r in _RESOURCES])
def test_mcp_resource_has_description(resource: Resource) -> None:
    description = (resource.description or "").strip()
    assert description, (
        f"MCP resource '{resource.name}' ({resource.uri}) is missing a description"
    )
    assert len(description) >= MIN_DESCRIPTION_CHARS, (
        f"MCP resource '{resource.name}' description too short "
        f"({len(description)} < {MIN_DESCRIPTION_CHARS} chars): {description!r}"
    )


@pytest.mark.parametrize("template", _TEMPLATES, ids=[t.name for t in _TEMPLATES])
def test_mcp_resource_template_has_description(template: ResourceTemplate) -> None:
    description = (template.description or "").strip()
    assert description, (
        f"MCP resource template '{template.name}' ({template.uriTemplate}) "
        "is missing a description"
    )
    assert len(description) >= MIN_DESCRIPTION_CHARS, (
        f"MCP resource template '{template.name}' description too short "
        f"({len(description)} < {MIN_DESCRIPTION_CHARS} chars): {description!r}"
    )


@pytest.mark.parametrize("prompt", _PROMPTS, ids=[p.name for p in _PROMPTS])
def test_mcp_prompt_has_description(prompt: Prompt) -> None:
    description = (prompt.description or "").strip()
    assert description, f"MCP prompt '{prompt.name}' is missing a description"
    assert len(description) >= MIN_DESCRIPTION_CHARS, (
        f"MCP prompt '{prompt.name}' description too short "
        f"({len(description)} < {MIN_DESCRIPTION_CHARS} chars): {description!r}"
    )


def test_mcp_surface_is_non_empty() -> None:
    """Sanity check: at least one tool/resource/prompt is registered.

    Guards against accidental no-op registrations (empty surface would
    silently pass every parameterised case above).
    """
    assert _TOOLS, "no MCP tools registered — surface is empty"
    assert _RESOURCES, "no MCP resources registered — surface is empty"
    assert _PROMPTS, "no MCP prompts registered — surface is empty"
