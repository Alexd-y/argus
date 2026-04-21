"""End-to-end stdio smoke tests for the ARGUS MCP server (Backlog/dev1_md §13).

These tests boot the real ``python -m src.mcp.server`` process over stdio
and drive it with the official MCP Python client. They assert the
JSON-RPC contract that LLM clients (Cursor / Claude Desktop / etc.) will
actually see:

* ``initialize`` returns the server name + protocol metadata.
* ``tools/list`` returns the §13 contract (15 tools, no extras).
* ``resources/list`` and ``resources/templates/list`` cover the four §13
  resource URIs.
* ``prompts/list`` returns the three §13 prompts.
* Each tool advertises a JSON Schema for its input model.
* Calling ``policy.evaluate`` round-trips a structured response without
  crashing the server (proves the runtime + audit logger are wired up).
* ``scope.verify`` falls back to a deny verdict when no scope is loaded.
* ``report.generate`` rejects malformed payloads via Pydantic instead of
  crashing the connection.
* ``argus://catalog/tools`` and ``argus://approvals/pending`` resources
  return well-formed JSON bodies.
* Calling an unknown tool surfaces a tool-level error without tearing
  down the JSON-RPC session.

The subprocess inherits a deterministic environment so neither the
default Settings validators nor the audit logger try to talk to a real
DB / Redis. We use a context-manager helper rather than a yielding
``async`` fixture: anyio's :class:`anyio.CancelScope` insists that the
TaskGroup created by :func:`mcp.client.stdio.stdio_client` is exited on
the same task that entered it, and pytest-asyncio's fixture lifecycle
violates that invariant on Windows.
"""

from __future__ import annotations

import os
import sys
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


_REPO_BACKEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)


_EXPECTED_TOOLS: frozenset[str] = frozenset(
    {
        "scan.create",
        "scan.status",
        "scan.cancel",
        "findings.list",
        "findings.get",
        "findings.mark_false_positive",
        "approvals.list",
        "approvals.decide",
        "tool.catalog.list",
        "tool.run.trigger",
        "tool.run.status",
        "report.generate",
        "report.download",
        "scope.verify",
        "policy.evaluate",
    }
)

_EXPECTED_PROMPTS: frozenset[str] = frozenset(
    {
        "vulnerability.explainer",
        "remediation.advisor",
        "severity.normalizer",
    }
)


def _server_env() -> dict[str, str]:
    """Environment variables forwarded into the spawned MCP server.

    We pin every value the production ``Settings`` validators look at so
    the spawned process never tries to talk to a real Postgres / Redis /
    JWT issuer. The MCP server itself never opens those connections at
    boot — only on first tool invocation that touches the DB — but we
    still inject safe defaults so collection cannot accidentally regress.
    """
    return {
        **os.environ,
        "DEBUG": "true",
        "DATABASE_URL": (
            "postgresql+asyncpg://argus:argus@localhost:5432/argus_int_test"
        ),
        "JWT_SECRET": "test-secret-not-for-prod-but-required-by-settings",
        "MCP_TRANSPORT": "stdio",
        "MCP_REQUIRE_AUTH": "false",
        "MCP_AUTH_TOKEN": "test-bearer-token",
        "ARGUS_TEST_MODE": "1",
        # Ensure subprocess uses UTF-8 on Windows shells regardless of cp1251.
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUNBUFFERED": "1",
    }


def _server_params() -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "src.mcp.server", "--transport", "stdio"],
        cwd=_REPO_BACKEND_DIR,
        env=_server_env(),
    )


@asynccontextmanager
async def _open_session() -> AsyncIterator[
    tuple[ClientSession, "InitializeResultLike"]
]:
    """Spawn the MCP server in stdio mode and yield an initialised session.

    The InitializeResult is also yielded so callers do not need to reach
    into private session attributes to assert on server metadata.
    """
    async with stdio_client(_server_params()) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as client:
            init_result = await client.initialize()
            yield client, init_result


# Type alias used only for readability above; the concrete type comes from
# ``mcp.types.InitializeResult`` but importing the symbol just for an
# annotation in a smoke test is overkill.
InitializeResultLike = object


pytestmark = pytest.mark.asyncio


class TestStdioInitialize:
    async def test_initialize_returns_server_name(self) -> None:
        async with _open_session() as (_, init_result):
            info = init_result.serverInfo  # type: ignore[attr-defined]
            assert info.name == "argus"


class TestStdioToolsList:
    async def test_returns_full_section_13_contract(self) -> None:
        async with _open_session() as (session, _):
            listed = await session.list_tools()
            names = {t.name for t in listed.tools}
            missing = _EXPECTED_TOOLS - names
            assert not missing, f"missing MCP tools: {missing}"
            extras = names - _EXPECTED_TOOLS
            assert not extras, f"unexpected MCP tools registered: {extras}"

    async def test_each_tool_has_input_schema(self) -> None:
        async with _open_session() as (session, _):
            listed = await session.list_tools()
            for tool in listed.tools:
                assert tool.inputSchema, f"tool {tool.name!r} missing inputSchema"
                assert tool.inputSchema.get("type") == "object"


class TestStdioResources:
    async def test_lists_concrete_and_template_uris(self) -> None:
        async with _open_session() as (session, _):
            listed = await session.list_resources()
            templates = await session.list_resource_templates()
            all_uris = {str(r.uri) for r in listed.resources} | {
                t.uriTemplate for t in templates.resourceTemplates
            }
            assert any("argus://catalog/tools" in u for u in all_uris)
            assert any("argus://findings/" in u for u in all_uris)
            assert any("argus://reports/" in u for u in all_uris)
            assert any("argus://approvals/pending" in u for u in all_uris)


class TestStdioPrompts:
    async def test_lists_section_13_prompts(self) -> None:
        async with _open_session() as (session, _):
            listed = await session.list_prompts()
            names = {p.name for p in listed.prompts}
            missing = _EXPECTED_PROMPTS - names
            assert not missing, f"missing MCP prompts: {missing}"


class TestStdioPolicyRoundTrip:
    async def test_policy_evaluate_returns_structured_response(self) -> None:
        async with _open_session() as (session, _):
            result = await session.call_tool(
                "policy.evaluate",
                {
                    "payload": {
                        "tool_id": "subfinder",
                        "target": "https://example.com",
                        "risk_level": "passive",
                    }
                },
            )
            assert result.isError is False
            assert result.structuredContent is not None
            assert "outcome" in result.structuredContent
            assert result.structuredContent["risk_level"] == "passive"


class TestStdioScopeRoundTrip:
    async def test_scope_verify_with_empty_factory_returns_denied(self) -> None:
        # The default scope factory returns an empty ``ScopeEngine`` so any
        # target is denied; we just want to prove the JSON-RPC contract.
        async with _open_session() as (session, _):
            result = await session.call_tool(
                "scope.verify",
                {"payload": {"target": "https://example.com"}},
            )
            assert result.isError is False
            assert result.structuredContent is not None
            assert result.structuredContent["allowed"] is False


class TestStdioReportGenerateValidation:
    async def test_short_scan_id_is_rejected_by_schema(self) -> None:
        # Pydantic schema validation runs server-side; the call should fail
        # cleanly with isError=True rather than crash the connection.
        async with _open_session() as (session, _):
            result = await session.call_tool(
                "report.generate",
                {"payload": {"scan_id": "abc"}},
            )
            assert result.isError is True


class TestStdioCatalogResource:
    async def test_catalog_resource_returns_text_payload(self) -> None:
        # ``argus://catalog/tools`` is registered as a fixed-URI resource;
        # the body is a JSON document.
        async with _open_session() as (session, _):
            contents = await session.read_resource("argus://catalog/tools")
            assert contents.contents
            text = contents.contents[0].text  # type: ignore[union-attr]
            assert text.startswith("{")
            assert '"items"' in text


class TestStdioApprovalsResource:
    async def test_pending_approvals_resource_returns_well_formed_body(
        self,
    ) -> None:
        # No approvals have been seeded, so the response is the empty set
        # — but the JSON-RPC contract still works.
        async with _open_session() as (session, _):
            contents = await session.read_resource("argus://approvals/pending")
            assert contents.contents
            text = contents.contents[0].text  # type: ignore[union-attr]
            assert '"items"' in text


class TestStdioUnknownTool:
    async def test_unknown_tool_name_returns_isError(self) -> None:
        # FastMCP wraps the failure in a tool error response; the session
        # itself stays alive so the LLM can recover.
        async with _open_session() as (session, _):
            result = await session.call_tool(f"unknown.tool.{uuid.uuid4().hex[:8]}", {})
            assert result.isError is True
            # Make sure the connection is still alive afterwards.
            listed = await session.list_tools()
            assert listed.tools
