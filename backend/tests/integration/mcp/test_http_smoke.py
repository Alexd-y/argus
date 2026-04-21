"""End-to-end streamable-HTTP smoke tests for the ARGUS MCP server.

These tests boot the real ``python -m src.mcp.server`` process bound to a
random localhost port and drive it with the official MCP Python client
over the ``streamable-http`` transport. They cover the JSON-RPC contract
that production deployments (behind an OAuth proxy, ingress controller,
or an OpenAI Responses client) will see:

* ``initialize`` returns the server name + protocol metadata.
* ``tools/list`` returns the §13 contract (15 tools, no extras).
* ``resources/list`` and ``resources/templates/list`` cover the four §13
  resource URIs.
* ``prompts/list`` returns the three §13 prompts.
* ``policy.evaluate`` round-trips a structured response.
* ``scope.verify`` falls back to the deny verdict when no scope is loaded.
* ``report.generate`` rejects malformed payloads with ``isError=True``.
* Reading ``argus://catalog/tools`` returns a JSON body.
* Calling an unknown tool surfaces a tool-level error without breaking
  the JSON-RPC session.

Like the stdio suite we use a context-manager helper instead of an async
fixture: anyio's :class:`anyio.CancelScope` insists that the TaskGroup
created by :func:`mcp.client.streamable_http.streamable_http_client` is
exited on the same task that entered it, and pytest-asyncio's fixture
lifecycle violates that invariant on Windows.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, closing

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


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


def _server_env(port: int) -> dict[str, str]:
    """Environment forwarded into the spawned MCP server.

    Pin every value the production ``Settings`` validators look at so
    the spawned process never tries to talk to a real Postgres / Redis /
    JWT issuer.
    """
    return {
        **os.environ,
        "DEBUG": "true",
        "DATABASE_URL": (
            "postgresql+asyncpg://argus:argus@localhost:5432/argus_int_test"
        ),
        "JWT_SECRET": "test-secret-not-for-prod-but-required-by-settings",
        "MCP_TRANSPORT": "streamable-http",
        "MCP_HTTP_HOST": "127.0.0.1",
        "MCP_HTTP_PORT": str(port),
        "MCP_REQUIRE_AUTH": "false",
        "MCP_AUTH_TOKEN": "test-bearer-token",
        "ARGUS_TEST_MODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUNBUFFERED": "1",
    }


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return int(s.getsockname()[1])


async def _wait_until_listening(url: str, *, timeout_s: float = 30.0) -> None:
    """Poll the MCP endpoint until it accepts connections or we time out.

    The streamable-HTTP endpoint replies with ``406 Not Acceptable`` to a
    bare ``GET`` because it expects MCP framing — that's a perfectly
    valid signal that the process is up. Anything that we can connect to
    counts; we just want to avoid racing the subprocess.
    """
    deadline = asyncio.get_event_loop().time() + timeout_s
    last_exc: Exception | None = None
    async with httpx.AsyncClient() as client:
        while asyncio.get_event_loop().time() < deadline:
            try:
                resp = await client.get(url, timeout=1.0)
                # Anything from the server (200/404/405/406/...) means
                # the listener is accepting traffic.
                _ = resp.status_code
                return
            except httpx.HTTPError as exc:
                last_exc = exc
                await asyncio.sleep(0.2)
    raise RuntimeError(f"MCP HTTP server never came up at {url}: {last_exc!r}")


@asynccontextmanager
async def _mcp_http_server() -> AsyncIterator[str]:
    """Boot the MCP server in streamable-http mode and yield its URL."""
    port = _free_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "src.mcp.server",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=_REPO_BACKEND_DIR,
        env=_server_env(port),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    url = f"http://127.0.0.1:{port}/mcp"
    try:
        await _wait_until_listening(url)
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


@asynccontextmanager
async def _open_session() -> AsyncIterator[
    tuple[ClientSession, "InitializeResultLike"]
]:
    """Boot the MCP server (HTTP) and yield an initialised session."""
    async with _mcp_http_server() as url:
        async with streamable_http_client(url) as (read, write, _get_session_id):
            async with ClientSession(read, write) as client:
                init_result = await client.initialize()
                yield client, init_result


# Type alias used only for readability above; the concrete type comes
# from ``mcp.types.InitializeResult``.
InitializeResultLike = object


pytestmark = [pytest.mark.asyncio, pytest.mark.integration]


class TestHttpInitialize:
    async def test_initialize_returns_server_name(self) -> None:
        async with _open_session() as (_, init_result):
            info = init_result.serverInfo  # type: ignore[attr-defined]
            assert info.name == "argus"


class TestHttpToolsList:
    async def test_returns_full_section_13_contract(self) -> None:
        async with _open_session() as (session, _):
            listed = await session.list_tools()
            names = {t.name for t in listed.tools}
            assert _EXPECTED_TOOLS - names == set()
            assert names - _EXPECTED_TOOLS == set()

    async def test_each_tool_has_input_schema(self) -> None:
        async with _open_session() as (session, _):
            listed = await session.list_tools()
            for tool in listed.tools:
                assert tool.inputSchema, f"tool {tool.name!r} missing inputSchema"
                assert tool.inputSchema.get("type") == "object"


class TestHttpResources:
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


class TestHttpPrompts:
    async def test_lists_section_13_prompts(self) -> None:
        async with _open_session() as (session, _):
            listed = await session.list_prompts()
            names = {p.name for p in listed.prompts}
            assert _EXPECTED_PROMPTS - names == set()


class TestHttpPolicyRoundTrip:
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


class TestHttpScopeRoundTrip:
    async def test_scope_verify_with_empty_factory_returns_denied(self) -> None:
        async with _open_session() as (session, _):
            result = await session.call_tool(
                "scope.verify",
                {"payload": {"target": "https://example.com"}},
            )
            assert result.isError is False
            assert result.structuredContent is not None
            assert result.structuredContent["allowed"] is False


class TestHttpReportGenerateValidation:
    async def test_short_scan_id_is_rejected_by_schema(self) -> None:
        async with _open_session() as (session, _):
            result = await session.call_tool(
                "report.generate",
                {"payload": {"scan_id": "abc"}},
            )
            assert result.isError is True


class TestHttpCatalogResource:
    async def test_catalog_resource_returns_text_payload(self) -> None:
        async with _open_session() as (session, _):
            contents = await session.read_resource("argus://catalog/tools")
            assert contents.contents
            text = contents.contents[0].text  # type: ignore[union-attr]
            assert text.startswith("{")
            assert '"items"' in text


class TestHttpUnknownTool:
    async def test_unknown_tool_name_returns_isError(self) -> None:
        async with _open_session() as (session, _):
            result = await session.call_tool(f"unknown.tool.{uuid.uuid4().hex[:8]}", {})
            assert result.isError is True
            # Connection must remain alive afterwards.
            listed = await session.list_tools()
            assert listed.tools
