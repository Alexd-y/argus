"""Unit tests for :mod:`src.mcp.server`.

Asserts that:

* :func:`build_app` registers the full §13 capability set without raising
  (15 tools, 4 resources, 3 prompts).
* All tool names match the Backlog/dev1_md §13 contract exactly.
* All registered Pydantic schemas are introspectable (FastMCP's tool manager
  generates a JSON schema for every input model).
* The CLI entrypoint refuses unknown transports / out-of-range ports without
  raising a Python traceback to the user.
"""

from __future__ import annotations

import asyncio

import pytest

from src.mcp.server import _parse_port, _resolve_transport, build_app


_EXPECTED_TOOLS = {
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

_EXPECTED_PROMPTS = {
    "vulnerability.explainer",
    "remediation.advisor",
    "severity.normalizer",
}


class TestBuildApp:
    def test_app_constructs_without_errors(self) -> None:
        app = build_app(name="argus-test")
        assert app.name == "argus-test"

    def test_all_15_tools_registered(self) -> None:
        app = build_app(name="argus-test")
        tools = asyncio.run(app.list_tools())
        names = {t.name for t in tools}
        missing = _EXPECTED_TOOLS - names
        assert not missing, f"Missing tools: {missing}"
        # Allow no extras outside the §13 contract
        extras = names - _EXPECTED_TOOLS
        assert not extras, f"Unexpected tools registered: {extras}"

    def test_all_3_prompts_registered(self) -> None:
        app = build_app(name="argus-test")
        prompts = asyncio.run(app.list_prompts())
        names = {p.name for p in prompts}
        missing = _EXPECTED_PROMPTS - names
        assert not missing, f"Missing prompts: {missing}"

    def test_resources_registered(self) -> None:
        app = build_app(name="argus-test")
        resources = asyncio.run(app.list_resources())
        templates = asyncio.run(app.list_resource_templates())
        # tools_catalog is a fixed URI; findings/reports use templates.
        all_uris = {str(r.uri) for r in resources} | {t.uriTemplate for t in templates}
        # At least the 4 §13 resources are present
        assert any("argus://catalog/tools" in u for u in all_uris)
        assert any("argus://findings/" in u for u in all_uris)
        assert any("argus://reports/" in u for u in all_uris)
        assert any("argus://approvals/pending" in u for u in all_uris)

    def test_tools_have_input_schemas(self) -> None:
        app = build_app(name="argus-test")
        tools = asyncio.run(app.list_tools())
        for tool in tools:
            assert tool.inputSchema, f"tool {tool.name!r} missing input schema"
            assert isinstance(tool.inputSchema, dict)
            assert tool.inputSchema.get("type") == "object"


class TestResolveTransport:
    @pytest.mark.parametrize("value", ["stdio", "STDIO", "sse", "streamable-http"])
    def test_known_transports(self, value: str) -> None:
        assert _resolve_transport(value) == value.lower()

    def test_default_to_settings(self) -> None:
        assert _resolve_transport(None) in {"stdio", "sse", "streamable-http"}

    def test_unknown_transport_raises_systemexit(self) -> None:
        with pytest.raises(SystemExit, match="unsupported MCP transport"):
            _resolve_transport("websocket")


class TestParsePort:
    @pytest.mark.parametrize("value", [1, 80, 8080, 65_535])
    def test_valid_ports(self, value: int) -> None:
        assert _parse_port(value, default=999) == value

    def test_none_returns_default(self) -> None:
        assert _parse_port(None, default=8765) == 8765

    def test_empty_string_returns_default(self) -> None:
        assert _parse_port("", default=8765) == 8765

    @pytest.mark.parametrize("value", [0, -1, 65_536, 100_000])
    def test_out_of_range_raises(self, value: int) -> None:
        with pytest.raises(SystemExit, match="out of range"):
            _parse_port(value, default=8765)

    def test_non_numeric_raises(self) -> None:
        with pytest.raises(SystemExit, match="invalid port value"):
            _parse_port("abc", default=8765)
