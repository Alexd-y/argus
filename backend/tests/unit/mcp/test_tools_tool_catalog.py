"""Unit tests for MCP ``tool.catalog.*`` and ``tool.run.*`` tools (Backlog §13).

The tool service uses a *singleton* ``ToolRegistry`` loaded from
``backend/config/tools/*.yaml``.  Loading those YAMLs requires Ed25519
signature verification + filesystem access, which is the wrong scope for a
unit test, so we install an in-memory fake registry via
``reset_registry_for_tests`` for every test in this module.

These tests assert:

* ``tool.catalog.list`` filters and paginates correctly.
* ``tool.run.trigger`` enforces the justification rule for HIGH /
  DESTRUCTIVE tools and routes them to ``approval_pending``.
* ``tool.run.trigger`` returns ``queued`` for low-risk tools and never
  spawns a subprocess.
* ``tool.run.status`` raises :class:`ResourceNotFoundError` when no
  lookup callback is wired up (the in-process fallback).

The tests bypass FastMCP's ``ToolError`` wrapping by invoking the
registered tool's underlying coroutine directly so the closed-taxonomy
:class:`MCPError` instances propagate as-is.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest
from mcp.server.fastmcp import FastMCP

from src.mcp.audit_logger import MCPAuditLogger
from src.mcp.auth import MCPAuthContext
from src.mcp.context import set_audit_logger, set_auth_override
from src.mcp.exceptions import (
    ApprovalRequiredError,
    ResourceNotFoundError,
)
from src.mcp.schemas.common import PaginationInput
from src.mcp.schemas.tool_run import (
    ToolCatalogListInput,
    ToolCatalogListResult,
    ToolRiskLevel,
    ToolRunStatus,
    ToolRunStatusInput,
    ToolRunTriggerInput,
    ToolRunTriggerResult,
)
from src.mcp.services import tool_service
from src.mcp.tools import tool_catalog as tool_catalog_tools
from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel
from src.sandbox.adapter_base import (
    NetworkPolicyRef,
    ParseStrategy,
    ToolCategory,
    ToolDescriptor,
)


def _drain_events(audit_logger: MCPAuditLogger) -> list[object]:
    sink = audit_logger.audit_logger.sink
    events: list[object] = []
    for tenant_events in sink._events.values():  # type: ignore[attr-defined]
        events.extend(tenant_events)
    events.sort(key=lambda e: e.occurred_at)  # type: ignore[attr-defined]
    return events


def _make_descriptor(
    *,
    tool_id: str,
    risk: RiskLevel = RiskLevel.PASSIVE,
    requires_approval: bool = False,
    category: ToolCategory = ToolCategory.RECON,
) -> ToolDescriptor:
    return ToolDescriptor(
        tool_id=tool_id,
        category=category,
        phase=ScanPhase.RECON,
        risk_level=risk,
        requires_approval=requires_approval,
        network_policy=NetworkPolicyRef(name="recon"),
        seccomp_profile="recon-default",
        default_timeout_s=60,
        cpu_limit="500m",
        memory_limit="256Mi",
        image="ghcr.io/argus/test-tool:latest",
        command_template=["echo", "{{ target }}"],
        parse_strategy=ParseStrategy.JSON_LINES,
    )


class _FakeRegistry:
    """Stand-in for :class:`ToolRegistry` that bypasses signature verification."""

    def __init__(self, descriptors: list[ToolDescriptor]) -> None:
        self._by_id = {d.tool_id: d for d in descriptors}

    def all_descriptors(self) -> list[ToolDescriptor]:
        return [self._by_id[tid] for tid in sorted(self._by_id)]

    def get(self, tool_id: str) -> ToolDescriptor | None:
        return self._by_id.get(tool_id)


@pytest.fixture()
def registry() -> Iterator[_FakeRegistry]:
    """Fresh fake registry per test, restored on teardown."""
    descriptors = [
        _make_descriptor(tool_id="subfinder", risk=RiskLevel.PASSIVE),
        _make_descriptor(
            tool_id="nuclei", risk=RiskLevel.MEDIUM, category=ToolCategory.WEB_VA
        ),
        _make_descriptor(
            tool_id="sqlmap",
            risk=RiskLevel.HIGH,
            requires_approval=True,
            category=ToolCategory.WEB_VA,
        ),
        _make_descriptor(
            tool_id="metasploit",
            risk=RiskLevel.DESTRUCTIVE,
            requires_approval=True,
            category=ToolCategory.WEB_VA,
        ),
    ]
    instance = _FakeRegistry(descriptors)
    tool_service.reset_registry_for_tests(instance)  # type: ignore[arg-type]
    try:
        yield instance
    finally:
        tool_service.reset_registry_for_tests(None)


@pytest.fixture()
def app(auth_ctx: MCPAuthContext, audit_logger: MCPAuditLogger) -> FastMCP:
    set_auth_override(auth_ctx)
    set_audit_logger(audit_logger)
    instance = FastMCP(name="argus-tools-test")
    tool_catalog_tools.register(instance)
    return instance


def _tool_fn(app: FastMCP, name: str):
    return app._tool_manager._tools[name].fn  # type: ignore[attr-defined]


def _call(app: FastMCP, name: str, payload: object) -> object:
    return asyncio.run(_tool_fn(app, name)(payload=payload))


class TestToolCatalogList:
    def test_returns_all_entries(
        self,
        app: FastMCP,
        registry: _FakeRegistry,
    ) -> None:
        result = _call(app, "tool.catalog.list", ToolCatalogListInput())
        assert isinstance(result, ToolCatalogListResult)
        assert result.total == 4
        ids = {item.tool_id for item in result.items}
        assert ids == {"subfinder", "nuclei", "sqlmap", "metasploit"}

    def test_filter_by_risk_level(
        self,
        app: FastMCP,
        registry: _FakeRegistry,
    ) -> None:
        result = _call(
            app,
            "tool.catalog.list",
            ToolCatalogListInput(risk_level=ToolRiskLevel.HIGH),
        )
        assert isinstance(result, ToolCatalogListResult)
        assert result.total == 1
        assert result.items[0].tool_id == "sqlmap"

    def test_filter_by_category(
        self,
        app: FastMCP,
        registry: _FakeRegistry,
    ) -> None:
        result = _call(
            app,
            "tool.catalog.list",
            ToolCatalogListInput(category="web_va"),
        )
        assert isinstance(result, ToolCatalogListResult)
        ids = {item.tool_id for item in result.items}
        assert ids == {"nuclei", "sqlmap", "metasploit"}

    def test_filter_by_requires_approval(
        self,
        app: FastMCP,
        registry: _FakeRegistry,
    ) -> None:
        result = _call(
            app,
            "tool.catalog.list",
            ToolCatalogListInput(requires_approval=True),
        )
        assert isinstance(result, ToolCatalogListResult)
        ids = {item.tool_id for item in result.items}
        assert ids == {"sqlmap", "metasploit"}

    def test_pagination_caps_results(
        self,
        app: FastMCP,
        registry: _FakeRegistry,
    ) -> None:
        result = _call(
            app,
            "tool.catalog.list",
            ToolCatalogListInput(pagination=PaginationInput(limit=2, offset=1)),
        )
        assert isinstance(result, ToolCatalogListResult)
        assert result.total == 4
        assert len(result.items) == 2

    def test_descriptor_internal_fields_are_stripped(
        self,
        app: FastMCP,
        registry: _FakeRegistry,
    ) -> None:
        # Catalog entries must not expose ``image`` / ``command_template``.
        result = _call(app, "tool.catalog.list", ToolCatalogListInput())
        assert isinstance(result, ToolCatalogListResult)
        for item in result.items:
            dumped = item.model_dump()
            assert "command_template" not in dumped
            assert "image" not in dumped


class TestToolRunTrigger:
    def test_low_risk_tool_returns_queued(
        self,
        app: FastMCP,
        registry: _FakeRegistry,
        audit_logger: MCPAuditLogger,
    ) -> None:
        result = _call(
            app,
            "tool.run.trigger",
            ToolRunTriggerInput(
                tool_id="subfinder",
                target="https://example.com",
            ),
        )
        assert isinstance(result, ToolRunTriggerResult)
        assert result.status is ToolRunStatus.QUEUED
        assert result.requires_approval is False
        assert result.tool_run_id is not None
        events = _drain_events(audit_logger)
        assert events[-1].payload["tool_id"] == "subfinder"  # type: ignore[attr-defined]
        assert events[-1].payload["target_redacted"] == "true"  # type: ignore[attr-defined]

    def test_high_risk_tool_requires_justification(
        self,
        app: FastMCP,
        registry: _FakeRegistry,
    ) -> None:
        with pytest.raises(ApprovalRequiredError):
            _call(
                app,
                "tool.run.trigger",
                ToolRunTriggerInput(
                    tool_id="sqlmap",
                    target="https://example.com",
                ),
            )

    def test_high_risk_tool_with_justification_pends_approval(
        self,
        app: FastMCP,
        registry: _FakeRegistry,
    ) -> None:
        result = _call(
            app,
            "tool.run.trigger",
            ToolRunTriggerInput(
                tool_id="sqlmap",
                target="https://example.com",
                justification=(
                    "Authorised pentest engagement against in-scope domain."
                ),
            ),
        )
        assert isinstance(result, ToolRunTriggerResult)
        assert result.status is ToolRunStatus.APPROVAL_PENDING
        assert result.requires_approval is True
        assert result.approval_request_id
        assert result.tool_run_id is None

    def test_destructive_tool_pends_approval(
        self,
        app: FastMCP,
        registry: _FakeRegistry,
    ) -> None:
        result = _call(
            app,
            "tool.run.trigger",
            ToolRunTriggerInput(
                tool_id="metasploit",
                target="https://example.com",
                justification=("Authorised destructive scan with operator sign-off."),
            ),
        )
        assert isinstance(result, ToolRunTriggerResult)
        assert result.status is ToolRunStatus.APPROVAL_PENDING

    def test_unknown_tool_returns_not_found(
        self,
        app: FastMCP,
        registry: _FakeRegistry,
    ) -> None:
        with pytest.raises(ResourceNotFoundError):
            _call(
                app,
                "tool.run.trigger",
                ToolRunTriggerInput(
                    tool_id="ghost-tool",
                    target="https://example.com",
                ),
            )


class TestMcpToolCatalogToolRunStatus:
    def test_default_lookup_returns_not_found(
        self,
        app: FastMCP,
        registry: _FakeRegistry,
    ) -> None:
        with pytest.raises(ResourceNotFoundError):
            _call(
                app,
                "tool.run.status",
                ToolRunStatusInput(tool_run_id="tr-12345678"),
            )

    def test_short_id_rejected_by_schema(self) -> None:
        # ``tool_run_id`` has min_length=8; Pydantic rejects shorter values.
        with pytest.raises(Exception):
            ToolRunStatusInput(tool_run_id="abc")
