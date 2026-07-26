"""Tests for MCP tool-service layer — ``list_catalog``, ``trigger_tool_run``,
``get_tool_run_status``, and registry singleton lifecycle.

All tests are offline — the tool registry is injected via
:func:`reset_registry_for_tests`, and DB / Celery callbacks are mocked.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest

# Skip entire module if MCP service layer cannot be imported (heavy deps)
pytest.importorskip("src.mcp.services.tool_service", reason="MCP tool_service requires full runtime stack")

from src.mcp.exceptions import (
    ApprovalRequiredError,
    MCPError,
    ResourceNotFoundError,
    UpstreamServiceError,
    ValidationError,
    is_known_error_code,
)
from src.mcp.schemas.tool_run import (
    ToolRiskLevel,
    ToolRunStatus,
    ToolRunTriggerInput,
)
from src.mcp.services.tool_service import (
    get_registry,
    get_tool_run_status,
    list_catalog,
    reset_registry_for_tests,
    trigger_tool_run,
)
from src.sandbox.adapter_base import (
    NetworkPolicyRef,
    ParseStrategy,
    RiskLevel,
    ToolCategory,
    ToolDescriptor,
)
from src.orchestration.state_machine import ScanPhase as ToolPhase


# ---------------------------------------------------------------------------
# Helpers — build synthetic ToolRegistry with known descriptors
# ---------------------------------------------------------------------------


def _make_descriptor(
    tool_id: str,
    category: ToolCategory = ToolCategory.RECON,
    phase: ToolPhase = ToolPhase.RECON,
    risk_level: RiskLevel = RiskLevel.LOW,
    requires_approval: bool = False,
    cwe_hints: tuple[int, ...] = (),
) -> ToolDescriptor:
    return ToolDescriptor(
        tool_id=tool_id,
        category=category,
        phase=phase,
        risk_level=risk_level,
        requires_approval=requires_approval,
        network_policy=NetworkPolicyRef(name="recon"),
        seccomp_profile="default.json",
        default_timeout_s=60,
        cpu_limit="500m",
        memory_limit="256Mi",
        image="argus/sandbox:test",
        command_template=["echo", "test"],
        parse_strategy=ParseStrategy.TEXT_LINES,
        description=f"Tool {tool_id} — for testing",
        cwe_hints=cwe_hints,
    )


def _fake_registry(descriptors: list[ToolDescriptor]) -> MagicMock:
    registry = MagicMock()
    registry.all_descriptors.return_value = descriptors
    registry.get.side_effect = lambda tid: next(
        (d for d in descriptors if d.tool_id == tid), None
    )
    return registry


# ---------------------------------------------------------------------------
# Singleton lifecycle
# ---------------------------------------------------------------------------


class TestRegistrySingleton:
    """``get_registry()`` and ``reset_registry_for_tests()``."""

    def teardown_method(self) -> None:
        reset_registry_for_tests(None)

    def test_reset_clears_injected_registry(self) -> None:
        fake = _fake_registry([])
        reset_registry_for_tests(fake)
        assert get_registry() is fake
        reset_registry_for_tests(None)
        assert get_registry() is not fake


# ---------------------------------------------------------------------------
# list_catalog
# ---------------------------------------------------------------------------


class TestListCatalog:
    """Catalog listing with filters and pagination."""

    _DESCRIPTORS = [
        _make_descriptor("nmap", category=ToolCategory.RECON, risk_level=RiskLevel.LOW),
        _make_descriptor("nuclei", category=ToolCategory.WEB_VA, risk_level=RiskLevel.MEDIUM),
        _make_descriptor("sqlmap", category=ToolCategory.WEB_VA, risk_level=RiskLevel.HIGH, requires_approval=True),
        _make_descriptor("ffuf", category=ToolCategory.RECON, risk_level=RiskLevel.LOW),
    ]

    def setup_method(self) -> None:
        reset_registry_for_tests(_fake_registry(list(self._DESCRIPTORS)))

    def teardown_method(self) -> None:
        reset_registry_for_tests(None)

    def test_list_all_returns_all_items(self) -> None:
        result = list_catalog()
        assert result.total == 4
        assert len(result.items) == 4

    def test_filter_by_category(self) -> None:
        result = list_catalog(category="web_va")
        assert result.total == 2
        tool_ids = {e.tool_id for e in result.items}
        assert tool_ids == {"nuclei", "sqlmap"}

    def test_filter_by_risk_level(self) -> None:
        result = list_catalog(risk_level=ToolRiskLevel.LOW)
        assert result.total == 2
        tool_ids = {e.tool_id for e in result.items}
        assert tool_ids == {"nmap", "ffuf"}

    def test_filter_by_requires_approval(self) -> None:
        result = list_catalog(requires_approval=True)
        assert result.total == 1
        assert result.items[0].tool_id == "sqlmap"
        assert result.items[0].requires_approval is True

    def test_pagination_offset(self) -> None:
        result = list_catalog(limit=2, offset=2)
        assert len(result.items) <= 2
        assert result.total == 4

    def test_cwe_hints_included(self) -> None:
        custom = _make_descriptor(
            "custom", cwe_hints=(79, 89), risk_level=RiskLevel.MEDIUM,
            category=ToolCategory.WEB_VA,
        )
        reset_registry_for_tests(_fake_registry([custom]))
        result = list_catalog()
        assert result.items[0].cwe_hints == (79, 89)

    def test_category_filter_is_case_insensitive(self) -> None:
        result = list_catalog(category="WEB_VA")
        assert result.total == 2


# ---------------------------------------------------------------------------
# trigger_tool_run
# ---------------------------------------------------------------------------


class TestTriggerToolRun:
    """Policy decision for tool-run triggers."""

    _LOW_TOOL = _make_descriptor("nmap", risk_level=RiskLevel.LOW)
    _HIGH_TOOL = _make_descriptor(
        "sqlmap", risk_level=RiskLevel.HIGH, requires_approval=True,
        category=ToolCategory.WEB_VA,
    )
    _DESTRUCTIVE_TOOL = _make_descriptor(
        "hydra", risk_level=RiskLevel.DESTRUCTIVE,
        category=ToolCategory.AUTH,
    )

    def setup_method(self) -> None:
        reset_registry_for_tests(
            _fake_registry([self._LOW_TOOL, self._HIGH_TOOL, self._DESTRUCTIVE_TOOL])
        )

    def teardown_method(self) -> None:
        reset_registry_for_tests(None)

    def test_low_risk_tool_queued_without_approval(self) -> None:
        payload = ToolRunTriggerInput(tool_id="nmap", target="example.com")
        result = trigger_tool_run(
            payload=payload, actor="test-user", tenant_id="t1"
        )
        assert result.status == ToolRunStatus.QUEUED
        assert result.requires_approval is False
        assert result.tool_run_id is not None

    def test_high_risk_tool_requires_justification(self) -> None:
        payload = ToolRunTriggerInput(
            tool_id="sqlmap", target="example.com", justification=""
        )
        with pytest.raises(ApprovalRequiredError, match="justification"):
            trigger_tool_run(payload=payload, actor="u1", tenant_id="t1")

    def test_high_risk_tool_with_long_justification_returns_pending(self) -> None:
        payload = ToolRunTriggerInput(
            tool_id="sqlmap",
            target="example.com",
            justification="We need to verify SQL injection on the login form",
        )
        result = trigger_tool_run(
            payload=payload, actor="u1", tenant_id="t1"
        )
        assert result.status == ToolRunStatus.APPROVAL_PENDING
        assert result.requires_approval is True
        assert result.approval_request_id is not None

    def test_destructive_always_requires_approval(self) -> None:
        payload = ToolRunTriggerInput(
            tool_id="hydra",
            target="example.com",
            justification="Brute-force check of weak admin credentials per scope",
        )
        result = trigger_tool_run(
            payload=payload, actor="u1", tenant_id="t1"
        )
        assert result.status == ToolRunStatus.APPROVAL_PENDING

    def test_unknown_tool_raises_not_found(self) -> None:
        payload = ToolRunTriggerInput(tool_id="nonexistent", target="example.com")
        with pytest.raises(ResourceNotFoundError, match="not registered"):
            trigger_tool_run(payload=payload, actor="u1", tenant_id="t1")

    def test_approval_factory_is_called(self) -> None:
        approval_calls: list[str] = []

        def approval_factory(desc, actor):
            rid = f"req-{uuid.uuid4().hex[:8]}"
            approval_calls.append(rid)
            return rid

        payload = ToolRunTriggerInput(
            tool_id="sqlmap",
            target="example.com",
            justification="Testing approval factory integration for sqlmap scan",
        )
        result = trigger_tool_run(
            payload=payload,
            actor="u1",
            tenant_id="t1",
            approval_factory=approval_factory,
        )
        assert len(approval_calls) == 1
        assert result.approval_request_id == approval_calls[0]

    def test_justification_exactly_ten_characters_accepts(self) -> None:
        payload = ToolRunTriggerInput(
            tool_id="sqlmap",
            target="example.com",
            justification="A" * 10,
        )
        result = trigger_tool_run(payload=payload, actor="u", tenant_id="t")
        assert result.status == ToolRunStatus.APPROVAL_PENDING


# ---------------------------------------------------------------------------
# get_tool_run_status
# ---------------------------------------------------------------------------


class TestGetToolRunStatus:
    """Tool run status lookup with fallback patterns."""

    def test_missing_tool_run_id_raises(self) -> None:
        with pytest.raises(ValidationError, match="tool_run_id"):
            get_tool_run_status(tenant_id="t1", tool_run_id="")

    def test_no_lookup_raises_not_found(self) -> None:
        with pytest.raises(ResourceNotFoundError, match="not visible"):
            get_tool_run_status(tenant_id="t1", tool_run_id="run-123")

    def test_lookup_returns_result(self) -> None:
        from src.mcp.schemas.tool_run import ToolRunStatusResult

        expected = ToolRunStatusResult(
            tool_run_id="run-abc1",
            tool_id="nmap",
            status=ToolRunStatus.COMPLETED,
            finding_count=3,
        )

        def lookup(_tenant: str, _run_id: str):
            return expected

        result = get_tool_run_status(
            tenant_id="t1", tool_run_id="run-abc1", lookup=lookup
        )
        assert result is expected
        assert result.tool_run_id == "run-abc1"
        assert result.status == ToolRunStatus.COMPLETED
        assert result.finding_count == 3

    def test_lookup_returns_none_raises_not_found(self) -> None:
        def lookup(_tenant: str, _run_id: str):
            return None

        with pytest.raises(ResourceNotFoundError, match="was not found"):
            get_tool_run_status(
                tenant_id="t1", tool_run_id="run-xyz", lookup=lookup
            )


# ---------------------------------------------------------------------------
# MCP exception taxonomy
# ---------------------------------------------------------------------------


class TestMCPExceptionTaxonomy:
    """Closed-taxonomy errors are serialisable and carry correct codes."""

    def test_each_error_has_unique_code(self) -> None:
        from src.mcp.exceptions import _ALL_ERROR_CODES

        assert len(_ALL_ERROR_CODES) >= 10
        assert "mcp_auth_unauthenticated" in _ALL_ERROR_CODES
        assert "mcp_resource_not_found" in _ALL_ERROR_CODES

    def test_exception_str_includes_code(self) -> None:
        err = ResourceNotFoundError("Missing scan ABC")
        assert "mcp_resource_not_found" in str(err)
        assert "Missing scan ABC" in str(err)

    def test_is_known_error_code(self) -> None:
        assert is_known_error_code("mcp_auth_forbidden") is True
        assert is_known_error_code("mcp_made_up_error") is False

    def test_message_does_not_leak_custom_code_as_attribute(self) -> None:
        err = MCPError("Something went wrong", code="my_custom_label")
        assert err.code == "my_custom_label"
        assert "my_custom_label" not in err.message
