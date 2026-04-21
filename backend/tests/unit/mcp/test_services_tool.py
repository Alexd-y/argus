"""Unit tests for :mod:`src.mcp.services.tool_service`.

Strategy:
* Build :class:`ToolDescriptor` instances by hand and inject them into a
  stub registry that exposes the subset of :class:`ToolRegistry` methods
  the service actually calls (``get``, ``all_descriptors``).
* Verify the catalog filters (category / risk_level /
  requires_approval), pagination, the high-risk approval gate, and the
  ``get_tool_run_status`` lookup contract.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from src.mcp.exceptions import (
    ApprovalRequiredError,
    ResourceNotFoundError,
    ValidationError,
)
from src.mcp.schemas.tool_run import (
    ToolRiskLevel,
    ToolRunStatus,
    ToolRunStatusResult,
    ToolRunTriggerInput,
)
from src.mcp.services import tool_service
from src.mcp.services.tool_service import (
    get_tool_run_status,
    list_catalog,
    reset_registry_for_tests,
    trigger_tool_run,
)
from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel
from src.sandbox.adapter_base import (
    NetworkPolicyRef,
    ParseStrategy,
    ToolCategory,
    ToolDescriptor,
)


# ---------------------------------------------------------------------------
# Fixture: hand-crafted descriptors + stub registry
# ---------------------------------------------------------------------------


def _make_descriptor(
    *,
    tool_id: str,
    risk: RiskLevel,
    requires_approval: bool = False,
    category: ToolCategory = ToolCategory.RECON,
    phase: ScanPhase = ScanPhase.RECON,
    description: str = "stub tool",
) -> ToolDescriptor:
    return ToolDescriptor(
        tool_id=tool_id,
        category=category,
        phase=phase,
        risk_level=risk,
        requires_approval=requires_approval,
        network_policy=NetworkPolicyRef(name="default"),
        seccomp_profile="default.json",
        default_timeout_s=60,
        cpu_limit="500m",
        memory_limit="256Mi",
        image="argus/example:1.0",
        command_template=["example", "{target.url}"],
        parse_strategy=ParseStrategy.JSON_LINES,
        description=description,
    )


class _StubRegistry:
    """Subset of :class:`ToolRegistry` used by ``tool_service``."""

    def __init__(self, descriptors: list[ToolDescriptor]) -> None:
        self._by_id = {d.tool_id: d for d in descriptors}

    def get(self, tool_id: str) -> ToolDescriptor | None:
        return self._by_id.get(tool_id)

    def all_descriptors(self) -> list[ToolDescriptor]:
        return [self._by_id[k] for k in sorted(self._by_id)]


@pytest.fixture()
def descriptors() -> list[ToolDescriptor]:
    return [
        _make_descriptor(tool_id="nmap", risk=RiskLevel.LOW),
        _make_descriptor(
            tool_id="nuclei",
            risk=RiskLevel.MEDIUM,
            category=ToolCategory.WEB_VA,
            phase=ScanPhase.VULN_ANALYSIS,
        ),
        _make_descriptor(
            tool_id="sqlmap",
            risk=RiskLevel.HIGH,
            requires_approval=True,
            category=ToolCategory.WEB_VA,
            phase=ScanPhase.EXPLOITATION,
        ),
        _make_descriptor(
            tool_id="metasploit",
            risk=RiskLevel.DESTRUCTIVE,
            requires_approval=True,
            category=ToolCategory.NETWORK,
            phase=ScanPhase.EXPLOITATION,
        ),
    ]


@pytest.fixture(autouse=True)
def stub_registry(descriptors: list[ToolDescriptor]) -> Iterator[None]:
    reset_registry_for_tests(_StubRegistry(descriptors))  # type: ignore[arg-type]
    yield
    reset_registry_for_tests(None)


# ---------------------------------------------------------------------------
# list_catalog
# ---------------------------------------------------------------------------


class TestListCatalog:
    def test_returns_all_when_no_filters(self) -> None:
        result = list_catalog()
        assert result.total == 4
        assert {item.tool_id for item in result.items} == {
            "nmap",
            "nuclei",
            "sqlmap",
            "metasploit",
        }

    def test_filter_by_category(self) -> None:
        result = list_catalog(category="web_va")
        assert result.total == 2
        assert {item.tool_id for item in result.items} == {"nuclei", "sqlmap"}

    def test_filter_by_risk_level(self) -> None:
        result = list_catalog(risk_level=ToolRiskLevel.HIGH)
        assert result.total == 1
        assert result.items[0].tool_id == "sqlmap"

    def test_filter_requires_approval(self) -> None:
        result = list_catalog(requires_approval=True)
        assert result.total == 2
        assert {item.tool_id for item in result.items} == {"sqlmap", "metasploit"}

    def test_filter_does_not_require_approval(self) -> None:
        result = list_catalog(requires_approval=False)
        assert result.total == 2
        assert {item.tool_id for item in result.items} == {"nmap", "nuclei"}

    def test_pagination_limit(self) -> None:
        result = list_catalog(limit=2, offset=0)
        assert len(result.items) == 2
        assert result.total == 4

    def test_pagination_offset(self) -> None:
        result = list_catalog(limit=2, offset=2)
        assert len(result.items) == 2
        # Items are sorted alphabetically by tool_id; offset=2 skips 'metasploit', 'nmap'
        assert {item.tool_id for item in result.items} == {"nuclei", "sqlmap"}

    def test_combined_filters(self) -> None:
        result = list_catalog(category="web_va", requires_approval=True)
        assert result.total == 1
        assert result.items[0].tool_id == "sqlmap"

    def test_descriptor_to_entry_truncates_description(self) -> None:
        # ToolDescriptor caps description at 500 chars at the source — the
        # service-layer slice [:2048] is a defence-in-depth no-op for valid
        # descriptors. We construct a 500-char description and assert the
        # MCP entry round-trips without truncation.
        long = "X" * 500
        reset_registry_for_tests(
            _StubRegistry(
                [_make_descriptor(tool_id="long", risk=RiskLevel.LOW, description=long)]
            )
        )
        result = list_catalog()
        assert result.items[0].description == long
        assert len(result.items[0].description) <= 2_048


# ---------------------------------------------------------------------------
# trigger_tool_run
# ---------------------------------------------------------------------------


class TestTriggerToolRun:
    def test_low_risk_queued_immediately(self) -> None:
        result = trigger_tool_run(
            payload=ToolRunTriggerInput(tool_id="nmap", target="example.com"),
            actor="alice",
            tenant_id="t-1",
        )
        assert result.status is ToolRunStatus.QUEUED
        assert result.requires_approval is False
        assert result.tool_run_id is not None

    def test_unknown_tool_raises_not_found(self) -> None:
        with pytest.raises(ResourceNotFoundError):
            trigger_tool_run(
                payload=ToolRunTriggerInput(tool_id="ghost", target="example.com"),
                actor="alice",
                tenant_id="t-1",
            )

    def test_high_risk_without_justification_blocks(self) -> None:
        with pytest.raises(ApprovalRequiredError):
            trigger_tool_run(
                payload=ToolRunTriggerInput(
                    tool_id="sqlmap", target="https://example.com/login"
                ),
                actor="alice",
                tenant_id="t-1",
            )

    def test_high_risk_with_short_justification_blocks(self) -> None:
        with pytest.raises(ApprovalRequiredError):
            trigger_tool_run(
                payload=ToolRunTriggerInput(
                    tool_id="sqlmap",
                    target="https://example.com/login",
                    justification="too short",
                ),
                actor="alice",
                tenant_id="t-1",
            )

    def test_high_risk_with_justification_returns_approval_pending(self) -> None:
        result = trigger_tool_run(
            payload=ToolRunTriggerInput(
                tool_id="sqlmap",
                target="https://example.com/login",
                justification="Customer reported SQLi on login form, ticket SEC-1234",
            ),
            actor="alice",
            tenant_id="t-1",
        )
        assert result.status is ToolRunStatus.APPROVAL_PENDING
        assert result.requires_approval is True
        assert result.approval_request_id is not None
        assert result.tool_run_id is None

    def test_destructive_risk_requires_approval(self) -> None:
        result = trigger_tool_run(
            payload=ToolRunTriggerInput(
                tool_id="metasploit",
                target="https://example.com",
                justification="Validating exploit chain on staging environment",
            ),
            actor="alice",
            tenant_id="t-1",
        )
        assert result.status is ToolRunStatus.APPROVAL_PENDING
        assert result.requires_approval is True

    def test_approval_factory_invoked_for_high_risk(self) -> None:
        seen: list[tuple[str, str]] = []

        def factory(descriptor: ToolDescriptor, actor: str) -> str:
            seen.append((descriptor.tool_id, actor))
            return "approval-id-123"

        result = trigger_tool_run(
            payload=ToolRunTriggerInput(
                tool_id="sqlmap",
                target="https://example.com/login",
                justification="Customer-reported SQL injection on /login form, SEC-9000",
            ),
            actor="alice",
            tenant_id="t-1",
            approval_factory=factory,
        )
        assert result.approval_request_id == "approval-id-123"
        assert seen == [("sqlmap", "alice")]


# ---------------------------------------------------------------------------
# get_tool_run_status
# ---------------------------------------------------------------------------


class TestGetToolRunStatus:
    def test_empty_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            get_tool_run_status(tenant_id="t-1", tool_run_id="")

    def test_default_lookup_returns_not_found(self) -> None:
        with pytest.raises(ResourceNotFoundError):
            get_tool_run_status(tenant_id="t-1", tool_run_id="run-12345")

    def test_lookup_returns_status(self) -> None:
        canned = ToolRunStatusResult(
            tool_run_id="run-12345abc",
            tool_id="nmap",
            status=ToolRunStatus.RUNNING,
        )

        def lookup(tenant_id: str, tool_run_id: str) -> ToolRunStatusResult | None:
            assert tenant_id == "t-1"
            assert tool_run_id == "run-12345abc"
            return canned

        result = get_tool_run_status(
            tenant_id="t-1", tool_run_id="run-12345abc", lookup=lookup
        )
        assert result.tool_run_id == "run-12345abc"
        assert result.status is ToolRunStatus.RUNNING

    def test_lookup_returns_none_raises_not_found(self) -> None:
        def lookup(_t: str, _r: str) -> ToolRunStatusResult | None:
            return None

        with pytest.raises(ResourceNotFoundError):
            get_tool_run_status(
                tenant_id="t-1", tool_run_id="missing-run-id", lookup=lookup
            )


def test_module_public_api() -> None:
    public = set(tool_service.__all__)
    assert {
        "list_catalog",
        "trigger_tool_run",
        "get_tool_run_status",
        "get_registry",
        "reset_registry_for_tests",
    } <= public
