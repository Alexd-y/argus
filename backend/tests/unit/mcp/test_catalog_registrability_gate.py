"""MCP catalog registrability gate wiring (R9.2)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-prod-but-required-by-settings")
os.environ.setdefault("ARGUS_TEST_MODE", "1")

import pytest  # noqa: E402

from src.core.config import settings  # noqa: E402
from src.mcp.schemas.tool_run import ToolRiskLevel  # noqa: E402
from src.mcp.services import tool_service  # noqa: E402


@dataclass
class _Enum:
    value: str


@dataclass
class FakeDescriptor:
    tool_id: str
    command_template: list[str]
    risk_level: _Enum = field(default_factory=lambda: _Enum("low"))
    category: _Enum = field(default_factory=lambda: _Enum("recon"))
    phase: _Enum = field(default_factory=lambda: _Enum("recon"))
    requires_approval: bool = False
    description: str = ""
    cwe_hints: tuple[int, ...] = ()


class FakeRegistry:
    def __init__(self, descriptors):
        self._descriptors = descriptors

    def all_descriptors(self):
        return list(self._descriptors)


_DESCRIPTORS = [
    FakeDescriptor("nuclei", ["nuclei"]),  # parser + executable present
    FakeDescriptor("skipfish", ["skipfish"]),  # no parser → filtered when gate on
]


@pytest.fixture(autouse=True)
def _inject_registry(monkeypatch):
    tool_service.reset_registry_for_tests(FakeRegistry(_DESCRIPTORS))
    monkeypatch.setattr(
        tool_service, "get_registered_tool_parsers", lambda: frozenset({"nuclei"})
    )
    monkeypatch.setattr(
        tool_service, "load_known_executables", lambda: frozenset({"nuclei", "skipfish"})
    )
    yield
    tool_service.reset_registry_for_tests(None)


def test_gate_disabled_lists_all_tools(monkeypatch):
    monkeypatch.setattr(settings, "mcp_registrability_gate_enabled", False)
    result = tool_service.list_catalog()
    ids = {e.tool_id for e in result.items}
    assert ids == {"nuclei", "skipfish"}


def test_gate_enabled_filters_unparseable_tool(monkeypatch):
    monkeypatch.setattr(settings, "mcp_registrability_gate_enabled", True)
    result = tool_service.list_catalog()
    ids = {e.tool_id for e in result.items}
    assert ids == {"nuclei"}  # skipfish filtered (no parser)
    assert result.total == 1


def test_risk_level_enum_is_valid():
    # Guards the FakeDescriptor risk value against the real ToolRiskLevel enum.
    assert ToolRiskLevel("low")
