"""P7-WSTG-007 (fix G-4): single, versioned WSTG registry.

Guards that:
* the removed ``wstg_coverage_v2`` module is no longer importable (one source
  of truth — no competing registry);
* the surviving ``build_wstg_coverage_v2`` alias lives in ``wstg_coverage`` and
  delegates to the same registry; and
* every coverage result surfaces an explicit WSTG methodology version.
"""

from __future__ import annotations

import importlib

import pytest

from src.reports.wstg_coverage import (
    WSTG_VERSION,
    WstgCoverageResult,
    build_wstg_coverage,
    build_wstg_coverage_v2,
)


def test_wstg_coverage_v2_module_removed() -> None:
    """The dead competing registry module must not exist (fix G-4)."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("src.reports.wstg_coverage_v2")


def test_version_present_in_result() -> None:
    result = build_wstg_coverage(["nmap"])
    assert isinstance(result, WstgCoverageResult)
    assert result.wstg_version == WSTG_VERSION == "4.2"


def test_v2_alias_shares_single_registry() -> None:
    """The v2 alias delegates to the same registry (identical test count)."""
    tools = ["nmap", "nuclei", "testssl"]
    base = build_wstg_coverage(tools)
    v2 = build_wstg_coverage_v2(tools)
    assert v2.total_tests == base.total_tests
    assert v2.covered == base.covered
    assert v2.wstg_version == base.wstg_version == WSTG_VERSION


def test_scenario_coverage_is_additive() -> None:
    """A scenario-coverage block attaches without disturbing tool coverage."""
    scenario_block = {"total_scenarios": 3, "confirmed_findings": 1}
    result = build_wstg_coverage(["nmap"], scenario_coverage=scenario_block)
    assert result.scenario_coverage == scenario_block
    # Tool coverage fields remain intact.
    assert result.total_tests >= 90

    baseline = build_wstg_coverage(["nmap"])
    assert result.total_tests == baseline.total_tests
    assert result.covered == baseline.covered
    assert baseline.scenario_coverage is None
