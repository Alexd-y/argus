"""P1 — WSTG per-scenario coverage: materialised from per-test states + wired into
the WSTG block (previously scenario_coverage was never attached → null placeholder)."""

from __future__ import annotations

from types import SimpleNamespace

from src.reports.scenario_coverage import (
    CoverageStatus,
    scenario_coverage_from_wstg_states,
)
from src.reports.wstg_report import SCENARIO_REGISTRY_VERSION, build_wstg_block


def _state(
    test_id: str,
    *,
    applicability: str = "applicable",
    execution_status: str = "not_started",
    outcome: str = "not_evaluated",
    scenario_ids: list[str] | None = None,
    evidence_refs: list[str] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        test_id=test_id,
        applicability=applicability,
        execution_status=execution_status,
        outcome=outcome,
        scenario_ids=scenario_ids or [],
        evidence_refs=evidence_refs or [],
        evidence_validated=False,
    )


def test_status_mapping_is_honest() -> None:
    cov = scenario_coverage_from_wstg_states(
        [
            _state("WSTG-A", execution_status="completed", outcome="fail"),
            _state("WSTG-B", execution_status="completed", outcome="pass"),
            _state("WSTG-C", applicability="not_applicable"),
            _state("WSTG-D", execution_status="not_started"),
            _state("WSTG-E", execution_status="blocked"),
            _state("WSTG-F", execution_status="failed"),
            _state("WSTG-G", execution_status="partial"),
            _state("WSTG-H", execution_status="completed", outcome="inconclusive"),
        ]
    )
    by_id = {r["scenario_id"]: r["coverage_status"] for r in cov["records"]}
    assert by_id["WSTG-A"] == CoverageStatus.CONFIRMED_FINDING.value
    assert by_id["WSTG-B"] == CoverageStatus.EXECUTED_NO_FINDING.value
    assert by_id["WSTG-C"] == CoverageStatus.NOT_APPLICABLE.value
    assert by_id["WSTG-D"] == CoverageStatus.NOT_RUN.value
    assert by_id["WSTG-E"] == CoverageStatus.BLOCKED.value
    assert by_id["WSTG-F"] == CoverageStatus.ERROR.value
    assert by_id["WSTG-G"] == CoverageStatus.PARTIAL.value
    assert by_id["WSTG-H"] == CoverageStatus.PARTIAL.value
    assert cov["total_scenarios"] == 8
    assert cov["confirmed_findings"] == 1


def test_scenario_ids_expand_to_multiple_records() -> None:
    cov = scenario_coverage_from_wstg_states(
        [_state("WSTG-X", execution_status="completed", outcome="pass", scenario_ids=["s1", "s2"])]
    )
    ids = sorted(r["scenario_id"] for r in cov["records"])
    assert ids == ["s1", "s2"]
    assert all(r["wstg"] == ["WSTG-X"] for r in cov["records"])


def test_build_wstg_block_attaches_materialised_scenario_coverage() -> None:
    block = build_wstg_block([], scan_id="scan-1", target="https://t.example")
    sc = block["scenario_coverage"]
    assert isinstance(sc, dict)
    assert sc["total_scenarios"] > 0  # materialised from the catalog's per-test states
    assert "by_status" in sc
    assert block["scenario_registry_version"] == SCENARIO_REGISTRY_VERSION
    assert SCENARIO_REGISTRY_VERSION == "argus-wstg-scn-1"


def test_explicit_scenario_coverage_takes_precedence() -> None:
    explicit = {"total_scenarios": 3, "source": "executed-results"}
    block = build_wstg_block(
        [], scan_id="scan-1", target="https://t.example", scenario_coverage=explicit
    )
    assert block["scenario_coverage"] is explicit
