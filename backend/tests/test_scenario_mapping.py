"""Tests for FindingToScenarioMapper (VA3UP-005)."""

from __future__ import annotations

import pytest

from app.schemas.threat_modeling.schemas import (
    CriticalAsset,
    ThreatScenario,
    TrustBoundary,
)
from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle
from app.schemas.vulnerability_analysis.scenario_mapping import FindingToScenarioMap
from src.recon.vulnerability_analysis.scenario_mapping import (
    generate_all_scenario_mapping_artifacts,
    generate_finding_asset_map_csv,
    generate_finding_boundary_map_csv,
    generate_finding_scenario_map_csv,
    generate_finding_to_scenario_map_json,
    map_findings_to_scenario,
)


@pytest.fixture
def bundle() -> VulnerabilityAnalysisInputBundle:
    """Minimal bundle with scenarios, boundaries, assets."""
    return VulnerabilityAnalysisInputBundle(
        engagement_id="e1",
        threat_scenarios=[
            ThreatScenario(
                id="ts1",
                title="IDOR scenario",
                description="Test",
                likelihood=0.5,
                impact=0.5,
                priority="high",
            ),
            ThreatScenario(
                id="ts2",
                title="Auth bypass",
                description="Test",
                likelihood=0.3,
                impact=0.8,
                priority="high",
            ),
        ],
        trust_boundaries=[
            TrustBoundary(id="tb1", name="Client-Server"),
            TrustBoundary(id="tb2", name="API-DB"),
        ],
        critical_assets=[
            CriticalAsset(id="ca1", name="User data", asset_type="data"),
            CriticalAsset(id="ca2", name="API keys", asset_type="secret"),
        ],
    )


def test_map_findings_from_checks(bundle: VulnerabilityAnalysisInputBundle) -> None:
    """Map findings from authorization/input checks."""
    ai_results = {
        "authorization_analysis": {
            "checks": [
                {
                    "target_id": "ep1",
                    "description": "IDOR check for /api/users",
                    "scenario_ids": ["ts1"],
                    "trust_boundary_id": "tb1",
                    "affected_asset_id": "ca1",
                    "evidence_refs": ["route:api/users", "param:id"],
                },
            ],
        },
        "input_surface_analysis": {
            "checks": [
                {
                    "target_id": "ep2",
                    "description": "SQLi in search param",
                    "scenario_ids": ["ts2"],
                    "trust_boundary_id": "tb2",
                    "affected_asset_id": "ca2",
                    "evidence_refs": ["param:q"],
                },
            ],
        },
    }
    mapping = map_findings_to_scenario(bundle, ai_results)
    assert len(mapping.scenario_links) == 2
    assert len(mapping.boundary_links) == 2
    assert len(mapping.asset_links) == 2

    scenario_ids = {l.scenario_id for l in mapping.scenario_links}
    assert "ts1" in scenario_ids
    assert "ts2" in scenario_ids

    boundary_ids = {l.boundary_id for l in mapping.boundary_links}
    assert "tb1" in boundary_ids
    assert "tb2" in boundary_ids

    asset_ids = {l.asset_id for l in mapping.asset_links}
    assert "ca1" in asset_ids
    assert "ca2" in asset_ids


def test_map_findings_ignores_unknown_ids(bundle: VulnerabilityAnalysisInputBundle) -> None:
    """Unknown scenario/boundary/asset IDs are skipped."""
    ai_results = {
        "authorization_analysis": {
            "checks": [
                {
                    "target_id": "ep1",
                    "description": "Check",
                    "scenario_ids": ["ts_unknown"],
                    "trust_boundary_id": "tb_unknown",
                    "affected_asset_id": "ca_unknown",
                    "evidence_refs": [],
                },
            ],
        },
    }
    mapping = map_findings_to_scenario(bundle, ai_results)
    assert len(mapping.scenario_links) == 0
    assert len(mapping.boundary_links) == 0
    assert len(mapping.asset_links) == 0


def test_map_findings_from_correlations_and_remediations(
    bundle: VulnerabilityAnalysisInputBundle,
) -> None:
    """Correlations and remediations add finding IDs; checks provide linkage."""
    ai_results = {
        "authorization_analysis": {
            "checks": [
                {
                    "target_id": "ep1",
                    "description": "Auth check",
                    "scenario_ids": ["ts1"],
                    "trust_boundary_id": "tb1",
                    "affected_asset_id": "ca1",
                    "evidence_refs": [],
                },
            ],
        },
        "finding_correlation": {
            "correlations": [
                {
                    "finding_ids": ["ep1", "ep2"],
                    "link_type": "related",
                    "description": "Both target same asset",
                    "evidence_refs": [],
                },
            ],
        },
        "remediation_note_generation": {
            "remediations": [
                {
                    "finding_id": "ep1",
                    "recommendation": "Add auth check",
                    "priority": "high",
                    "evidence_refs": [],
                },
            ],
        },
    }
    mapping = map_findings_to_scenario(bundle, ai_results)
    assert len(mapping.scenario_links) >= 1
    assert any(l.finding_id == "ep1" for l in mapping.scenario_links)


def test_generate_json(mapping: FindingToScenarioMap) -> None:
    """JSON output is valid."""
    json_str = generate_finding_to_scenario_map_json(mapping)
    import json as j

    data = j.loads(json_str)
    assert "scenario_links" in data
    assert "boundary_links" in data
    assert "asset_links" in data


def test_generate_csvs(mapping: FindingToScenarioMap) -> None:
    """CSV outputs have correct headers."""
    scenario_csv = generate_finding_scenario_map_csv(mapping)
    assert "finding_id,scenario_id,link_type,rationale,evidence_refs" in scenario_csv

    boundary_csv = generate_finding_boundary_map_csv(mapping)
    assert "finding_id,boundary_id,rationale,evidence_refs" in boundary_csv

    asset_csv = generate_finding_asset_map_csv(mapping)
    assert "finding_id,asset_id,rationale,evidence_refs" in asset_csv


def test_generate_all_artifacts(bundle: VulnerabilityAnalysisInputBundle) -> None:
    """generate_all_scenario_mapping_artifacts returns all four files."""
    ai_results = {
        "authorization_analysis": {
            "checks": [
                {
                    "target_id": "ep1",
                    "description": "Check",
                    "scenario_ids": ["ts1"],
                    "trust_boundary_id": "tb1",
                    "affected_asset_id": "ca1",
                    "evidence_refs": ["ref1"],
                },
            ],
        },
    }
    artifacts = generate_all_scenario_mapping_artifacts(bundle, ai_results)
    assert "finding_to_scenario_map.json" in artifacts
    assert "finding_scenario_map.csv" in artifacts
    assert "finding_boundary_map.csv" in artifacts
    assert "finding_asset_map.csv" in artifacts


@pytest.fixture
def mapping(bundle: VulnerabilityAnalysisInputBundle) -> FindingToScenarioMap:
    """Mapping with one link of each type."""
    return map_findings_to_scenario(
        bundle,
        {
            "authorization_analysis": {
                "checks": [
                    {
                        "target_id": "ep1",
                        "description": "IDOR",
                        "scenario_ids": ["ts1"],
                        "trust_boundary_id": "tb1",
                        "affected_asset_id": "ca1",
                        "evidence_refs": ["ref1"],
                    },
                ],
            },
        },
    )
