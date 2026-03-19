"""Unit tests for stage2_parsers (TM2-002) and artifact generators (TM2-003/004/005)."""

from __future__ import annotations

import json

from app.schemas.threat_modeling.schemas import CriticalAsset, ThreatModelInputBundle
from src.recon.threat_modeling.artifacts import (
    generate_application_flows_json,
    generate_priority_hypotheses_json,
    generate_threat_model_json,
)
from src.recon.threat_modeling.stage2_parsers import (
    parse_application_flows_to_stage3,
    parse_critical_assets_to_stage3,
    parse_entry_points_to_stage3,
    parse_priority_hypotheses,
    parse_threat_scenarios_to_stage3,
    parse_trust_boundaries_to_stage3,
)


def _minimal_bundle() -> ThreatModelInputBundle:
    return ThreatModelInputBundle(
        engagement_id="eng-123",
        target_id=None,
    )


class TestParseCriticalAssetsToStage3:
    def test_from_prior_outputs(self) -> None:
        prior = {
            "critical_assets": {
                "assets": [
                    {"id": "ca-1", "name": "DB", "asset_type": "data", "statement_type": "evidence"},
                    {"id": "ca-2", "name": "API", "statement_type": "hypothesis"},
                ]
            }
        }
        result = parse_critical_assets_to_stage3(prior, _minimal_bundle())
        assert len(result) == 2
        assert result[0].id == "ca-1"
        assert result[0].type == "observation"
        assert result[1].type == "hypothesis"

    def test_empty_fallback_to_bundle(self) -> None:
        bundle = ThreatModelInputBundle(
            engagement_id="eng",
            critical_assets=[CriticalAsset(id="b1", name="X", asset_type="t", description=None)],
        )
        result = parse_critical_assets_to_stage3({}, bundle)
        assert len(result) == 1
        assert result[0].source == "bundle.critical_assets"


class TestParseTrustBoundariesToStage3:
    def test_from_prior_outputs(self) -> None:
        prior = {
            "trust_boundaries": {
                "boundaries": [
                    {"id": "tb-1", "name": "DMZ", "components": ["web", "api"]},
                ]
            }
        }
        result = parse_trust_boundaries_to_stage3(prior, _minimal_bundle())
        assert len(result) == 1
        assert result[0].components == ["web", "api"]


class TestParseEntryPointsToStage3:
    def test_from_prior_outputs(self) -> None:
        prior = {
            "entry_points": {
                "entry_points": [
                    {"id": "ep-1", "name": "Login", "host_or_component": "auth-svc"},
                ]
            }
        }
        result = parse_entry_points_to_stage3(prior, _minimal_bundle())
        assert len(result) == 1
        assert result[0].component_id == "auth-svc"
        assert result[0].type == "hypothesis"


class TestParseThreatScenariosToStage3:
    def test_from_prior_outputs(self) -> None:
        prior = {
            "threat_scenarios": {
                "scenarios": [
                    {
                        "id": "ts-1",
                        "title": "Auth bypass",
                        "description": "Weak auth",
                        "entry_point": "ep-1",
                        "attacker_profile": "ap-1",
                        "priority": "high",
                    },
                ]
            }
        }
        result = parse_threat_scenarios_to_stage3(prior)
        assert len(result) == 1
        assert result[0].entry_point_id == "ep-1"
        assert result[0].attacker_profile_id == "ap-1"
        assert result[0].priority == "high"


class TestParsePriorityHypotheses:
    def test_from_bundle(self) -> None:
        bundle = ThreatModelInputBundle(
            engagement_id="eng",
            priority_hypotheses=[
                {
                    "id": "ph-1",
                    "text": "API may lack rate limiting",
                    "priority": "high",
                    "confidence": 0.8,
                    "related_asset_id": "ca-1",
                    "source": "stage2_structured.json",
                },
            ],
        )
        result = parse_priority_hypotheses(bundle, {})
        assert len(result.hypotheses) == 1
        assert result.hypotheses[0].hypothesis_text == "API may lack rate limiting"
        assert result.hypotheses[0].confidence == 0.8

    def test_fallback_from_threat_scenarios(self) -> None:
        prior = {
            "threat_scenarios": {
                "scenarios": [
                    {"id": "ts-1", "description": "Auth weakness", "priority": "medium"},
                ]
            }
        }
        result = parse_priority_hypotheses(_minimal_bundle(), prior)
        assert len(result.hypotheses) == 1
        assert result.hypotheses[0].source_artifact == "ai_tm_threat_scenarios"


class TestParseApplicationFlowsToStage3:
    def test_from_prior_outputs(self) -> None:
        prior = {
            "application_flows": {
                "flows": [
                    {"id": "f1", "source": "client", "sink": "api", "data_type": "json"},
                ]
            }
        }
        result = parse_application_flows_to_stage3(prior, _minimal_bundle())
        assert len(result) == 1
        assert result[0].source == "client"
        assert result[0].sink == "api"


class TestGenerateThreatModelJson:
    def test_output_valid_json(self) -> None:
        prior = {
            "critical_assets": {"assets": [{"id": "ca-1", "name": "DB", "asset_type": "data"}]},
            "trust_boundaries": {"boundaries": []},
            "entry_points": {"entry_points": []},
            "attacker_profiles": {"profiles": [{"id": "ap-1", "name": "A", "capability_level": "low"}]},
            "threat_scenarios": {"scenarios": []},
        }
        out = generate_threat_model_json(_minimal_bundle(), prior, "run-1", "job-1")
        data = json.loads(out)
        assert data["run_id"] == "run-1"
        assert data["job_id"] == "job-1"
        assert len(data["critical_assets"]) == 1
        assert len(data["attacker_profiles"]) == 1


class TestGeneratePriorityHypothesesJson:
    def test_output_valid_json(self) -> None:
        bundle = ThreatModelInputBundle(
            engagement_id="eng",
            priority_hypotheses=[{"id": "ph-1", "text": "Test", "priority": "high", "confidence": 0.5}],
        )
        out = generate_priority_hypotheses_json(bundle, {})
        data = json.loads(out)
        assert "hypotheses" in data
        assert len(data["hypotheses"]) == 1


class TestGenerateApplicationFlowsJson:
    def test_output_valid_json(self) -> None:
        prior = {
            "application_flows": {
                "flows": [{"id": "f1", "source": "a", "sink": "b"}],
            }
        }
        out = generate_application_flows_json(prior, _minimal_bundle())
        data = json.loads(out)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["source"] == "a"
