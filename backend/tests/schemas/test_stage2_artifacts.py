"""Unit tests for Stage 2 threat modeling artifacts (TM2-001)."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.schemas.ai.common import PriorityLevel
from app.schemas.threat_modeling.schemas import ApplicationFlow
from app.schemas.threat_modeling.stage2_artifacts import (
    AiTmPriorityHypotheses,
    PriorityHypothesis,
    Stage2InputsArtifact,
    Stage3ApplicationFlow,
    Stage3CriticalAsset,
    Stage3EntryPoint,
    Stage3ThreatScenario,
    Stage3TrustBoundary,
    ThreatModelUnified,
)


def _valid_stage3_critical_asset() -> dict:
    return {
        "id": "ca-1",
        "name": "User credentials",
        "type": "observation",
        "source": "stage3_readiness.json",
    }


def _valid_stage3_trust_boundary() -> dict:
    return {
        "id": "tb-1",
        "name": "DMZ boundary",
        "components": ["web-server", "api-gateway"],
        "source": "stage3_readiness.json",
    }


def _valid_stage3_entry_point() -> dict:
    return {
        "id": "ep-1",
        "name": "Login API",
        "component_id": "comp-1",
        "type": "hypothesis",
        "source": "stage3_readiness.json",
    }


def _valid_stage3_threat_scenario() -> dict:
    return {
        "id": "ts-1",
        "priority": "high",
        "entry_point_id": "ep-1",
        "attacker_profile_id": "ap-1",
        "description": "Attacker exploits weak auth",
    }


def _valid_priority_hypothesis() -> dict:
    return {
        "id": "ph-1",
        "hypothesis_text": "API may lack rate limiting",
        "priority": "high",
        "confidence": 0.8,
        "related_asset_id": "ca-1",
        "source_artifact": "stage3_readiness.json",
    }


def _valid_threat_model_input_bundle() -> dict:
    return {
        "engagement_id": "12345678-1234-1234-1234-123456789012",
        "target_id": None,
        "critical_assets": [],
        "trust_boundaries": [],
        "attacker_profiles": [],
        "entry_points": [],
        "application_flows": [],
        "artifact_refs": [],
        "priority_hypotheses": [],
        "anomalies": [],
        "intel_findings": [],
        "api_surface": [],
        "endpoint_inventory": [],
        "route_inventory": [],
        "dns_summary": None,
        "live_hosts": [],
        "tech_profile": [],
    }


def _valid_application_flow() -> dict:
    return {
        "id": "flow-1",
        "source": "frontend",
        "sink": "backend",
        "data_type": "credentials",
        "description": "Auth flow",
    }


class TestStage3CriticalAsset:
    def test_valid_observation(self) -> None:
        data = _valid_stage3_critical_asset()
        obj = Stage3CriticalAsset.model_validate(data)
        assert obj.id == "ca-1"
        assert obj.name == "User credentials"
        assert obj.type == "observation"
        assert obj.source == "stage3_readiness.json"

    def test_valid_hypothesis(self) -> None:
        data = {**_valid_stage3_critical_asset(), "type": "hypothesis"}
        obj = Stage3CriticalAsset.model_validate(data)
        assert obj.type == "hypothesis"

    def test_rejects_invalid_type(self) -> None:
        data = {**_valid_stage3_critical_asset(), "type": "unknown"}
        with pytest.raises(ValidationError):
            Stage3CriticalAsset.model_validate(data)

    def test_rejects_empty_id(self) -> None:
        data = {**_valid_stage3_critical_asset(), "id": ""}
        with pytest.raises(ValidationError):
            Stage3CriticalAsset.model_validate(data)

    def test_rejects_extra_fields(self) -> None:
        data = {**_valid_stage3_critical_asset(), "unknown_field": "x"}
        with pytest.raises(ValidationError):
            Stage3CriticalAsset.model_validate(data)

    def test_serialization_roundtrip(self) -> None:
        data = _valid_stage3_critical_asset()
        obj = Stage3CriticalAsset.model_validate(data)
        dumped = obj.model_dump(mode="json")
        assert dumped == data
        json_str = obj.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed == data


class TestStage3TrustBoundary:
    def test_valid(self) -> None:
        data = _valid_stage3_trust_boundary()
        obj = Stage3TrustBoundary.model_validate(data)
        assert obj.id == "tb-1"
        assert obj.components == ["web-server", "api-gateway"]

    def test_empty_components_default(self) -> None:
        data = _valid_stage3_trust_boundary()
        del data["components"]
        obj = Stage3TrustBoundary.model_validate(data)
        assert obj.components == []

    def test_rejects_extra_fields(self) -> None:
        data = {**_valid_stage3_trust_boundary(), "extra": "x"}
        with pytest.raises(ValidationError):
            Stage3TrustBoundary.model_validate(data)

    def test_serialization_roundtrip(self) -> None:
        data = _valid_stage3_trust_boundary()
        obj = Stage3TrustBoundary.model_validate(data)
        dumped = obj.model_dump(mode="json")
        assert dumped == data


class TestStage3EntryPoint:
    def test_valid(self) -> None:
        data = _valid_stage3_entry_point()
        obj = Stage3EntryPoint.model_validate(data)
        assert obj.type == "hypothesis"
        assert obj.component_id == "comp-1"

    def test_type_must_be_hypothesis(self) -> None:
        data = {**_valid_stage3_entry_point(), "type": "observation"}
        with pytest.raises(ValidationError):
            Stage3EntryPoint.model_validate(data)

    def test_rejects_extra_fields(self) -> None:
        data = {**_valid_stage3_entry_point(), "unknown": "x"}
        with pytest.raises(ValidationError):
            Stage3EntryPoint.model_validate(data)

    def test_serialization_roundtrip(self) -> None:
        data = _valid_stage3_entry_point()
        obj = Stage3EntryPoint.model_validate(data)
        assert obj.model_dump(mode="json") == data


class TestStage3ThreatScenario:
    def test_valid(self) -> None:
        data = _valid_stage3_threat_scenario()
        obj = Stage3ThreatScenario.model_validate(data)
        assert obj.priority == "high"
        assert obj.entry_point_id == "ep-1"

    def test_rejects_empty_description(self) -> None:
        data = {**_valid_stage3_threat_scenario(), "description": ""}
        with pytest.raises(ValidationError):
            Stage3ThreatScenario.model_validate(data)

    def test_rejects_extra_fields(self) -> None:
        data = {**_valid_stage3_threat_scenario(), "extra": "x"}
        with pytest.raises(ValidationError):
            Stage3ThreatScenario.model_validate(data)

    def test_serialization_roundtrip(self) -> None:
        data = _valid_stage3_threat_scenario()
        obj = Stage3ThreatScenario.model_validate(data)
        assert obj.model_dump(mode="json") == data


class TestThreatModelUnified:
    def test_valid_empty(self) -> None:
        data = {
            "critical_assets": [],
            "trust_boundaries": [],
            "entry_points": [],
            "attacker_profiles": [],
            "threat_scenarios": [],
        }
        obj = ThreatModelUnified.model_validate(data)
        assert obj.critical_assets == []
        assert obj.trust_boundaries == []

    def test_valid_with_nested_models(self) -> None:
        data = {
            "critical_assets": [_valid_stage3_critical_asset()],
            "trust_boundaries": [_valid_stage3_trust_boundary()],
            "entry_points": [_valid_stage3_entry_point()],
            "attacker_profiles": [
                {"id": "ap-1", "name": "Script kiddie", "capability_level": "low"}
            ],
            "threat_scenarios": [_valid_stage3_threat_scenario()],
        }
        obj = ThreatModelUnified.model_validate(data)
        assert len(obj.critical_assets) == 1
        assert len(obj.trust_boundaries) == 1
        assert len(obj.entry_points) == 1
        assert len(obj.attacker_profiles) == 1
        assert len(obj.threat_scenarios) == 1

    def test_rejects_extra_fields(self) -> None:
        data = {
            "critical_assets": [],
            "trust_boundaries": [],
            "entry_points": [],
            "attacker_profiles": [],
            "threat_scenarios": [],
            "unknown": "x",
        }
        with pytest.raises(ValidationError):
            ThreatModelUnified.model_validate(data)

    def test_serialization_roundtrip(self) -> None:
        data = {
            "critical_assets": [_valid_stage3_critical_asset()],
            "trust_boundaries": [],
            "entry_points": [],
            "attacker_profiles": [],
            "threat_scenarios": [],
        }
        obj = ThreatModelUnified.model_validate(data)
        roundtrip = ThreatModelUnified.model_validate(obj.model_dump(mode="json"))
        assert roundtrip.critical_assets[0].id == "ca-1"


class TestPriorityHypothesis:
    def test_valid(self) -> None:
        data = _valid_priority_hypothesis()
        obj = PriorityHypothesis.model_validate(data)
        assert obj.priority == PriorityLevel.HIGH
        assert obj.confidence == 0.8
        assert obj.related_asset_id == "ca-1"

    def test_related_asset_id_optional(self) -> None:
        data = _valid_priority_hypothesis()
        del data["related_asset_id"]
        obj = PriorityHypothesis.model_validate(data)
        assert obj.related_asset_id is None

    def test_priority_enum_enforced(self) -> None:
        data = {**_valid_priority_hypothesis(), "priority": "urgent"}
        with pytest.raises(ValidationError):
            PriorityHypothesis.model_validate(data)

    def test_confidence_bounds(self) -> None:
        data = {**_valid_priority_hypothesis(), "confidence": 1.5}
        with pytest.raises(ValidationError):
            PriorityHypothesis.model_validate(data)

        data = {**_valid_priority_hypothesis(), "confidence": -0.1}
        with pytest.raises(ValidationError):
            PriorityHypothesis.model_validate(data)

    def test_confidence_boundary_values(self) -> None:
        for val in (0.0, 1.0):
            data = {**_valid_priority_hypothesis(), "confidence": val}
            obj = PriorityHypothesis.model_validate(data)
            assert obj.confidence == val

    def test_rejects_extra_fields(self) -> None:
        data = {**_valid_priority_hypothesis(), "extra": "x"}
        with pytest.raises(ValidationError):
            PriorityHypothesis.model_validate(data)

    def test_serialization_roundtrip(self) -> None:
        data = _valid_priority_hypothesis()
        obj = PriorityHypothesis.model_validate(data)
        dumped = obj.model_dump(mode="json")
        assert dumped["priority"] == "high"
        roundtrip = PriorityHypothesis.model_validate(dumped)
        assert roundtrip.priority == PriorityLevel.HIGH


class TestAiTmPriorityHypotheses:
    def test_valid_empty(self) -> None:
        data = {"hypotheses": []}
        obj = AiTmPriorityHypotheses.model_validate(data)
        assert obj.hypotheses == []

    def test_valid_with_hypotheses(self) -> None:
        data = {"hypotheses": [_valid_priority_hypothesis()]}
        obj = AiTmPriorityHypotheses.model_validate(data)
        assert len(obj.hypotheses) == 1
        assert obj.hypotheses[0].id == "ph-1"

    def test_rejects_extra_fields(self) -> None:
        data = {"hypotheses": [], "extra": "x"}
        with pytest.raises(ValidationError):
            AiTmPriorityHypotheses.model_validate(data)

    def test_serialization_roundtrip(self) -> None:
        data = {"hypotheses": [_valid_priority_hypothesis()]}
        obj = AiTmPriorityHypotheses.model_validate(data)
        roundtrip = AiTmPriorityHypotheses.model_validate(obj.model_dump(mode="json"))
        assert roundtrip.hypotheses[0].hypothesis_text == "API may lack rate limiting"


class TestStage3ApplicationFlow:
    def test_inherits_application_flow_fields(self) -> None:
        data = _valid_application_flow()
        obj = Stage3ApplicationFlow.model_validate(data)
        assert obj.id == "flow-1"
        assert obj.source == "frontend"
        assert obj.sink == "backend"
        assert obj.data_type == "credentials"

    def test_is_subclass_of_application_flow(self) -> None:
        assert issubclass(Stage3ApplicationFlow, ApplicationFlow)

    def test_rejects_extra_fields(self) -> None:
        data = {**_valid_application_flow(), "extra": "x"}
        with pytest.raises(ValidationError):
            Stage3ApplicationFlow.model_validate(data)

    def test_serialization_roundtrip(self) -> None:
        data = _valid_application_flow()
        obj = Stage3ApplicationFlow.model_validate(data)
        assert obj.model_dump(mode="json") == data


class TestStage2InputsArtifact:
    def test_valid(self) -> None:
        data = {
            "run_id": "run-001",
            "job_id": "job-001",
            "engagement_id": "12345678-1234-1234-1234-123456789012",
            "target_id": None,
            "bundle": _valid_threat_model_input_bundle(),
        }
        obj = Stage2InputsArtifact.model_validate(data)
        assert obj.run_id == "run-001"
        assert obj.bundle.engagement_id == "12345678-1234-1234-1234-123456789012"

    def test_valid_with_target_id(self) -> None:
        data = {
            "run_id": "run-001",
            "job_id": "job-001",
            "engagement_id": "12345678-1234-1234-1234-123456789012",
            "target_id": "87654321-4321-4321-4321-210987654321",
            "bundle": _valid_threat_model_input_bundle(),
        }
        obj = Stage2InputsArtifact.model_validate(data)
        assert obj.target_id == "87654321-4321-4321-4321-210987654321"

    def test_rejects_empty_run_id(self) -> None:
        data = {
            "run_id": "",
            "job_id": "job-001",
            "engagement_id": "12345678-1234-1234-1234-123456789012",
            "bundle": _valid_threat_model_input_bundle(),
        }
        with pytest.raises(ValidationError):
            Stage2InputsArtifact.model_validate(data)

    def test_rejects_invalid_bundle(self) -> None:
        data = {
            "run_id": "run-001",
            "job_id": "job-001",
            "engagement_id": "eng-12345678-1234-1234-1234-123456789012",
            "bundle": {"engagement_id": ""},
        }
        with pytest.raises(ValidationError):
            Stage2InputsArtifact.model_validate(data)

    def test_rejects_extra_fields(self) -> None:
        data = {
            "run_id": "run-001",
            "job_id": "job-001",
            "engagement_id": "12345678-1234-1234-1234-123456789012",
            "bundle": _valid_threat_model_input_bundle(),
            "unknown": "x",
        }
        with pytest.raises(ValidationError):
            Stage2InputsArtifact.model_validate(data)

    def test_serialization_roundtrip(self) -> None:
        data = {
            "run_id": "run-001",
            "job_id": "job-001",
            "engagement_id": "12345678-1234-1234-1234-123456789012",
            "target_id": None,
            "bundle": _valid_threat_model_input_bundle(),
        }
        obj = Stage2InputsArtifact.model_validate(data)
        roundtrip = Stage2InputsArtifact.model_validate(obj.model_dump(mode="json"))
        assert roundtrip.run_id == obj.run_id
        assert roundtrip.bundle.engagement_id == obj.bundle.engagement_id
