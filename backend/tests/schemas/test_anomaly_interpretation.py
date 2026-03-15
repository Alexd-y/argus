import json
from pathlib import Path

import pytest
from app.schemas.ai.anomaly_interpretation import (
    AnomalyInterpretationInput,
    AnomalyInterpretationOutput,
)
from app.schemas.ai.common import ReconAiTask, build_task_metadata
from pydantic import ValidationError

EXAMPLES_AI_OUTPUTS_DIR = Path(__file__).resolve().parents[2] / "examples" / "ai_outputs"


def test_anomaly_example_validates() -> None:
    payload = json.loads(
        (EXAMPLES_AI_OUTPUTS_DIR / "anomaly_interpretation.example.json").read_text(
            encoding="utf-8"
        )
    )
    parsed = AnomalyInterpretationOutput.model_validate(payload)
    assert parsed.anomalies


def test_anomaly_classification_enum_enforced() -> None:
    with pytest.raises(ValidationError):
        AnomalyInterpretationOutput.model_validate(
            {
                "anomalies": [
                    {
                        "statement_type": "hypothesis",
                        "host": "x.example.com",
                        "classification": "unknown_class",
                        "confidence": 0.5,
                        "recommendation": "review",
                        "evidence_refs": ["anomaly_validation.md"],
                    }
                ]
            }
        )


def test_anomaly_input_rejects_wrong_meta_task() -> None:
    with pytest.raises(ValidationError):
        AnomalyInterpretationInput.model_validate(
            {
                "meta": build_task_metadata(
                    task=ReconAiTask.CONTENT_SIMILARITY_INTERPRETATION,
                    run_id="run-1",
                    job_id="job-1",
                ).model_dump(mode="json"),
                "anomalies": [
                    {
                        "host": "x.example.com",
                        "status": "404",
                        "suspicious_host": True,
                        "catch_all_hint": False,
                        "shared_with_root": False,
                        "evidence_refs": ["content_clusters.csv:x.example.com"],
                    }
                ],
            }
        )


def test_anomaly_output_enforces_hypothesis_statement_type() -> None:
    with pytest.raises(ValidationError):
        AnomalyInterpretationOutput.model_validate(
            {
                "anomalies": [
                    {
                        "statement_type": "observation",
                        "host": "x.example.com",
                        "classification": "catch_all",
                        "confidence": 0.5,
                        "recommendation": "review",
                        "evidence_refs": ["anomaly_validation.md"],
                    }
                ]
            }
        )


def test_anomaly_hypothesis_requires_evidence_refs() -> None:
    with pytest.raises(ValidationError):
        AnomalyInterpretationOutput.model_validate(
            {
                "anomalies": [
                    {
                        "statement_type": "hypothesis",
                        "host": "x.example.com",
                        "classification": "catch_all",
                        "confidence": 0.5,
                        "recommendation": "review",
                        "evidence_refs": [],
                    }
                ]
            }
        )
