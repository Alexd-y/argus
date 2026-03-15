import json
from pathlib import Path

import pytest
from app.schemas.ai.common import ReconAiTask, build_task_metadata
from app.schemas.ai.parameter_input_analysis import (
    ParameterInputAnalysisInput,
    ParameterInputAnalysisOutput,
)
from pydantic import ValidationError

EXAMPLES_AI_OUTPUTS_DIR = Path(__file__).resolve().parents[2] / "examples" / "ai_outputs"


def test_parameter_input_example_validates() -> None:
    payload = json.loads(
        (EXAMPLES_AI_OUTPUTS_DIR / "parameter_input_analysis.example.json").read_text(
            encoding="utf-8"
        )
    )
    parsed = ParameterInputAnalysisOutput.model_validate(payload)
    assert parsed.params


def test_parameter_input_confidence_range_enforced() -> None:
    with pytest.raises(ValidationError):
        ParameterInputAnalysisOutput.model_validate(
            {
                "params": [
                    {
                        "statement_type": "observation",
                        "name": "id",
                        "category": "id_state",
                        "context_url": "https://example.com/user/1",
                        "confidence": 2.0,
                        "evidence_refs": ["route_inventory.csv"],
                    }
                ]
            }
        )


def test_parameter_input_output_rejects_wrong_statement_type() -> None:
    with pytest.raises(ValidationError):
        ParameterInputAnalysisOutput.model_validate(
            {
                "params": [
                    {
                        "statement_type": "inference",
                        "name": "id",
                        "category": "id_state",
                        "context_url": "https://example.com/user/1",
                        "confidence": 0.7,
                        "evidence_refs": ["route_inventory.csv:https://example.com/user/1"],
                    }
                ]
            }
        )


def test_parameter_input_rejects_wrong_meta_task() -> None:
    with pytest.raises(ValidationError):
        ParameterInputAnalysisInput.model_validate(
            {
                "meta": build_task_metadata(
                    task=ReconAiTask.API_SURFACE_INFERENCE,
                    run_id="run-1",
                    job_id="job-1",
                ).model_dump(mode="json"),
                "params": [
                    {
                        "name": "redirect",
                        "source": "query",
                        "context_url": "https://example.com/?redirect=/home",
                        "evidence_refs": ["route_inventory.csv:https://example.com/?redirect=/home"],
                    }
                ],
            }
        )
