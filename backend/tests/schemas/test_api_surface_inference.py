import json
from pathlib import Path

import pytest
from app.schemas.ai.api_surface_inference import ApiSurfaceInferenceInput, ApiSurfaceInferenceOutput
from app.schemas.ai.common import ReconAiTask, build_task_metadata
from pydantic import ValidationError

EXAMPLES_AI_OUTPUTS_DIR = Path(__file__).resolve().parents[2] / "examples" / "ai_outputs"


def test_api_surface_example_validates() -> None:
    payload = json.loads(
        (EXAMPLES_AI_OUTPUTS_DIR / "api_surface_inference.example.json").read_text(
            encoding="utf-8"
        )
    )
    parsed = ApiSurfaceInferenceOutput.model_validate(payload)
    assert parsed.api_surface


def test_api_surface_enum_enforced() -> None:
    with pytest.raises(ValidationError):
        ApiSurfaceInferenceOutput.model_validate(
            {
                "api_surface": [
                    {
                        "statement_type": "inference",
                        "path": "/api/bad",
                        "api_type": "rpc",
                        "auth_boundary_hint": "unknown",
                        "confidence": 0.5,
                        "evidence_refs": ["api_surface.csv"],
                    }
                ]
            }
        )


def test_api_surface_output_rejects_wrong_statement_type() -> None:
    with pytest.raises(ValidationError):
        ApiSurfaceInferenceOutput.model_validate(
            {
                "api_surface": [
                    {
                        "statement_type": "observation",
                        "path": "/api/v1/users",
                        "api_type": "rest_like",
                        "auth_boundary_hint": "frontend_to_backend",
                        "confidence": 0.5,
                        "evidence_refs": ["api_surface.csv:/api/v1/users"],
                    }
                ]
            }
        )


def test_api_surface_input_rejects_wrong_meta_task() -> None:
    with pytest.raises(ValidationError):
        ApiSurfaceInferenceInput.model_validate(
            {
                "meta": build_task_metadata(
                    task=ReconAiTask.HEADERS_TLS_SUMMARY,
                    run_id="run-1",
                    job_id="job-1",
                ).model_dump(mode="json"),
                "api_candidates": [
                    {
                        "path": "/api/v1/users",
                        "source": "route_inventory",
                        "method_hint": "GET",
                        "evidence_refs": ["api_surface.csv:/api/v1/users"],
                    }
                ],
            }
        )
