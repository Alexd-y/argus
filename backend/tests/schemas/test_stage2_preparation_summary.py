import json
from pathlib import Path

import pytest
from app.schemas.ai.common import ReconAiTask, build_task_metadata
from app.schemas.ai.schema_export import to_report_notes
from app.schemas.ai.stage2_preparation_summary import (
    Stage2PreparationSummaryInput,
    Stage2PreparationSummaryOutput,
)
from pydantic import ValidationError

EXAMPLES_AI_OUTPUTS_DIR = Path(__file__).resolve().parents[2] / "examples" / "ai_outputs"


def test_stage2_preparation_example_validates() -> None:
    payload = json.loads(
        (EXAMPLES_AI_OUTPUTS_DIR / "stage2_preparation_summary.example.json").read_text(
            encoding="utf-8"
        )
    )
    parsed = Stage2PreparationSummaryOutput.model_validate(payload)
    assert parsed.next_steps


def test_stage2_preparation_priority_enum_enforced() -> None:
    with pytest.raises(ValidationError):
        Stage2PreparationSummaryOutput.model_validate(
            {
                "summary": "x",
                "next_steps": [
                    {
                        "statement_type": "hypothesis",
                        "step": "do",
                        "priority": "urgent",
                        "confidence": 0.4,
                        "evidence_refs": ["stage2_inputs.md"],
                    }
                ],
            }
        )


def test_stage2_preparation_input_rejects_wrong_meta_task() -> None:
    with pytest.raises(ValidationError):
        Stage2PreparationSummaryInput.model_validate(
            {
                "meta": build_task_metadata(
                    task=ReconAiTask.HEADERS_TLS_SUMMARY,
                    run_id="run-1",
                    job_id="job-1",
                ).model_dump(mode="json"),
                "focus_hosts": ["example.com"],
                "risk_hypotheses": ["platform_alias"],
            }
        )


def test_stage2_preparation_output_enforces_hypothesis_statement_type() -> None:
    with pytest.raises(ValidationError):
        Stage2PreparationSummaryOutput.model_validate(
            {
                "summary": "x",
                "next_steps": [
                    {
                        "statement_type": "observation",
                        "step": "Validate host ownership",
                        "priority": "high",
                        "confidence": 0.6,
                        "evidence_refs": ["stage2_inputs.md"],
                    }
                ],
            }
        )


def test_stage2_preparation_hypothesis_requires_evidence_refs() -> None:
    with pytest.raises(ValidationError):
        Stage2PreparationSummaryOutput.model_validate(
            {
                "summary": "x",
                "next_steps": [
                    {
                        "statement_type": "hypothesis",
                        "step": "Validate host ownership",
                        "priority": "high",
                        "confidence": 0.6,
                        "evidence_refs": [],
                    }
                ],
            }
        )


def test_to_report_notes_supports_stage2_and_api_tasks() -> None:
    stage2_notes = to_report_notes(
        "stage2_preparation_summary",
        {
            "summary": "x",
            "next_steps": [
                {"priority": "high", "step": "Validate host ownership"},
            ],
        },
    )
    assert stage2_notes
    assert stage2_notes[0]["section_id"] == "section-14-stage-2-preparation"
    assert "Validate host ownership" in stage2_notes[0]["note"]

    api_notes = to_report_notes(
        "api_surface_inference",
        {
            "api_surface": [
                {
                    "path": "/api/v1/users",
                    "api_type": "rest_like",
                    "auth_boundary_hint": "frontend_to_backend",
                }
            ]
        },
    )
    assert api_notes
    assert api_notes[0]["section_id"] == "section-10-api-surface-mapping"
    assert "/api/v1/users" in api_notes[0]["note"]
