import json
from pathlib import Path

import pytest
from app.schemas.ai.common import ReconAiTask, build_task_metadata
from app.schemas.ai.schema_export import to_report_notes
from app.schemas.ai.stage3_preparation_summary import (
    Stage3NextStep,
    Stage3PreparationSummaryInput,
    Stage3PreparationSummaryOutput,
    build_stage3_next_step,
)
from app.schemas.recon.stage3_readiness import CoverageScores, Stage3ReadinessResult
from pydantic import ValidationError

EXAMPLES_AI_OUTPUTS_DIR = Path(__file__).resolve().parents[2] / "examples" / "ai_outputs"


def test_stage3_preparation_example_validates() -> None:
    payload = json.loads(
        (EXAMPLES_AI_OUTPUTS_DIR / "stage3_preparation_summary.example.json").read_text(
            encoding="utf-8"
        )
    )
    parsed = Stage3PreparationSummaryOutput.model_validate(payload)
    assert parsed.next_steps


def test_stage3_preparation_priority_enum_enforced() -> None:
    with pytest.raises(ValidationError):
        Stage3PreparationSummaryOutput.model_validate(
            {
                "summary": "x",
                "next_steps": [
                    {
                        "statement_type": "hypothesis",
                        "step": "do",
                        "priority": "urgent",
                        "confidence": 0.4,
                        "evidence_refs": ["stage3_readiness.json"],
                    }
                ],
            }
        )


def test_stage3_preparation_input_requires_stage3_readiness() -> None:
    with pytest.raises(ValidationError):
        Stage3PreparationSummaryInput.model_validate(
            {
                "meta": build_task_metadata(
                    task=ReconAiTask.STAGE3_PREPARATION_SUMMARY,
                    run_id="run-1",
                    job_id="job-1",
                ).model_dump(mode="json"),
                "focus_hosts": ["example.com"],
                "risk_hypotheses": ["platform_alias"],
            }
        )


def test_stage3_preparation_input_accepts_valid_stage3_readiness() -> None:
    stage3_readiness = Stage3ReadinessResult(
        status="partially_ready_for_stage3",
        coverage_scores=CoverageScores(route=0.5, input_surface=0.5, api_surface=0.5),
    )
    parsed = Stage3PreparationSummaryInput.model_validate(
        {
            "meta": build_task_metadata(
                task=ReconAiTask.STAGE3_PREPARATION_SUMMARY,
                run_id="run-1",
                job_id="job-1",
            ).model_dump(mode="json"),
            "focus_hosts": ["example.com"],
            "risk_hypotheses": ["platform_alias"],
            "stage3_readiness": stage3_readiness.model_dump(mode="json"),
        }
    )
    assert parsed.stage3_readiness.status == "partially_ready_for_stage3"


def test_stage3_preparation_input_rejects_wrong_meta_task() -> None:
    with pytest.raises(ValidationError):
        Stage3PreparationSummaryInput.model_validate(
            {
                "meta": build_task_metadata(
                    task=ReconAiTask.HEADERS_TLS_SUMMARY,
                    run_id="run-1",
                    job_id="job-1",
                ).model_dump(mode="json"),
                "focus_hosts": ["example.com"],
                "risk_hypotheses": ["platform_alias"],
                "stage3_readiness": {
                    "status": "partially_ready_for_stage3",
                    "coverage_scores": {"route": 0.5, "input_surface": 0.5, "api_surface": 0.5},
                },
            }
        )


def test_stage3_preparation_output_enforces_hypothesis_statement_type() -> None:
    with pytest.raises(ValidationError):
        Stage3PreparationSummaryOutput.model_validate(
            {
                "summary": "x",
                "next_steps": [
                    {
                        "statement_type": "observation",
                        "step": "Address missing evidence",
                        "priority": "high",
                        "confidence": 0.6,
                        "evidence_refs": ["stage3_readiness.json"],
                    }
                ],
            }
        )


def test_stage3_preparation_hypothesis_requires_evidence_refs() -> None:
    with pytest.raises(ValidationError):
        Stage3PreparationSummaryOutput.model_validate(
            {
                "summary": "x",
                "next_steps": [
                    {
                        "statement_type": "hypothesis",
                        "step": "Address missing evidence",
                        "priority": "high",
                        "confidence": 0.6,
                        "evidence_refs": [],
                    }
                ],
            }
        )


def test_to_report_notes_supports_stage3_task() -> None:
    stage3_notes = to_report_notes(
        "stage3_preparation_summary",
        {
            "summary": "x",
            "next_steps": [
                {"priority": "high", "step": "Address missing evidence gaps"},
            ],
        },
    )
    assert stage3_notes
    assert stage3_notes[0]["section_id"] == "section-17-stage-3-readiness"
    assert "Address missing evidence gaps" in stage3_notes[0]["note"]


def test_build_stage3_next_step_creates_valid_step() -> None:
    """REC-011: build_stage3_next_step helper creates valid Stage3NextStep."""
    step = build_stage3_next_step(
        step="Validate route classification for auth flows",
        priority="high",
        evidence_refs=["route_classification.csv", "stage3_readiness.json"],
    )
    assert isinstance(step, Stage3NextStep)
    assert step.step == "Validate route classification for auth flows"
    assert step.priority == "high"
    assert step.evidence_refs == ["route_classification.csv", "stage3_readiness.json"]
    assert step.statement_type == "hypothesis"


def test_stage3_preparation_input_bundle_validates_with_stage3_readiness() -> None:
    """REC-011: Stage3PreparationSummaryInput accepts stage3_readiness from build output."""
    stage3_readiness = Stage3ReadinessResult(
        status="partially_ready_for_stage3",
        missing_evidence=["params_inventory.csv"],
        unknowns=[],
        recommended_follow_up=["Expand route discovery"],
        coverage_scores=CoverageScores(
            route=0.5,
            input_surface=0.3,
            api_surface=0.6,
            content_anomaly=0.4,
            boundary_mapping=0.0,
        ),
    )
    input_payload = {
        "meta": build_task_metadata(
            task=ReconAiTask.STAGE3_PREPARATION_SUMMARY,
            run_id="run-1",
            job_id="job-1",
        ).model_dump(mode="json"),
        "focus_hosts": ["example.com"],
        "risk_hypotheses": ["platform_alias"],
        "stage3_readiness": stage3_readiness.model_dump(mode="json"),
    }
    parsed = Stage3PreparationSummaryInput.model_validate(input_payload)
    assert parsed.stage3_readiness.status == "partially_ready_for_stage3"
    assert parsed.stage3_readiness.coverage_scores.route == 0.5
    assert "params_inventory.csv" in parsed.stage3_readiness.missing_evidence


def test_stage3_preparation_output_next_steps_require_evidence_refs() -> None:
    """REC-011: Stage3PreparationSummaryOutput next_steps must have non-empty evidence_refs."""
    valid_output = Stage3PreparationSummaryOutput.model_validate(
        {
            "summary": "Stage 3 readiness assessment complete.",
            "next_steps": [
                {
                    "statement_type": "hypothesis",
                    "step": "Address missing evidence",
                    "priority": "high",
                    "confidence": 0.8,
                    "evidence_refs": ["stage3_readiness.json"],
                },
            ],
        }
    )
    assert len(valid_output.next_steps) == 1
    assert valid_output.next_steps[0].evidence_refs == ["stage3_readiness.json"]
