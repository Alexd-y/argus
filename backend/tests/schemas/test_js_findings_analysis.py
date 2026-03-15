import json
from pathlib import Path

import pytest
from app.schemas.ai.common import ReconAiTask, build_task_metadata
from app.schemas.ai.js_findings_analysis import JsFindingsAnalysisInput, JsFindingsAnalysisOutput
from pydantic import ValidationError

EXAMPLES_AI_OUTPUTS_DIR = Path(__file__).resolve().parents[2] / "examples" / "ai_outputs"


def test_js_findings_example_validates() -> None:
    payload = json.loads(
        (EXAMPLES_AI_OUTPUTS_DIR / "js_findings_analysis.example.json").read_text(encoding="utf-8")
    )
    parsed = JsFindingsAnalysisOutput.model_validate(payload)
    assert parsed.findings


def test_js_findings_requires_evidence_for_observation() -> None:
    with pytest.raises(ValidationError):
        JsFindingsAnalysisOutput.model_validate(
            {
                "summary": "x",
                "findings": [
                    {
                        "statement_type": "observation",
                        "category": "api_ref",
                        "value": "/api/v1/users",
                        "confidence": 0.5,
                        "evidence_refs": [],
                    }
                ],
            }
        )


def test_js_findings_output_rejects_wrong_statement_type() -> None:
    with pytest.raises(ValidationError):
        JsFindingsAnalysisOutput.model_validate(
            {
                "summary": "x",
                "findings": [
                    {
                        "statement_type": "inference",
                        "category": "api_ref",
                        "value": "/api/v1/users",
                        "confidence": 0.5,
                        "evidence_refs": ["js:app.js"],
                    }
                ],
            }
        )


def test_js_findings_input_rejects_wrong_meta_task() -> None:
    with pytest.raises(ValidationError):
        JsFindingsAnalysisInput.model_validate(
            {
                "meta": build_task_metadata(
                    task=ReconAiTask.PARAMETER_INPUT_ANALYSIS,
                    run_id="run-1",
                    job_id="job-1",
                ).model_dump(mode="json"),
                "script_findings": [
                    {
                        "category": "api_ref",
                        "value": "/api/v1/users",
                        "evidence_refs": ["js:app.js"],
                    }
                ],
            }
        )


def test_js_findings_input_rejects_broken_run_linkage() -> None:
    with pytest.raises(ValidationError):
        JsFindingsAnalysisInput.model_validate(
            {
                "meta": {
                    "task": "js_findings_analysis",
                    "run_id": "run-1",
                    "job_id": "job-1",
                    "run_link": "recon://runs/another",
                    "job_link": "recon://jobs/job-1",
                    "trace_id": "run-1:job-1:js_findings_analysis",
                },
                "script_findings": [
                    {
                        "category": "api_ref",
                        "value": "/api/v1/users",
                        "evidence_refs": ["js:app.js"],
                    }
                ],
            }
        )
