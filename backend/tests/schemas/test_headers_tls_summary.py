import json
from pathlib import Path

import pytest
from app.schemas.ai.common import ReconAiTask, build_task_metadata
from app.schemas.ai.headers_tls_summary import HeadersTlsSummaryInput, HeadersTlsSummaryOutput
from pydantic import ValidationError

EXAMPLES_AI_OUTPUTS_DIR = Path(__file__).resolve().parents[2] / "examples" / "ai_outputs"


def test_headers_tls_example_validates() -> None:
    payload = json.loads(
        (EXAMPLES_AI_OUTPUTS_DIR / "headers_tls_summary.example.json").read_text(
            encoding="utf-8"
        )
    )
    parsed = HeadersTlsSummaryOutput.model_validate(payload)
    assert parsed.controls


def test_headers_tls_requires_known_posture() -> None:
    with pytest.raises(ValidationError):
        HeadersTlsSummaryOutput.model_validate(
            {
                "summary": "x",
                "controls": [
                    {
                        "statement_type": "observation",
                        "host": "https://example.com",
                        "posture": "excellent",
                        "confidence": 0.5,
                        "evidence_refs": ["headers_detailed.csv:https://example.com"],
                    }
                ],
            }
        )


def test_headers_tls_output_rejects_wrong_statement_type() -> None:
    with pytest.raises(ValidationError):
        HeadersTlsSummaryOutput.model_validate(
            {
                "summary": "x",
                "controls": [
                    {
                        "statement_type": "inference",
                        "host": "https://example.com",
                        "posture": "moderate",
                        "confidence": 0.5,
                        "evidence_refs": ["headers_detailed.csv:https://example.com"],
                    }
                ],
            }
        )


def test_headers_tls_input_rejects_wrong_meta_task() -> None:
    with pytest.raises(ValidationError):
        HeadersTlsSummaryInput.model_validate(
            {
                "meta": build_task_metadata(
                    task=ReconAiTask.JS_FINDINGS_ANALYSIS,
                    run_id="run-1",
                    job_id="job-1",
                ).model_dump(mode="json"),
                "hosts": [
                    {
                        "host": "https://example.com",
                        "header_score": "5",
                        "cookie_count": "1",
                        "cookie_secure": "1",
                        "evidence_refs": ["headers_detailed.csv:https://example.com"],
                    }
                ],
            }
        )
