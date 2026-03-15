import json
from pathlib import Path

import pytest
from app.schemas.ai.common import ReconAiTask, build_task_metadata
from app.schemas.ai.content_similarity_interpretation import (
    ContentSimilarityInterpretationInput,
    ContentSimilarityInterpretationOutput,
)
from pydantic import ValidationError

EXAMPLES_AI_OUTPUTS_DIR = Path(__file__).resolve().parents[2] / "examples" / "ai_outputs"


def test_content_similarity_example_validates() -> None:
    payload = json.loads(
        (EXAMPLES_AI_OUTPUTS_DIR / "content_similarity_interpretation.example.json").read_text(
            encoding="utf-8"
        )
    )
    parsed = ContentSimilarityInterpretationOutput.model_validate(payload)
    assert parsed.clusters


def test_content_similarity_requires_evidence_for_inference() -> None:
    with pytest.raises(ValidationError):
        ContentSimilarityInterpretationOutput.model_validate(
            {
                "summary": "x",
                "clusters": [
                    {
                        "statement_type": "inference",
                        "cluster_id": "cluster-1",
                        "interpretation": "unique_or_small_cluster",
                        "confidence": 0.61,
                        "evidence_refs": [],
                    }
                ],
            }
        )


def test_content_similarity_output_rejects_wrong_statement_type() -> None:
    with pytest.raises(ValidationError):
        ContentSimilarityInterpretationOutput.model_validate(
            {
                "summary": "x",
                "clusters": [
                    {
                        "statement_type": "observation",
                        "cluster_id": "cluster-1",
                        "interpretation": "unique_or_small_cluster",
                        "confidence": 0.61,
                        "evidence_refs": ["content_clusters.csv:cluster-1"],
                    }
                ],
            }
        )


@pytest.mark.parametrize("bad_evidence_ref", ["   ", "bad evidence ref"])
def test_content_similarity_input_rejects_invalid_evidence_ref(
    bad_evidence_ref: str,
) -> None:
    with pytest.raises(ValidationError):
        ContentSimilarityInterpretationInput.model_validate(
            {
                "meta": build_task_metadata(
                    task=ReconAiTask.CONTENT_SIMILARITY_INTERPRETATION,
                    run_id="run-1",
                    job_id="job-1",
                ).model_dump(mode="json"),
                "content_clusters": [
                    {
                        "cluster_id": "content-1",
                        "host": "example.com",
                        "cluster_size": 3,
                        "template_hint": "shared_platform_template",
                        "evidence_ref": bad_evidence_ref,
                    }
                ],
                "redirect_clusters": [
                    {
                        "redirect_cluster_id": "redir-1",
                        "host": "example.com",
                        "redirect_target": "https://example.com/login",
                        "evidence_ref": "redirect_clusters.csv:redir-1",
                    }
                ],
            }
        )


def test_content_similarity_input_rejects_wrong_meta_task() -> None:
    with pytest.raises(ValidationError):
        ContentSimilarityInterpretationInput.model_validate(
            {
                "meta": build_task_metadata(
                    task=ReconAiTask.ANOMALY_INTERPRETATION,
                    run_id="run-1",
                    job_id="job-1",
                ).model_dump(mode="json"),
                "content_clusters": [
                    {
                        "cluster_id": "content-1",
                        "host": "example.com",
                        "cluster_size": 3,
                        "template_hint": "shared_platform_template",
                        "evidence_ref": "content_clusters.csv:content-1",
                    }
                ],
                "redirect_clusters": [],
            }
        )
