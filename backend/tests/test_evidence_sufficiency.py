"""Unit tests for Evidence Sufficiency Evaluator (VA3UP-002)."""

from __future__ import annotations

import pytest

from app.schemas.vulnerability_analysis.evidence_sufficiency import (
    EvidenceSufficiencyThresholdConfig,
    FindingSufficiencyDetail,
    SufficiencyStatus,
)
from src.recon.vulnerability_analysis.evidence_sufficiency import evaluate_evidence_sufficiency


def test_evaluate_empty_ai_results() -> None:
    """No findings when ai_results is empty."""
    result = evaluate_evidence_sufficiency({}, "run1", "job1")
    assert result.run_id == "run1"
    assert result.job_id == "job1"
    assert len(result.findings) == 0
    assert result.summary["total_findings"] == 0


def test_evaluate_sufficient_finding() -> None:
    """Finding with enough evidence, diversity, and confidence is sufficient."""
    ai = {
        "authorization_analysis": {
            "checks": [
                {
                    "target_id": "ep_1",
                    "evidence_refs": ["artifact:stage1_a", "recon:stage2_b", "section:s3"],
                    "confidence": 0.85,
                    "statement_type": "evidence",
                },
            ],
        },
    }
    result = evaluate_evidence_sufficiency(
        ai, "r1", "j1", artifact_refs=["artifact:stage1_a", "recon:stage2_b"]
    )
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.finding_id == "ep_1"
    assert f.sufficiency_status == SufficiencyStatus.SUFFICIENT
    assert f.evidence_count == 3
    assert f.source_count >= 2
    assert f.deficiencies == []


def test_evaluate_insufficient_finding() -> None:
    """Finding with no evidence and low confidence is insufficient."""
    ai = {
        "authorization_analysis": {
            "checks": [
                {"target_id": "ep_2", "evidence_refs": [], "confidence": 0.2},
            ],
        },
    }
    result = evaluate_evidence_sufficiency(ai, "r1", "j1")
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.finding_id == "ep_2"
    assert f.sufficiency_status == SufficiencyStatus.INSUFFICIENT
    assert any("evidence_count_below_min" in d for d in f.deficiencies) or any(
        "confidence_below_min" in d for d in f.deficiencies
    )


def test_evaluate_contradiction_penalty() -> None:
    """Contradictions reduce confidence and add deficiency."""
    ai = {
        "authorization_analysis": {
            "checks": [
                {
                    "target_id": "ep_3",
                    "evidence_refs": ["a:1", "b:2"],
                    "confidence": 0.9,
                },
            ],
        },
    }
    result = evaluate_evidence_sufficiency(
        ai, "r1", "j1", contradiction_map={"ep_3": True}
    )
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.has_contradictions is True
    assert "has_contradictions" in f.deficiencies


def test_evaluate_source_diversity() -> None:
    """Single source fails diversity check."""
    config = EvidenceSufficiencyThresholdConfig(min_source_diversity=2)
    ai = {
        "authorization_analysis": {
            "checks": [
                {
                    "target_id": "ep_4",
                    "evidence_refs": ["artifact:x", "artifact:y"],
                    "confidence": 0.8,
                },
            ],
        },
    }
    result = evaluate_evidence_sufficiency(ai, "r1", "j1", config=config)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.source_count == 1
    assert any("source_diversity_below_min" in d for d in f.deficiencies)


def test_evaluate_finding_correlation() -> None:
    """Correlations from finding_correlation task are extracted."""
    ai = {
        "finding_correlation": {
            "correlations": [
                {
                    "finding_ids": ["f1", "f2"],
                    "link_type": "related",
                    "evidence_refs": ["a:1", "b:2"],
                },
            ],
        },
    }
    result = evaluate_evidence_sufficiency(ai, "r1", "j1")
    assert len(result.findings) == 1
    assert result.findings[0].finding_id == "f1|f2"


def test_evaluate_to_json_dict() -> None:
    """Result serializes to JSON."""
    ai = {"authorization_analysis": {"checks": [{"target_id": "x", "evidence_refs": ["a"], "confidence": 0.5}]}}
    result = evaluate_evidence_sufficiency(ai, "r1", "j1")
    d = result.to_json_dict()
    assert "run_id" in d
    assert "findings" in d
    assert "threshold_config" in d
