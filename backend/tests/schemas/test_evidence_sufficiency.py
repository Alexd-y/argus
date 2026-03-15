"""Unit tests for evidence_sufficiency schemas (VA3UP-002)."""

from __future__ import annotations

import pytest

from app.schemas.vulnerability_analysis.evidence_sufficiency import (
    EvidenceSufficiencyResult,
    EvidenceSufficiencyThresholdConfig,
    FindingSufficiencyDetail,
    SufficiencyStatus,
)


def test_threshold_config_defaults() -> None:
    """Threshold config has sensible defaults."""
    cfg = EvidenceSufficiencyThresholdConfig()
    assert cfg.min_evidence_count == 2
    assert cfg.min_source_diversity == 2
    assert cfg.min_directness_score == 0.3
    assert cfg.min_linkage_quality == 0.5
    assert cfg.min_confidence == 0.6
    assert cfg.contradiction_penalty == 0.3


def test_finding_sufficiency_detail() -> None:
    """FindingSufficiencyDetail validates correctly."""
    d = FindingSufficiencyDetail(
        finding_id="ep_1",
        evidence_count=3,
        source_count=2,
        directness_score=0.8,
        linkage_quality=0.9,
        confidence=0.85,
        has_contradictions=False,
        sufficiency_status=SufficiencyStatus.SUFFICIENT,
        deficiencies=[],
        sources_summary={"artifact": 2, "recon": 1},
    )
    assert d.finding_id == "ep_1"
    assert d.sufficiency_status == SufficiencyStatus.SUFFICIENT
    assert d.model_dump()


def test_evidence_sufficiency_result() -> None:
    """EvidenceSufficiencyResult serializes to JSON."""
    result = EvidenceSufficiencyResult(
        run_id="r1",
        job_id="j1",
        findings=[
            FindingSufficiencyDetail(
                finding_id="f1",
                evidence_count=2,
                source_count=2,
                directness_score=0.5,
                linkage_quality=0.5,
                confidence=0.7,
                has_contradictions=False,
                sufficiency_status=SufficiencyStatus.SUFFICIENT,
                deficiencies=[],
                sources_summary={},
            ),
        ],
        summary={"total_findings": 1, "sufficient": 1, "partial": 0, "insufficient": 0},
    )
    d = result.to_json_dict()
    assert d["run_id"] == "r1"
    assert d["job_id"] == "j1"
    assert len(d["findings"]) == 1
    assert d["findings"][0]["finding_id"] == "f1"
    assert d["summary"]["total_findings"] == 1


def test_sufficiency_status_values() -> None:
    """SufficiencyStatus has expected values."""
    assert SufficiencyStatus.SUFFICIENT.value == "sufficient"
    assert SufficiencyStatus.PARTIAL.value == "partial"
    assert SufficiencyStatus.INSUFFICIENT.value == "insufficient"
