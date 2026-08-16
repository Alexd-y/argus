"""WIRE-006 — FindingDTO lifecycle bridge is append-only (AI cannot delete)."""

from __future__ import annotations

import json
import logging
from uuid import uuid4

import pytest
from src.capabilities.schemas import CoverageStatus
from src.findings.diff import DiffStatus, diff_occurrence
from src.findings.lifecycle import (
    FindingAssessment,
    FindingLifecycleService,
    FindingState,
)
from src.findings.lifecycle_bridge import (
    FindingIngestContext,
    FindingLifecycleBridge,
    retain_findings_despite_ai_classification,
)
from src.findings.normalizer import Normalizer, ParseStrategy
from src.findings.retest import RetestJob, RetestResultKind
from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    FindingStatus,
)


def _dto(**overrides: object) -> FindingDTO:
    kwargs: dict[str, object] = {
        "id": uuid4(),
        "tenant_id": uuid4(),
        "scan_id": uuid4(),
        "asset_id": uuid4(),
        "tool_run_id": uuid4(),
        "category": FindingCategory.XSS,
        "cwe": [79],
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_v3_score": 6.1,
        "confidence": ConfidenceLevel.SUSPECTED,
        "status": FindingStatus.NEW,
        "evidence_ids": [uuid4(), uuid4()],
    }
    kwargs.update(overrides)
    return FindingDTO(**kwargs)  # type: ignore[arg-type]


def _context(dto: FindingDTO, *, request_signature: str = "GET /search?q=1") -> FindingIngestContext:
    return FindingIngestContext(
        engagement_id=str(dto.scan_id),
        asset="https://app.example",
        location="/search",
        parameter_or_component="q",
        root_cause_family="reflected_input",
        scanner="nuclei",
        detector_id="xss-reflected",
        detector_version="1.0.0",
        request_signature=request_signature,
        evidence={"payload": "<script>"},
        title="Reflected XSS",
        evidence_refs=tuple(str(eid) for eid in dto.evidence_ids),
    )


def test_ingest_creates_logical_finding_and_occurrence() -> None:
    bridge = FindingLifecycleBridge()
    dto = _dto()
    bridged = bridge.ingest_dto(dto, context=_context(dto))

    assert bridged.finding.state is FindingState.CANDIDATE
    assert len(bridged.finding.occurrence_keys) == 1
    assert bridged.occurrence.finding_key == bridged.finding.finding_key
    assert len(bridged.occurrence.occurrence_key) == 64
    assert len(bridged.finding.finding_key) == 64
    assert len(bridged.finding.evidence_refs) >= 2
    assert diff_occurrence(None, bridged.occurrence) is DiffStatus.NEW


def test_ai_assessment_does_not_reduce_occurrence_count_or_evidence_refs() -> None:
    bridge = FindingLifecycleBridge()
    dto = _dto()
    first = bridge.ingest_dto(dto, context=_context(dto, request_signature="sig-a"))
    second = bridge.ingest_dto(dto, context=_context(dto, request_signature="sig-b"))
    finding = second.finding

    occ_before = list(finding.occurrence_keys)
    evidence_before = list(finding.evidence_refs)
    assert len(occ_before) == 2
    assert len(evidence_before) >= 2

    bridge.attach_assessment(
        finding,
        FindingAssessment(
            finding_key=finding.finding_key,
            tenant_id=finding.tenant_id,
            classification="contradicted",
            observation="response does not reflect payload",
            inference="likely false positive",
            evidence_refs=(),
            confidence=0.4,
        ),
    )

    assert finding.state is FindingState.AI_REVIEWED
    assert len(finding.assessments) == 1
    assert finding.occurrence_keys == occ_before
    assert finding.evidence_refs == evidence_before
    assert first.occurrence.occurrence_key in finding.occurrence_keys
    assert second.occurrence.occurrence_key in finding.occurrence_keys


def test_delete_via_assessment_is_ignored(caplog) -> None:
    bridge = FindingLifecycleBridge()
    dto = _dto()
    bridged = bridge.ingest_dto(dto, context=_context(dto))
    finding = bridged.finding
    occ_before = list(finding.occurrence_keys)
    evidence_before = list(finding.evidence_refs)

    with caplog.at_level(logging.WARNING):
        bridge.attach_assessment(
            finding,
            FindingAssessment(
                finding_key=finding.finding_key,
                tenant_id=finding.tenant_id,
                classification="delete",
                observation="drop this finding",
                rationale="AI requested deletion",
            ),
        )

    assert finding.finding_key in bridge.findings
    assert len(finding.assessments) == 1
    assert finding.assessments[0].classification == "delete"
    assert len(finding.occurrence_keys) == len(occ_before)
    assert finding.occurrence_keys == occ_before
    assert finding.evidence_refs == evidence_before
    assert any("finding_delete_via_assessment_ignored" in rec.message for rec in caplog.records)

    service = FindingLifecycleService()
    with pytest.raises(RuntimeError, match="finding_deletion_forbidden"):
        service.delete_finding(finding)
    assert finding.finding_key in bridge.findings
    assert finding.occurrence_keys == occ_before


def test_contradicted_classification_does_not_drop_report_findings() -> None:
    rows = [
        {"title": "XSS", "classification": "contradicted", "evidence_refs": ["e1"]},
        {"title": "SQLi", "ai_classification": "supported", "evidence_refs": ["e2"]},
        {"title": "Open redirect", "classification": "insufficient"},
    ]
    retained = retain_findings_despite_ai_classification(rows)
    assert retained == rows
    assert len(retained) == 3


def test_diff_new_resolved_candidate_resolved_regressed() -> None:
    bridge = FindingLifecycleBridge()
    dto = _dto()
    bridged = bridge.ingest_dto(dto, context=_context(dto))
    finding = bridged.finding
    occurrence = bridged.occurrence

    assert diff_occurrence(None, occurrence) is DiffStatus.NEW

    finding = bridge.mark_resolved_candidate(finding, coverage_equivalent=True)
    assert finding.state is FindingState.RESOLVED_CANDIDATE
    assert (
        diff_occurrence(
            occurrence,
            None,
            current_state=finding.state,
            coverage_status=CoverageStatus.COVERED_NO_FINDING,
        )
        is DiffStatus.RESOLVED_CANDIDATE
    )

    finding, _job = bridge.apply_retest(
        finding,
        RetestJob(
            finding_key=finding.finding_key,
            tenant_id=finding.tenant_id,
            engagement_id=finding.engagement_id,
            coverage_equivalent=True,
            result=RetestResultKind.NOT_REPRODUCED,
        ),
    )
    assert finding.state is FindingState.RESOLVED
    assert (
        diff_occurrence(
            occurrence,
            None,
            current_state=finding.state,
            coverage_status=CoverageStatus.COVERED_NO_FINDING,
        )
        is DiffStatus.RESOLVED
    )

    finding, _job = bridge.apply_retest(
        finding,
        RetestJob(
            finding_key=finding.finding_key,
            tenant_id=finding.tenant_id,
            engagement_id=finding.engagement_id,
            coverage_equivalent=True,
            result=RetestResultKind.STILL_PRESENT,
        ),
    )
    assert finding.state is FindingState.REGRESSED
    assert (
        diff_occurrence(
            occurrence,
            occurrence,
            current_state=finding.state,
            coverage_status=CoverageStatus.COVERED_WITH_FINDING,
        )
        is DiffStatus.REGRESSED
    )


def test_normalizer_keeps_dto_path_and_bridges_lifecycle() -> None:
    bridge = FindingLifecycleBridge()
    normalizer = Normalizer(lifecycle_bridge=bridge)
    dtos = normalizer.normalize(
        tool_run_id=uuid4(),
        tool_id="nuclei",
        tenant_id=uuid4(),
        scan_id=uuid4(),
        asset_id=uuid4(),
        raw_output=json.dumps(
            {
                "title": "Reflected XSS in search",
                "category": "xss",
                "severity": "high",
                "url": "https://app.example/search?q=1",
                "parameter": "q",
                "description": "Reflected cross-site scripting in the search parameter.",
            }
        ).encode("utf-8"),
        parse_strategy=ParseStrategy.JSON_OBJECT,
    )

    assert len(dtos) == 1
    assert isinstance(dtos[0], FindingDTO)
    assert len(bridge.findings) == 1
    logical = next(iter(bridge.findings.values()))
    assert logical.occurrence_keys
    assert logical.category == FindingCategory.XSS.value
    occs = next(iter(bridge.occurrences.values()))
    assert len(occs) == 1
    assert occs[0].evidence_refs
