"""Unit tests for finding lifecycle, diff and retest."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from src.capabilities.schemas import CoverageStatus
from src.findings.diff import DiffStatus, diff_findings, diff_occurrence, occurrence_from_scan
from src.findings.fingerprint import compute_finding_key, compute_occurrence_key
from src.findings.lifecycle import (
    FindingAssessment,
    FindingLifecycle,
    FindingOccurrence,
    FindingState,
    apply_assessment,
)
from src.findings.retest import RetestOutcome, RetestResolutionError, resolve_retest


def _finding_key() -> str:
    return compute_finding_key(
        tenant_id="018f4a2e-7c8b-7b4d-8e0e-6b6579317431",
        engagement_id="018f4a2e-7c8b-7b4d-8e0e-6b6579317432",
        asset="https://app.example",
        category="xss",
        normalized_location="/search",
        parameter_or_component="q",
        root_cause_family="reflected_input",
    )


def _occurrence(*, scan_id: str, request_signature: str) -> FindingOccurrence:
    finding_key = _finding_key()
    now = datetime.now(tz=timezone.utc)
    return occurrence_from_scan(
        finding_key=finding_key,
        tenant_id="018f4a2e-7c8b-7b4d-8e0e-6b6579317431",
        scan_id=scan_id,
        scanner="nuclei",
        detector_id="xss-reflected",
        detector_version="1.0.0",
        request_signature=request_signature,
        evidence={"payload": "<script>"},
        seen_at=now,
    )


def test_finding_and_occurrence_keys_are_stable_sha256():
    finding_key = _finding_key()
    assert len(finding_key) == 64
    occurrence_key = compute_occurrence_key(
        finding_key=finding_key,
        scanner="nuclei",
        detector_id="xss-reflected",
        detector_version="1.0.0",
        request_signature="GET /search?q=1",
        evidence_signal_hash="abc" * 21 + "a",
    )
    assert len(occurrence_key) == 64


def test_assessment_is_additive_and_never_deletes_history():
    lifecycle = FindingLifecycle(
        finding_key=_finding_key(),
        tenant_id="018f4a2e-7c8b-7b4d-8e0e-6b6579317431",
        engagement_id="018f4a2e-7c8b-7b4d-8e0e-6b6579317432",
        state=FindingState.CANDIDATE,
    )
    assessment = FindingAssessment(
        id=str(uuid4()),
        finding_key=lifecycle.finding_key,
        tenant_id=lifecycle.tenant_id,
        assessor="wrb",
        proposed_state=FindingState.MACHINE_VALIDATED,
        confidence=0.9,
        rationale="validated by sandbox replay",
        evidence_refs=("evidence-1",),
    )
    updated = apply_assessment(lifecycle, assessment)
    assert len(updated.assessments) == 1
    assert updated.state is FindingState.MACHINE_VALIDATED


def test_diff_marks_new_unchanged_and_not_tested_without_coverage():
    baseline = _occurrence(scan_id="scan-1", request_signature="sig-a")
    current_same = _occurrence(scan_id="scan-2", request_signature="sig-a")
    current_changed = _occurrence(scan_id="scan-2", request_signature="sig-b")

    assert diff_occurrence(None, current_same) is DiffStatus.NEW
    assert diff_occurrence(baseline, current_same) is DiffStatus.UNCHANGED
    assert diff_occurrence(baseline, current_changed) is DiffStatus.CHANGED
    assert (
        diff_occurrence(
            baseline,
            None,
            coverage_status=CoverageStatus.NOT_TESTED,
        )
        is DiffStatus.NOT_TESTED
    )


def test_diff_resolved_candidate_requires_coverage():
    baseline = _occurrence(scan_id="scan-1", request_signature="sig-a")
    status = diff_occurrence(
        baseline,
        None,
        current_state=FindingState.RESOLVED_CANDIDATE,
        coverage_status=CoverageStatus.COVERED_NO_FINDING,
    )
    assert status is DiffStatus.RESOLVED_CANDIDATE


def test_retest_resolves_only_with_coverage():
    lifecycle = FindingLifecycle(
        finding_key=_finding_key(),
        tenant_id="018f4a2e-7c8b-7b4d-8e0e-6b6579317431",
        engagement_id="018f4a2e-7c8b-7b4d-8e0e-6b6579317432",
        state=FindingState.RESOLVED_CANDIDATE,
    )
    with pytest.raises(RetestResolutionError):
        resolve_retest(
            lifecycle,
            outcome=RetestOutcome.NOT_PRESENT,
            coverage_status=CoverageStatus.NOT_TESTED,
            job_id="job-1",
        )

    result = resolve_retest(
        lifecycle,
        outcome=RetestOutcome.NOT_PRESENT,
        coverage_status=CoverageStatus.COVERED_NO_FINDING,
        job_id="job-1",
    )
    assert result.new_state is FindingState.RESOLVED
    assert result.diff_status is DiffStatus.RESOLVED


def test_retest_reappearance_marks_regressed():
    lifecycle = FindingLifecycle(
        finding_key=_finding_key(),
        tenant_id="018f4a2e-7c8b-7b4d-8e0e-6b6579317431",
        engagement_id="018f4a2e-7c8b-7b4d-8e0e-6b6579317432",
        state=FindingState.RESOLVED_CANDIDATE,
    )
    result = resolve_retest(
        lifecycle,
        outcome=RetestOutcome.STILL_PRESENT,
        coverage_status=CoverageStatus.COVERED_WITH_FINDING,
        job_id="job-2",
    )
    assert result.new_state is FindingState.REGRESSED
    assert result.diff_status is DiffStatus.REGRESSED


def test_diff_findings_across_scans():
    baseline = _occurrence(scan_id="scan-1", request_signature="sig-a")
    current = _occurrence(scan_id="scan-2", request_signature="sig-a")
    diffs = diff_findings(
        baseline_occurrences=[baseline],
        current_occurrences=[current],
        baseline_states={baseline.finding_key: FindingState.ANALYST_CONFIRMED},
        current_states={current.finding_key: FindingState.ANALYST_CONFIRMED},
        coverage_by_finding={baseline.finding_key: CoverageStatus.COVERED_WITH_FINDING},
    )
    assert len(diffs) == 1
    assert diffs[0].status is DiffStatus.UNCHANGED
