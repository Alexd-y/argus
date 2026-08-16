"""QUICK-005 — late OAST is append-only and never reopens a cancelled scan."""

from __future__ import annotations

from typing import Any

import pytest

from src.quick.correlation import (
    append_late_oast,
    correlate_results,
    scan_must_not_reopen,
)
from src.quick.normalize import QuickNormalizeContext, normalize_match
from src.quick.schemas import FindingTriageVerdict

_TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_SCAN_ID = "11111111-2222-3333-4444-555555555555"
_ENGAGEMENT_ID = "99999999-8888-7777-6666-555555555555"
_ASSET_ID = "abcdef01-2345-6789-abcd-ef0123456789"
_TASK_ID = "fedcba98-7654-3210-fedc-ba9876543210"
_ASSET = "https://app.example"
_FAKE_ARTIFACT = "t/s/vuln_analysis/raw/quick_tool_raw.json"


@pytest.fixture(autouse=True)
def _mock_minio(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "src.quick.normalize.sink_raw_json",
        lambda **_kwargs: _FAKE_ARTIFACT,
    )


def _ctx(**overrides: Any) -> QuickNormalizeContext:
    base: dict[str, Any] = dict(
        tenant_id=_TENANT_ID,
        scan_id=_SCAN_ID,
        engagement_id=_ENGAGEMENT_ID,
        asset_id=_ASSET_ID,
        asset=_ASSET,
        tool_id="nuclei",
        tool_version="3.3.0",
        capability_id="web.application.cve.known_product",
        phase="vuln_analysis",
        task_id=_TASK_ID,
        protocol="https",
        template_id="oast-ssrf",
    )
    base.update(overrides)
    return QuickNormalizeContext(**base)


def _correlated():
    result = normalize_match(
        {
            "template_id": "oast-ssrf",
            "matched_at": "https://app.example/callback",
            "host": _ASSET,
            "severity": "medium",
            "category": "ssrf",
            "parameter": "url",
            "name": "SSRF candidate",
            "confidence": 0.4,
        },
        ctx=_ctx(),
    )
    return correlate_results((result,))[0]


@pytest.mark.parametrize(
    "status",
    ("cancelled", "canceled", "completed", "failed", "timed_out", "timeout", "CANCELLED"),
)
def test_scan_must_not_reopen_terminal_statuses(status: str) -> None:
    assert scan_must_not_reopen(status) is True


@pytest.mark.parametrize("status", ("running", "queued", "paused", "", "  "))
def test_scan_must_not_reopen_non_terminal_statuses(status: str) -> None:
    assert scan_must_not_reopen(status) is False


def test_late_oast_appends_occurrence_and_evidence() -> None:
    correlated = _correlated()
    original_evidence = set(correlated.finding.evidence_ids)
    original_occurrences = set(correlated.finding.occurrence_keys)
    late = append_late_oast(
        correlated,
        payload={
            "matched_at": "https://app.example/callback",
            "interaction_id": "oast-1",
            "callback": "https://oast.example/i/1",
            "template_id": "oast-ssrf",
        },
        scan_status="completed",
    )
    assert late.accepted is True
    assert late.occurrence.late_oast is True
    assert late.occurrence.finding_key == correlated.finding.finding_key
    assert late.occurrence.scanner == "oast"
    assert late.evidence.tool_id == "oast"
    assert late.evidence.evidence_id not in original_evidence
    assert late.occurrence.occurrence_key not in original_occurrences
    assert original_evidence.issubset(set(late.finding.evidence_ids))
    assert original_occurrences.issubset(set(late.finding.occurrence_keys))
    assert late.evidence.evidence_id in late.finding.evidence_ids
    assert late.occurrence.occurrence_key in late.finding.occurrence_keys
    assert late.finding.scan_id == _SCAN_ID


def test_cancelled_scan_is_not_reopened_to_running() -> None:
    correlated = _correlated()
    late = append_late_oast(
        correlated,
        payload={"interaction_id": "late-1", "id": "late-1"},
        scan_status="cancelled",
    )
    assert late.scan_reopened is False
    assert late.scan_was_terminal is True
    assert late.accepted is True
    assert late.occurrence.late_oast is True
    dumped = late.model_dump(mode="json")
    assert dumped["scan_reopened"] is False


def test_late_oast_does_not_mutate_source_finding() -> None:
    correlated = _correlated()
    before_ids = correlated.finding.evidence_ids
    before_keys = correlated.finding.occurrence_keys
    late = append_late_oast(
        correlated,
        payload={"interaction_id": "late-2"},
        scan_status="cancelled",
    )
    assert correlated.finding.evidence_ids == before_ids
    assert correlated.finding.occurrence_keys == before_keys
    assert set(late.finding.evidence_ids) > set(before_ids)
    assert late.finding is not correlated.finding


def test_hypothesis_promoted_but_scan_stays_closed() -> None:
    result = normalize_match(
        {
            "template_id": "oast-ssrf",
            "matched_at": "https://app.example/callback",
            "host": _ASSET,
            "severity": "low",
            "category": "ssrf",
            "parameter": "url",
            "name": "SSRF hypothesis",
            "confidence": 0.2,
        },
        ctx=_ctx(),
    )
    correlated = correlate_results((result,))[0]
    assert correlated.finding.verdict is FindingTriageVerdict.HYPOTHESIS
    late = append_late_oast(
        correlated,
        payload={"interaction_id": "late-3"},
        scan_status="failed",
        tool_id="interactsh",
        tool_version="1.2.0",
    )
    assert late.scan_reopened is False
    assert late.scan_was_terminal is True
    assert late.occurrence.scanner == "interactsh"
    assert late.occurrence.detector_version == "1.2.0"
    assert late.finding.verdict is FindingTriageVerdict.LIKELY
