"""QUICK-005 — multi-tool fingerprint merge keeps every occurrence and evidence."""

from __future__ import annotations

from typing import Any

import pytest

from src.quick.correlation import (
    correlate_results,
    mark_duplicate_occurrences,
    needs_selective_verification,
    overlay_ai_triage,
    select_verification_candidates,
)
from src.quick.normalize import QuickNormalizeContext, normalize_match
from src.quick.schemas import FindingTriage, FindingTriageVerdict, SeverityFloor

_TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_SCAN_ID = "11111111-2222-3333-4444-555555555555"
_ENGAGEMENT_ID = "99999999-8888-7777-6666-555555555555"
_ASSET_ID = "abcdef01-2345-6789-abcd-ef0123456789"
_TASK_ID = "fedcba98-7654-3210-fedc-ba9876543210"
_POLICY_ID = "01234567-89ab-cdef-0123-456789abcdef"
_ASSET = "https://app.example"
_ENDPOINT = "https://app.example/search?q=test"
_FAKE_ARTIFACT = "t/s/vuln_analysis/raw/quick_tool_raw.json"


@pytest.fixture(autouse=True)
def _mock_minio(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "src.quick.normalize.sink_raw_json",
        lambda **_kwargs: _FAKE_ARTIFACT,
    )


def _ctx(tool_id: str, **overrides: Any) -> QuickNormalizeContext:
    base: dict[str, Any] = dict(
        tenant_id=_TENANT_ID,
        scan_id=_SCAN_ID,
        engagement_id=_ENGAGEMENT_ID,
        asset_id=_ASSET_ID,
        asset=_ASSET,
        tool_id=tool_id,
        tool_version="1.0.0",
        capability_id="web.application.forms.input_validation",
        phase="vuln_analysis",
        task_id=_TASK_ID,
        policy_decision_id=_POLICY_ID,
        protocol="https",
    )
    base.update(overrides)
    return QuickNormalizeContext(**base)


def _match(*, tool_id: str, severity: str, confidence: float, template_id: str) -> dict[str, Any]:
    return {
        "template_id": template_id,
        "matched_at": _ENDPOINT,
        "host": _ASSET,
        "severity": severity,
        "category": "xss",
        "parameter": "q",
        "name": f"{tool_id} xss",
        "confidence": confidence,
    }


def test_two_tools_same_fingerprint_one_finding_two_occurrences() -> None:
    nuclei = normalize_match(
        _match(tool_id="nuclei", severity="high", confidence=0.9, template_id="xss-reflected"),
        ctx=_ctx("nuclei", template_id="xss-reflected"),
    )
    httpx = normalize_match(
        _match(tool_id="httpx", severity="medium", confidence=0.4, template_id="xss-generic"),
        ctx=_ctx("httpx", template_id="xss-generic", tool_version="1.6.0"),
    )
    assert nuclei.finding.finding_key == httpx.finding.finding_key
    assert nuclei.occurrence.occurrence_key != httpx.occurrence.occurrence_key

    correlated = correlate_results((nuclei, httpx))
    assert len(correlated) == 1
    item = correlated[0]
    assert item.finding.finding_key == nuclei.finding.finding_key
    assert len(item.occurrences) == 2
    scanners = {occ.scanner for occ in item.occurrences}
    assert scanners == {"nuclei", "httpx"}
    assert len(item.evidence) == 2
    assert set(item.finding.evidence_ids) == {nuclei.evidence.evidence_id, httpx.evidence.evidence_id}
    assert set(item.finding.occurrence_keys) == {
        nuclei.occurrence.occurrence_key,
        httpx.occurrence.occurrence_key,
    }
    assert item.finding.dedup_status == "unique"


def test_contradicting_evidence_is_retained() -> None:
    high = normalize_match(
        _match(tool_id="nuclei", severity="high", confidence=0.95, template_id="xss-a"),
        ctx=_ctx("nuclei", template_id="xss-a"),
    )
    low = normalize_match(
        _match(tool_id="httpx", severity="low", confidence=0.35, template_id="xss-b"),
        ctx=_ctx("httpx", template_id="xss-b"),
    )
    item = correlate_results((high, low))[0]
    assert item.contradictions
    assert any(note.startswith("severity:") for note in item.contradictions)
    assert "confidence_gap" in item.contradictions
    assert any(note.startswith("multi_tool:") for note in item.contradictions)
    assert set(item.finding.contradicting_evidence_ids) == {
        high.evidence.evidence_id,
        low.evidence.evidence_id,
    }
    assert high.evidence.evidence_id in {row.evidence_id for row in item.evidence}
    assert low.evidence.evidence_id in {row.evidence_id for row in item.evidence}
    assert item.finding.verdict is FindingTriageVerdict.NEEDS_VERIFICATION
    assert item.finding.severity == "high"


def test_mark_duplicate_occurrences_keeps_all_occurrences() -> None:
    first = normalize_match(
        _match(tool_id="nuclei", severity="high", confidence=0.8, template_id="xss-reflected"),
        ctx=_ctx("nuclei"),
    )
    second = normalize_match(
        _match(tool_id="httpx", severity="high", confidence=0.8, template_id="xss-reflected"),
        ctx=_ctx("httpx"),
    )
    merged = correlate_results((first, second))[0]
    marked = mark_duplicate_occurrences(merged)
    assert marked.finding.dedup_status == "unique"
    assert len(marked.occurrences) == 2
    assert marked.evidence == merged.evidence
    assert marked.finding.evidence_ids == merged.finding.evidence_ids


def test_distinct_fingerprints_stay_separate() -> None:
    xss = normalize_match(
        _match(tool_id="nuclei", severity="high", confidence=0.8, template_id="xss"),
        ctx=_ctx("nuclei"),
    )
    sqli_payload = _match(tool_id="nuclei", severity="high", confidence=0.8, template_id="sqli")
    sqli_payload["category"] = "sqli"
    sqli_payload["parameter"] = "id"
    sqli_payload["matched_at"] = "https://app.example/item?id=1"
    sqli = normalize_match(sqli_payload, ctx=_ctx("nuclei", template_id="sqli"))
    correlated = correlate_results((xss, sqli))
    assert len(correlated) == 2
    keys = {item.finding.finding_key for item in correlated}
    assert len(keys) == 2


def test_overlay_ai_triage_cannot_drop_evidence() -> None:
    nuclei = normalize_match(
        _match(tool_id="nuclei", severity="high", confidence=0.9, template_id="xss-reflected"),
        ctx=_ctx("nuclei"),
    )
    item = correlate_results((nuclei,))[0]
    triage = FindingTriage(
        finding_id=item.finding.finding_id,
        verdict=FindingTriageVerdict.FALSE_POSITIVE_CANDIDATE,
        severity=SeverityFloor.INFO,
        confidence=0.2,
        fact_summary="AI overlay must not erase scanner evidence.",
        hypothesis_summary="possible matcher noise",
    )
    overlaid = overlay_ai_triage(item, triage)
    assert overlaid.finding.evidence_ids == item.finding.evidence_ids
    assert overlaid.finding.occurrence_keys == item.finding.occurrence_keys
    assert overlaid.evidence == item.evidence
    assert overlaid.occurrences == item.occurrences
    assert overlaid.finding.hypothesis is not None
    assert overlaid.finding.hypothesis["source"] == "ai_overlay"


def test_informational_excluded_from_selective_verification() -> None:
    info_payload = _match(tool_id="nuclei", severity="info", confidence=0.2, template_id="tech-detect")
    info_payload["category"] = "info"
    info = normalize_match(info_payload, ctx=_ctx("nuclei", template_id="tech-detect"))
    high = normalize_match(
        _match(tool_id="nuclei", severity="critical", confidence=0.9, template_id="rce"),
        ctx=_ctx("nuclei", template_id="rce"),
    )
    correlated = correlate_results((info, high))
    selected = select_verification_candidates(correlated)
    assert all(item.finding.severity.lower() != "info" for item in selected)
    assert any(item.finding.severity == "critical" for item in selected)
    assert needs_selective_verification(info.finding) is False
    assert needs_selective_verification(high.finding) is True
    assert needs_selective_verification(info.finding, has_contradiction=True) is False
