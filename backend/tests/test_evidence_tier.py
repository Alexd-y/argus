"""Tests for EvidenceTier classification and FindingDTO new fields."""

from __future__ import annotations

from datetime import date, datetime, timezone
from uuid import uuid4

import pytest

from src.orchestration.evidence_tier import (
    EVIDENCE_TIER_DESCRIPTIONS,
    EVIDENCE_TIER_LABELS,
    EvidenceTier,
    classify_finding,
)
from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    SSVCDecision,
)


class TestEvidenceTier:
    def test_tier_ordering(self) -> None:
        assert EvidenceTier.EXPLOITED > EvidenceTier.CONFIRMED
        assert EvidenceTier.CONFIRMED > EvidenceTier.SUSPECTED
        assert EvidenceTier.SUSPECTED > EvidenceTier.INFORMATIONAL

    def test_tier_values(self) -> None:
        assert EvidenceTier.INFORMATIONAL == 1
        assert EvidenceTier.SUSPECTED == 2
        assert EvidenceTier.CONFIRMED == 3
        assert EvidenceTier.EXPLOITED == 4

    def test_labels_exist_for_all_tiers(self) -> None:
        for tier in EvidenceTier:
            assert tier in EVIDENCE_TIER_LABELS
            assert isinstance(EVIDENCE_TIER_LABELS[tier], str)
            assert len(EVIDENCE_TIER_LABELS[tier]) > 0

    def test_descriptions_exist_for_all_tiers(self) -> None:
        for tier in EvidenceTier:
            assert tier in EVIDENCE_TIER_DESCRIPTIONS
            assert isinstance(EVIDENCE_TIER_DESCRIPTIONS[tier], str)
            assert len(EVIDENCE_TIER_DESCRIPTIONS[tier]) > 0


class TestClassifyFinding:
    def test_exploitable_with_payload_is_exploited(self) -> None:
        result = classify_finding(
            ConfidenceLevel.EXPLOITABLE, has_payload=True, has_evidence=True
        )
        assert result == EvidenceTier.EXPLOITED

    def test_exploitable_without_payload_is_confirmed(self) -> None:
        result = classify_finding(
            ConfidenceLevel.EXPLOITABLE, has_payload=False, has_evidence=True
        )
        assert result == EvidenceTier.CONFIRMED

    def test_confirmed_always_confirmed(self) -> None:
        result = classify_finding(
            ConfidenceLevel.CONFIRMED, has_payload=False, has_evidence=True
        )
        assert result == EvidenceTier.CONFIRMED

    def test_likely_with_evidence_is_suspected(self) -> None:
        result = classify_finding(
            ConfidenceLevel.LIKELY, has_payload=False, has_evidence=True
        )
        assert result == EvidenceTier.SUSPECTED

    def test_likely_without_evidence_is_informational(self) -> None:
        result = classify_finding(
            ConfidenceLevel.LIKELY, has_payload=False, has_evidence=False
        )
        assert result == EvidenceTier.INFORMATIONAL

    def test_suspected_is_informational(self) -> None:
        result = classify_finding(
            ConfidenceLevel.SUSPECTED, has_payload=False, has_evidence=False
        )
        assert result == EvidenceTier.INFORMATIONAL

    def test_suspected_with_evidence_still_informational(self) -> None:
        result = classify_finding(
            ConfidenceLevel.SUSPECTED, has_payload=False, has_evidence=True
        )
        assert result == EvidenceTier.INFORMATIONAL

    def test_exploitable_no_payload_no_evidence(self) -> None:
        result = classify_finding(
            ConfidenceLevel.EXPLOITABLE, has_payload=False, has_evidence=False
        )
        assert result == EvidenceTier.CONFIRMED


def _make_finding(**overrides) -> FindingDTO:
    defaults = dict(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        asset_id=uuid4(),
        tool_run_id=uuid4(),
        category=FindingCategory.SQLI,
        cwe=[89],
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_v3_score=9.8,
        confidence=ConfidenceLevel.EXPLOITABLE,
        status=FindingStatus.NEW,
    )
    defaults.update(overrides)
    return FindingDTO(**defaults)


class TestFindingDTONewFields:
    def test_backward_compat_none_defaults(self) -> None:
        finding = _make_finding()
        assert finding.evidence_tier is None
        assert finding.payload_attempted == []
        assert finding.payload_successful == []
        assert finding.taint_path is None
        assert finding.code_location is None

    def test_evidence_tier_exploited(self) -> None:
        finding = _make_finding(evidence_tier=EvidenceTier.EXPLOITED)
        assert finding.evidence_tier == EvidenceTier.EXPLOITED
        assert finding.evidence_tier == 4

    def test_payload_attempted_and_successful(self) -> None:
        finding = _make_finding(
            payload_attempted=[
                "' OR 1=1 --",
                "admin' --",
                "' UNION SELECT NULL --",
            ],
            payload_successful=["' OR 1=1 --"],
        )
        assert len(finding.payload_attempted) == 3
        assert len(finding.payload_successful) == 1

    def test_taint_path(self) -> None:
        finding = _make_finding(
            taint_path=[
                "src/main.py:45:user_input()",
                "src/utils.py:112:process_query()",
                "src/db.py:78:execute_raw()",
            ]
        )
        assert len(finding.taint_path) == 3
        assert "src/main.py:45:user_input()" in finding.taint_path

    def test_code_location(self) -> None:
        finding = _make_finding(code_location="src/api/users.py:142")
        assert finding.code_location == "src/api/users.py:142"

    def test_full_finding_round_trip(self) -> None:
        finding = _make_finding(
            evidence_tier=EvidenceTier.EXPLOITED,
            payload_attempted=["' OR 1=1 --", "admin' --"],
            payload_successful=["' OR 1=1 --"],
            taint_path=["src/input.py:10→src/db.py:50"],
            code_location="src/db.py:50",
        )
        data = finding.model_dump()
        restored = FindingDTO.model_validate(data)
        assert restored.evidence_tier == EvidenceTier.EXPLOITED
        assert len(restored.payload_attempted) == 2
        assert len(restored.payload_successful) == 1
        assert len(restored.taint_path) == 1
        assert restored.code_location == "src/db.py:50"

    def test_frozen_model_allows_construction(self) -> None:
        finding = _make_finding(evidence_tier=EvidenceTier.CONFIRMED)
        with pytest.raises(Exception):
            finding.evidence_tier = EvidenceTier.EXPLOITED