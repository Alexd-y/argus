"""Unit tests for deterministic effective-severity selection (pure policy)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from src.findings.severity import SeverityBand
from src.findings.severity_assessment import (
    AssessmentMethod,
    AssessmentRecord,
    build_manual_override,
    conflicting_assessments,
    effective_band,
    select_effective_assessment,
)


def _rec(
    aid: str,
    method: str,
    severity: str,
    *,
    manual: bool = False,
    ts: datetime | None = None,
    supersedes: str | None = None,
) -> AssessmentRecord:
    return AssessmentRecord(
        assessment_id=aid,
        method=method,
        severity=severity,
        is_manual_override=manual,
        created_at=ts,
        supersedes=supersedes,
    )


class TestSelectEffective:
    def test_none_when_empty(self) -> None:
        assert select_effective_assessment([]) is None
        assert effective_band([]) is SeverityBand.UNKNOWN

    def test_manual_override_always_wins(self) -> None:
        records = [
            _rec("a", AssessmentMethod.CONFIRMED_EXPLOIT, "critical"),
            _rec("b", AssessmentMethod.MANUAL_OVERRIDE, "low", manual=True),
        ]
        winner = select_effective_assessment(records)
        assert winner is not None and winner.assessment_id == "b"
        assert effective_band(records) is SeverityBand.LOW

    def test_higher_trust_method_wins(self) -> None:
        records = [
            _rec("a", AssessmentMethod.HEURISTIC, "critical"),
            _rec("b", AssessmentMethod.CVSS_V3, "medium"),
        ]
        winner = select_effective_assessment(records)
        assert winner is not None and winner.assessment_id == "b"

    def test_recency_breaks_equal_trust(self) -> None:
        older = _rec(
            "a", AssessmentMethod.TOOL_NATIVE, "high", ts=datetime(2020, 1, 1, tzinfo=UTC)
        )
        newer = _rec(
            "b", AssessmentMethod.TOOL_NATIVE, "medium", ts=datetime(2024, 1, 1, tzinfo=UTC)
        )
        winner = select_effective_assessment([older, newer])
        assert winner is not None and winner.assessment_id == "b"

    def test_id_breaks_full_tie(self) -> None:
        ts = datetime(2024, 1, 1, tzinfo=UTC)
        a = _rec("a", AssessmentMethod.TOOL_NATIVE, "high", ts=ts)
        z = _rec("z", AssessmentMethod.TOOL_NATIVE, "high", ts=ts)
        winner = select_effective_assessment([a, z])
        assert winner is not None and winner.assessment_id == "z"

    def test_order_independent(self) -> None:
        records = [
            _rec("a", AssessmentMethod.HEURISTIC, "critical"),
            _rec("b", AssessmentMethod.CVSS_V3, "medium"),
            _rec("c", AssessmentMethod.MANUAL_OVERRIDE, "high", manual=True),
        ]
        forward = select_effective_assessment(records)
        backward = select_effective_assessment(list(reversed(records)))
        assert forward is not None and backward is not None
        assert forward.assessment_id == backward.assessment_id == "c"

    def test_superseded_excluded(self) -> None:
        # "b" supersedes "a"; even though "a" has higher trust, it is retired.
        records = [
            _rec("a", AssessmentMethod.CVSS_V3, "critical"),
            _rec("b", AssessmentMethod.TOOL_NATIVE, "low", supersedes="a"),
        ]
        winner = select_effective_assessment(records)
        assert winner is not None and winner.assessment_id == "b"

    def test_unknown_method_never_beats_known(self) -> None:
        records = [
            _rec("a", "totally_made_up", "critical"),
            _rec("b", AssessmentMethod.HEURISTIC, "low"),
        ]
        winner = select_effective_assessment(records)
        assert winner is not None and winner.assessment_id == "b"


class TestConflicts:
    def test_reports_differing_bands(self) -> None:
        records = [
            _rec("a", AssessmentMethod.CVSS_V3, "high"),
            _rec("b", AssessmentMethod.TOOL_NATIVE, "high"),
            _rec("c", AssessmentMethod.HEURISTIC, "low"),
        ]
        winner = select_effective_assessment(records)
        conflicts = {r.assessment_id for r in conflicting_assessments(records, winner)}
        # a wins (CVSS, High); b agrees (High) → not a conflict; c disagrees.
        assert conflicts == {"c"}

    def test_no_conflicts_when_all_agree(self) -> None:
        records = [
            _rec("a", AssessmentMethod.CVSS_V3, "medium"),
            _rec("b", AssessmentMethod.TOOL_NATIVE, "moderate"),  # synonym → medium
        ]
        assert conflicting_assessments(records) == []

    def test_empty_when_no_records(self) -> None:
        assert conflicting_assessments([]) == []


class TestManualOverrideBuilder:
    def test_requires_author(self) -> None:
        with pytest.raises(ValueError, match="author"):
            build_manual_override(
                assessment_id="x", severity="high", author="  ", reason="r"
            )

    def test_requires_reason(self) -> None:
        with pytest.raises(ValueError, match="reason"):
            build_manual_override(
                assessment_id="x", severity="high", author="analyst", reason=""
            )

    def test_builds_override_record(self) -> None:
        rec = build_manual_override(
            assessment_id="x",
            severity="critical",
            author="analyst@corp",
            reason="Confirmed RCE in prod",
            supersedes="prev",
        )
        assert rec.is_manual_override is True
        assert rec.method == AssessmentMethod.MANUAL_OVERRIDE.value
        assert rec.band is SeverityBand.CRITICAL
        assert rec.override_author == "analyst@corp"
        assert rec.override_reason == "Confirmed RCE in prod"
        assert rec.supersedes == "prev"
        assert rec.created_at is not None
