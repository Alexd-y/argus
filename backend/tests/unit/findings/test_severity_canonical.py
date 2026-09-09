"""Unit tests for :mod:`src.findings.severity` (canonical taxonomy + aggregation)."""

from __future__ import annotations

import math

import pytest

from src.findings.severity import (
    SEVERITY_BANDS,
    SeverityBand,
    SeverityCounts,
    aggregate_severity,
    band_from_cvss_score,
    normalize_severity,
)


class TestNormalizeSeverity:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("critical", SeverityBand.CRITICAL),
            ("CRITICAL", SeverityBand.CRITICAL),
            ("high", SeverityBand.HIGH),
            ("important", SeverityBand.HIGH),  # legacy frontend label
            ("medium", SeverityBand.MEDIUM),
            ("moderate", SeverityBand.MEDIUM),
            ("low", SeverityBand.LOW),
            ("info", SeverityBand.INFORMATIONAL),
            ("informational", SeverityBand.INFORMATIONAL),
            ("none", SeverityBand.INFORMATIONAL),  # CVSS None displayed as info
        ],
    )
    def test_known_labels(self, raw: str, expected: SeverityBand) -> None:
        assert normalize_severity(raw) == expected

    @pytest.mark.parametrize("raw", [None, "", "   ", "not_a_bucket", "p1", "sev5"])
    def test_unknown_never_becomes_low_or_info(self, raw: object) -> None:
        # Regression guard: an unrecognised label must not be silently coerced.
        assert normalize_severity(raw) == SeverityBand.UNKNOWN

    def test_idempotent_on_band(self) -> None:
        assert normalize_severity(SeverityBand.MEDIUM) is SeverityBand.MEDIUM


class TestBandFromCvssScore:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0.0, SeverityBand.INFORMATIONAL),  # CVSS "None" surfaced as info
            (0.1, SeverityBand.LOW),
            (3.9, SeverityBand.LOW),
            (4.0, SeverityBand.MEDIUM),
            (6.9, SeverityBand.MEDIUM),
            (7.0, SeverityBand.HIGH),
            (8.9, SeverityBand.HIGH),
            (9.0, SeverityBand.CRITICAL),
            (10.0, SeverityBand.CRITICAL),
        ],
    )
    def test_standard_scale_boundaries(self, score: float, expected: SeverityBand) -> None:
        assert band_from_cvss_score(score) == expected

    def test_missing_score_is_unknown_not_zero(self) -> None:
        assert band_from_cvss_score(None) == SeverityBand.UNKNOWN

    @pytest.mark.parametrize(
        "score", [float("nan"), math.inf, -math.inf, -0.1, 10.1, 11.0]
    )
    def test_invalid_scores_are_unknown(self, score: float) -> None:
        assert band_from_cvss_score(score) == SeverityBand.UNKNOWN

    def test_bool_is_not_a_score(self) -> None:
        # ``True`` must not masquerade as CVSS 1.0.
        assert band_from_cvss_score(True) == SeverityBand.UNKNOWN
        assert band_from_cvss_score(False) == SeverityBand.UNKNOWN


class TestAggregateSeverity:
    def test_sum_equals_population_and_unknown_kept(self) -> None:
        labels = [
            "critical", "high", "high", "medium", "low", "low", "low",
            "informational", "", "garbage", None,
        ]
        counts = aggregate_severity(labels)
        assert counts.critical == 1
        assert counts.high == 2
        assert counts.medium == 1
        assert counts.low == 3
        assert counts.informational == 1
        assert counts.unknown == 3  # "", "garbage", None
        assert counts.total == len(labels)
        assert sum(counts.as_dict().values()) == len(labels)

    def test_info_not_folded_into_low(self) -> None:
        counts = aggregate_severity(["informational", "info"])
        assert counts.informational == 2
        assert counts.low == 0

    def test_empty_population(self) -> None:
        counts = aggregate_severity([])
        assert counts == SeverityCounts()
        assert counts.total == 0

    def test_as_dict_ordering_includes_all_bands(self) -> None:
        keys = list(aggregate_severity([]).as_dict().keys())
        assert keys == [band.value for band in SEVERITY_BANDS]
        assert "unknown" in keys
