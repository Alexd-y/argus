"""Unit tests for :mod:`src.findings.cvss`."""

from __future__ import annotations

import pytest

from src.findings.cvss import CVSSScore, parse_cvss_vector, severity_label


class TestParseCvssVector:
    """Vector parsing for CVSS v3.0 / v3.1 / v4.0."""

    def test_v31_critical_round_trip(self) -> None:
        result = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert isinstance(result, CVSSScore)
        assert result.version == "3.1"
        assert pytest.approx(result.base, abs=0.01) == 9.8
        assert result.severity == "Critical"

    def test_v30_high(self) -> None:
        result = parse_cvss_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
        assert result.version == "3.0"
        assert result.base >= 7.0

    def test_v40_round_trip(self) -> None:
        result = parse_cvss_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        )
        assert result.version == "4.0"
        assert 0.0 <= result.base <= 10.0
        assert isinstance(result.severity, str) and result.severity

    def test_dto_is_frozen(self) -> None:
        result = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        with pytest.raises(Exception):
            result.base = 10.0  # type: ignore[misc]

    def test_dto_extra_fields_forbidden(self) -> None:
        with pytest.raises(Exception):
            CVSSScore(
                version="3.1",
                base=5.0,
                severity="Medium",
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                extra="boom",  # type: ignore[call-arg]
            )

    @pytest.mark.parametrize(
        "vector",
        [
            "",
            "CVSS:2.0/AV:N",
            "not-a-vector",
            "CVSS:3.1/INVALID",
            "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ],
    )
    def test_invalid_vectors_raise(self, vector: str) -> None:
        with pytest.raises(ValueError):
            parse_cvss_vector(vector)

    def test_non_string_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_cvss_vector(None)  # type: ignore[arg-type]


class TestSeverityLabel:
    """Boundary mapping in :func:`severity_label`."""

    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (None, "None"),
            (0.0, "None"),
            (0.1, "Low"),
            (3.9, "Low"),
            (4.0, "Medium"),
            (6.9, "Medium"),
            (7.0, "High"),
            (8.9, "High"),
            (9.0, "Critical"),
            (10.0, "Critical"),
        ],
    )
    def test_canonical_thresholds(self, score: float | None, expected: str) -> None:
        assert severity_label(score) == expected

    @pytest.mark.parametrize("score", [-0.1, 10.1, 11.0, -5.0])
    def test_out_of_range_raises(self, score: float) -> None:
        with pytest.raises(ValueError):
            severity_label(score)

    def test_non_numeric_raises(self) -> None:
        with pytest.raises(TypeError):
            severity_label("nope")  # type: ignore[arg-type]
