"""Unit tests for the canonical finding taxonomy (four orthogonal axes)."""

from __future__ import annotations

import pytest
from src.findings.taxonomy import (
    Lifecycle,
    RecordKind,
    RemediationPriority,
    ValidationState,
    derive_remediation_priority,
    normalize_lifecycle,
    normalize_record_kind,
    normalize_validation,
)


class TestNormalizeValidation:
    @pytest.mark.parametrize(
        ("confidence", "expected"),
        [
            ("confirmed", ValidationState.CONFIRMED),
            ("exploitable", ValidationState.CONFIRMED),
            ("likely", ValidationState.SUSPECTED),
            ("possible", ValidationState.SUSPECTED),
            ("advisory", ValidationState.INCONCLUSIVE),
            ("garbage", ValidationState.INCONCLUSIVE),
            (None, ValidationState.INCONCLUSIVE),
        ],
    )
    def test_from_confidence(self, confidence: object, expected: ValidationState) -> None:
        assert normalize_validation(confidence=confidence) == expected

    def test_false_positive_flag_wins(self) -> None:
        assert (
            normalize_validation(confidence="confirmed", false_positive=True)
            == ValidationState.REJECTED
        )

    def test_verdict_precedes_confidence(self) -> None:
        assert (
            normalize_validation(verdict="rejected", confidence="confirmed")
            == ValidationState.REJECTED
        )


class TestNormalizeLifecycle:
    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            ("new", Lifecycle.OPEN),
            ("validated", Lifecycle.OPEN),
            ("fixed", Lifecycle.FIXED),
            ("accepted_risk", Lifecycle.ACCEPTED_RISK),
            ("false_positive", Lifecycle.FALSE_POSITIVE),
            ("weird", Lifecycle.OPEN),
            (None, Lifecycle.OPEN),
        ],
    )
    def test_from_status(self, status: object, expected: Lifecycle) -> None:
        assert normalize_lifecycle(status=status) == expected

    def test_false_positive_flag_wins(self) -> None:
        assert (
            normalize_lifecycle(status="fixed", false_positive=True)
            == Lifecycle.FALSE_POSITIVE
        )


class TestNormalizeRecordKind:
    def test_explicit_wins(self) -> None:
        assert (
            normalize_record_kind(explicit="hardening", category="sqli", severity="critical")
            == RecordKind.HARDENING
        )

    def test_hardening_category(self) -> None:
        assert normalize_record_kind(category="misconfig") == RecordKind.HARDENING

    def test_informational_severity(self) -> None:
        assert (
            normalize_record_kind(category="info", severity="informational")
            == RecordKind.INFORMATIONAL
        )

    def test_default_vulnerability(self) -> None:
        assert (
            normalize_record_kind(category="sqli", severity="high")
            == RecordKind.VULNERABILITY
        )


class TestDeriveRemediationPriority:
    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            ("critical", RemediationPriority.P0),
            ("high", RemediationPriority.P1),
            ("medium", RemediationPriority.P2),
            ("low", RemediationPriority.P3),
            ("informational", RemediationPriority.P4),
            ("unknown", RemediationPriority.P4),
        ],
    )
    def test_base_mapping(self, severity: str, expected: RemediationPriority) -> None:
        assert derive_remediation_priority(severity=severity) == expected

    def test_kev_bumps_one_step(self) -> None:
        assert (
            derive_remediation_priority(severity="high", kev_listed=True)
            == RemediationPriority.P0
        )

    def test_high_epss_bumps_one_step(self) -> None:
        assert (
            derive_remediation_priority(severity="medium", epss_score=0.9)
            == RemediationPriority.P1
        )

    def test_bump_never_exceeds_p0(self) -> None:
        assert (
            derive_remediation_priority(severity="critical", kev_listed=True)
            == RemediationPriority.P0
        )

    def test_low_epss_does_not_bump(self) -> None:
        assert (
            derive_remediation_priority(severity="medium", epss_score=0.1)
            == RemediationPriority.P2
        )
