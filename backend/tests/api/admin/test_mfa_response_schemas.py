"""Unit tests for the MFA response-schema validators (C7-T03 / DEBUG-7).

Scope
-----
Locks the :data:`AwareUtcDatetime` contract added under DEBUG-7: every C7-T03
response model must reject naive ``datetime`` values and any non-UTC offset
at construction time. The router happy paths already use
``datetime.now(tz=timezone.utc)``, so the validator is a no-op for production
traffic but a hard fail on regression. These tests pin that behaviour
without booting an ASGI app — pure schema construction, runs in
milliseconds and is unaffected by the DAO test markers.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from src.api.admin.schemas.mfa import (
    AwareUtcDatetime,
    BackupCodesRegenerateResponse,
    MFAConfirmResponse,
    MFADisableResponse,
    MFAStatusResponse,
    MFAVerifyResponse,
    _ensure_aware_utc,
)

# A fixed UTC-aware reference instant — uses an explicit constructor so the
# tests are deterministic and do not depend on wall-clock time.
_AWARE_UTC: datetime = datetime(2026, 4, 23, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# _ensure_aware_utc — direct unit tests
# ---------------------------------------------------------------------------


class TestEnsureAwareUtc:
    """Direct coverage of the validator function."""

    def test_aware_utc_passes_unchanged(self) -> None:
        assert _ensure_aware_utc(_AWARE_UTC) is _AWARE_UTC

    def test_naive_datetime_raises(self) -> None:
        naive = datetime(2026, 4, 23, 12, 0, 0)
        with pytest.raises(ValueError, match="naive"):
            _ensure_aware_utc(naive)

    def test_non_utc_offset_raises(self) -> None:
        plus_three = datetime(2026, 4, 23, 12, 0, 0, tzinfo=timezone(timedelta(hours=3)))
        with pytest.raises(ValueError, match=r"UTC"):
            _ensure_aware_utc(plus_three)

    def test_negative_offset_raises(self) -> None:
        minus_five = datetime(2026, 4, 23, 12, 0, 0, tzinfo=timezone(timedelta(hours=-5)))
        with pytest.raises(ValueError, match=r"UTC"):
            _ensure_aware_utc(minus_five)


# ---------------------------------------------------------------------------
# Per-response coverage — every datetime field on every response model
# ---------------------------------------------------------------------------


class TestMFAConfirmResponseDatetime:
    def test_aware_utc_accepted(self) -> None:
        model = MFAConfirmResponse(enabled=True, enabled_at=_AWARE_UTC)
        assert model.enabled_at == _AWARE_UTC

    def test_naive_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            MFAConfirmResponse(enabled=True, enabled_at=datetime(2026, 4, 23))
        assert "naive" in str(exc.value)


class TestMFAVerifyResponseDatetime:
    def test_aware_utc_accepted(self) -> None:
        model = MFAVerifyResponse(verified=True, mfa_passed_at=_AWARE_UTC)
        assert model.mfa_passed_at == _AWARE_UTC

    def test_naive_rejected(self) -> None:
        # Construct a deliberately naive datetime (no tzinfo) — equivalent to
        # what ``datetime.utcnow()`` historically produced. Done explicitly to
        # avoid the ``utcnow()`` deprecation warning while still exercising
        # the validator's "no tzinfo" branch.
        naive = datetime(2026, 4, 23, 12, 0, 0)
        with pytest.raises(ValidationError):
            MFAVerifyResponse(verified=True, mfa_passed_at=naive)


class TestMFADisableResponseDatetime:
    def test_aware_utc_accepted(self) -> None:
        model = MFADisableResponse(disabled=True, disabled_at=_AWARE_UTC)
        assert model.disabled_at == _AWARE_UTC

    def test_non_utc_rejected(self) -> None:
        plus_one = datetime(2026, 4, 23, 12, 0, 0, tzinfo=timezone(timedelta(hours=1)))
        with pytest.raises(ValidationError):
            MFADisableResponse(disabled=True, disabled_at=plus_one)


class TestMFAStatusResponseDatetime:
    """``enrolled_at`` is ``Optional`` — None must remain valid."""

    def test_none_accepted(self) -> None:
        model = MFAStatusResponse(
            enabled=False,
            enrolled_at=None,
            remaining_backup_codes=0,
            mfa_passed_for_session=False,
        )
        assert model.enrolled_at is None

    def test_aware_utc_accepted(self) -> None:
        model = MFAStatusResponse(
            enabled=True,
            enrolled_at=_AWARE_UTC,
            remaining_backup_codes=10,
            mfa_passed_for_session=True,
        )
        assert model.enrolled_at == _AWARE_UTC

    def test_naive_rejected(self) -> None:
        with pytest.raises(ValidationError):
            MFAStatusResponse(
                enabled=True,
                enrolled_at=datetime(2026, 4, 23),
                remaining_backup_codes=10,
                mfa_passed_for_session=True,
            )


class TestBackupCodesRegenerateResponseDatetime:
    _CODES = [f"AAAA-AAAA-AAAA-AAA{n}" for n in range(10)]

    def test_aware_utc_accepted(self) -> None:
        model = BackupCodesRegenerateResponse(
            backup_codes=self._CODES,
            generated_at=_AWARE_UTC,
        )
        assert model.generated_at == _AWARE_UTC

    def test_naive_rejected(self) -> None:
        with pytest.raises(ValidationError):
            BackupCodesRegenerateResponse(
                backup_codes=self._CODES,
                generated_at=datetime(2026, 4, 23),
            )


# ---------------------------------------------------------------------------
# Public alias is exported — guards against accidental removal during refactor
# ---------------------------------------------------------------------------


def test_aware_utc_datetime_alias_is_public() -> None:
    from src.api.admin.schemas import mfa as schemas_module

    assert "AwareUtcDatetime" in schemas_module.__all__
    assert AwareUtcDatetime is schemas_module.AwareUtcDatetime
