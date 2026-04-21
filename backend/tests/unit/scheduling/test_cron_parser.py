"""Unit tests for :mod:`src.scheduling.cron_parser` (T34, ARG-056).

Covers the closed-taxonomy validation surface, next-fire calculations
(including DST spring-forward / fall-back edge cases, leap day, and
end-of-month skip semantics), maintenance-window membership, and
:func:`normalize_to_utc` defensive datetime hygiene.

The module under test is pure logic — no DB, no Redis, no network — so
these tests run entirely in-process against deterministic anchor
datetimes; no ``freezegun`` dependency is required.
"""

from __future__ import annotations

import importlib
import sys
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from src.scheduling import cron_parser
from src.scheduling.cron_parser import (
    MAX_CRON_FIELDS,
    MIN_INTERVAL_SECONDS,
    CronParserError,
    CronValidationError,
    ParsedCron,
    is_in_maintenance_window,
    next_fire_time,
    normalize_to_utc,
    validate_cron,
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestValidateCron:
    def test_validate_cron_valid_minute(self) -> None:
        """``"*/5 * * * *"`` is the default DOS-guard floor; should pass."""
        result = validate_cron("*/5 * * * *")
        assert isinstance(result, ParsedCron)
        assert result.expression == "*/5 * * * *"
        assert result.timezone == "UTC"
        assert result.min_interval_seconds == MIN_INTERVAL_SECONDS

    def test_validate_cron_valid_hourly(self) -> None:
        """Two-hour cron yields a 2h interval (7200s)."""
        result = validate_cron("0 */2 * * *")
        assert result.min_interval_seconds == 2 * 60 * 60

    def test_validate_cron_canonicalizes_whitespace(self) -> None:
        """Operator paste with tabs / runs of spaces is normalised."""
        result = validate_cron("  */5\t*  *   *  *  ")
        assert result.expression == "*/5 * * * *"

    @pytest.mark.parametrize(
        "expression",
        ["", "   ", "\t\n  "],
    )
    def test_validate_cron_empty_raises(self, expression: str) -> None:
        with pytest.raises(CronValidationError, match="empty"):
            validate_cron(expression)

    def test_validate_cron_too_many_fields_raises(self) -> None:
        """6-field expressions imply seconds granularity which we reject."""
        with pytest.raises(CronValidationError, match="second-level"):
            validate_cron("*/5 * * * * *")

    def test_validate_cron_too_few_fields_raises(self) -> None:
        with pytest.raises(CronValidationError, match="too few"):
            validate_cron("*/5 *")

    def test_validate_cron_too_frequent_raises(self) -> None:
        """Default ``max_freq_minutes=5`` rejects a per-minute schedule."""
        with pytest.raises(CronValidationError, match="too frequently"):
            validate_cron("* * * * *")

    def test_validate_cron_below_default_threshold_rejected(self) -> None:
        """``*/4`` fires every 4 minutes — below the 5-minute floor."""
        with pytest.raises(CronValidationError, match="too frequently"):
            validate_cron("*/4 * * * *")

    def test_validate_cron_unknown_timezone_raises(self) -> None:
        with pytest.raises(CronValidationError, match="unknown timezone"):
            validate_cron("*/5 * * * *", timezone="Mars/Olympus")

    def test_validate_cron_invalid_syntax_raises(self) -> None:
        """Garbage that croniter rejects must surface as our taxonomy.

        Use a 5-field expression (so it passes the field-count guard) with
        out-of-range tokens; croniter then rejects it and we remap.
        """
        with pytest.raises(CronValidationError, match="invalid cron syntax"):
            validate_cron("abc def ghi jkl mno")

    def test_validate_cron_impossible_date_remaps_in_freq_guard(self) -> None:
        """``"0 0 30 2 *"`` constructs OK but ``get_next`` raises
        ``CroniterBadDateError`` — must remap to our taxonomy in the
        frequency-guard branch.
        """
        with pytest.raises(CronValidationError, match="invalid cron syntax"):
            validate_cron("0 0 30 2 *")

    def test_validate_cron_with_relaxed_freq_for_maintenance_window(self) -> None:
        """A 60-minute window cron passes when ``max_freq_minutes=60``."""
        result = validate_cron("0 22 * * *", max_freq_minutes=60)
        assert result.min_interval_seconds == 24 * 60 * 60

    def test_validate_cron_does_not_leak_expression_in_error_message(self) -> None:
        """PII / log-safety: operator input MUST NOT appear in error args."""
        operator_input = "this-string-must-not-appear-in-logs"
        with pytest.raises(CronValidationError) as exc_info:
            validate_cron(operator_input)
        assert operator_input not in str(exc_info.value)
        assert operator_input not in repr(exc_info.value)


# ---------------------------------------------------------------------------
# next_fire_time
# ---------------------------------------------------------------------------


class TestNextFireTime:
    def test_next_fire_time_basic(self) -> None:
        """Daily-midnight cron after 10:00 → next midnight UTC."""
        after = datetime(2026, 4, 22, 10, 0, tzinfo=UTC)
        result = next_fire_time("0 0 * * *", after=after)
        assert result == datetime(2026, 4, 23, 0, 0, tzinfo=UTC)

    def test_next_fire_time_naive_after_assumes_utc(self) -> None:
        """Naive ``after`` is interpreted as UTC, matching the default."""
        naive = datetime(2026, 4, 22, 10, 0)
        aware = datetime(2026, 4, 22, 10, 0, tzinfo=UTC)
        assert next_fire_time("0 0 * * *", after=naive) == next_fire_time(
            "0 0 * * *", after=aware
        )

    def test_next_fire_time_returns_utc_tzinfo(self) -> None:
        """Result MUST carry ``tzinfo=UTC`` regardless of source timezone."""
        after = datetime(2026, 4, 22, 10, 0, tzinfo=ZoneInfo("Europe/Berlin"))
        result = next_fire_time("0 0 * * *", after=after, timezone="Europe/Berlin")
        assert result.tzinfo is UTC

    def test_next_fire_time_dst_spring_forward(self) -> None:
        """``"0 2 * * *"`` in NY: 2026-03-08 02:00 EST is skipped (DST gap),
        croniter advances to 03:00 EDT — equivalent to 07:00 UTC.
        """
        ny = ZoneInfo("America/New_York")
        # Anchor on the night BEFORE the spring-forward, in EST.
        after = datetime(2026, 3, 7, 23, 0, tzinfo=ny)
        result = next_fire_time("0 2 * * *", after=after, timezone="America/New_York")
        # 03:00 EDT = 07:00 UTC.
        assert result == datetime(2026, 3, 8, 7, 0, tzinfo=UTC)

    def test_next_fire_time_dst_fall_back_dedupes_duplicate(self) -> None:
        """``"0 1 * * *"`` in NY on 2026-11-01: wall-clock 01:00 occurs
        twice (EDT then EST). The first call returns the earlier instant;
        the SECOND call MUST skip the duplicate and return Nov 2 01:00,
        not the second Nov 1 01:00 — operators reading "daily 01:00"
        expect ONE fire per calendar day.
        """
        ny = ZoneInfo("America/New_York")
        after = datetime(2026, 10, 31, 22, 0, tzinfo=ny)
        first = next_fire_time("0 1 * * *", after=after, timezone="America/New_York")
        # First fire is 01:00 EDT (UTC -4) = 05:00 UTC.
        assert first == datetime(2026, 11, 1, 5, 0, tzinfo=UTC)
        second = next_fire_time("0 1 * * *", after=first, timezone="America/New_York")
        # Without dedup, second would be 01:00 EST = 06:00 UTC on Nov 1.
        # With dedup, it advances to 01:00 EST on Nov 2 = 06:00 UTC Nov 2.
        assert second == datetime(2026, 11, 2, 6, 0, tzinfo=UTC)

    def test_next_fire_time_leap_day(self) -> None:
        """``"0 12 29 2 *"`` from 2026-01-01 → next Feb 29 = 2028-02-29."""
        after = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
        result = next_fire_time("0 12 29 2 *", after=after)
        assert result == datetime(2028, 2, 29, 12, 0, tzinfo=UTC)

    def test_next_fire_time_end_of_month_skips_short_months(self) -> None:
        """``"0 0 31 * *"`` from Jan 15 → Jan 31, then Mar 31 (skips Feb)."""
        after = datetime(2026, 1, 15, 0, 0, tzinfo=UTC)
        first = next_fire_time("0 0 31 * *", after=after)
        assert first == datetime(2026, 1, 31, 0, 0, tzinfo=UTC)
        second = next_fire_time("0 0 31 * *", after=first)
        assert second == datetime(2026, 3, 31, 0, 0, tzinfo=UTC)

    def test_next_fire_time_invalid_expression_remaps_to_taxonomy(self) -> None:
        """Bad expression must surface as our taxonomy, not croniter's.

        ``next_fire_time`` does NOT pre-validate field count (callers are
        expected to have already run ``validate_cron``), so any 5-field
        nonsense reaches croniter and gets remapped.
        """
        with pytest.raises(CronValidationError, match="invalid cron syntax"):
            next_fire_time(
                "abc def ghi jkl mno",
                after=datetime(2026, 1, 1, tzinfo=UTC),
            )

    def test_next_fire_time_unknown_timezone_remaps_to_taxonomy(self) -> None:
        with pytest.raises(CronValidationError, match="unknown timezone"):
            next_fire_time(
                "0 0 * * *",
                after=datetime(2026, 1, 1, tzinfo=UTC),
                timezone="Atlantis/Lost",
            )

    def test_next_fire_time_impossible_date_remaps_to_taxonomy(self) -> None:
        """``"0 0 30 2 *"`` (Feb 30 — never fires) → croniter raises
        ``CroniterBadDateError`` which we remap.
        """
        with pytest.raises(CronValidationError, match="invalid cron syntax"):
            next_fire_time("0 0 30 2 *", after=datetime(2026, 1, 1, tzinfo=UTC))


# ---------------------------------------------------------------------------
# is_in_maintenance_window
# ---------------------------------------------------------------------------


class TestIsInMaintenanceWindow:
    def test_in_maintenance_window_at_start_returns_true(self) -> None:
        """Wall-clock equal to a fire instant → in window."""
        at = datetime(2026, 4, 22, 22, 0, tzinfo=UTC)
        assert is_in_maintenance_window("0 22 * * *", at=at) is True

    def test_in_maintenance_window_inside_returns_true(self) -> None:
        """30 minutes after fire, default 60-min duration → still in window."""
        at = datetime(2026, 4, 22, 22, 30, tzinfo=UTC)
        assert is_in_maintenance_window("0 22 * * *", at=at) is True

    def test_in_maintenance_window_outside_returns_false(self) -> None:
        """90 minutes after fire, 60-min duration → outside."""
        at = datetime(2026, 4, 22, 23, 30, tzinfo=UTC)
        assert (
            is_in_maintenance_window("0 22 * * *", at=at, window_duration_minutes=60)
            is False
        )

    def test_in_maintenance_window_at_window_end_inclusive(self) -> None:
        """Exactly ``duration`` minutes after the fire → still inside (inclusive)."""
        at = datetime(2026, 4, 22, 23, 0, tzinfo=UTC)
        assert (
            is_in_maintenance_window("0 22 * * *", at=at, window_duration_minutes=60)
            is True
        )

    def test_in_maintenance_window_timezone_aware(self) -> None:
        """Window defined in NY local; ``at`` arrives in UTC.

        ``"0 22 * * *"`` in America/New_York means 22:00 NY time.
        On 2026-04-22 (EDT, UTC-4), 22:00 NY = 02:00 UTC the next day.
        ``at = 2026-04-23 02:30 UTC`` → 22:30 NY → 30 min into the window
        → True.
        """
        at = datetime(2026, 4, 23, 2, 30, tzinfo=UTC)
        assert (
            is_in_maintenance_window(
                "0 22 * * *",
                at=at,
                window_duration_minutes=60,
                timezone="America/New_York",
            )
            is True
        )

    def test_in_maintenance_window_naive_at_assumes_utc(self) -> None:
        """A naive ``at`` is treated as UTC, matching the default tz."""
        naive = datetime(2026, 4, 22, 22, 30)
        aware = datetime(2026, 4, 22, 22, 30, tzinfo=UTC)
        assert is_in_maintenance_window(
            "0 22 * * *", at=naive
        ) == is_in_maintenance_window("0 22 * * *", at=aware)

    def test_in_maintenance_window_rejects_non_positive_duration(self) -> None:
        """Programmer error → stdlib :class:`ValueError`."""
        with pytest.raises(ValueError, match="window_duration_minutes"):
            is_in_maintenance_window(
                "0 22 * * *",
                at=datetime(2026, 4, 22, 22, 30, tzinfo=UTC),
                window_duration_minutes=0,
            )

    def test_in_maintenance_window_unknown_timezone_remaps(self) -> None:
        with pytest.raises(CronValidationError, match="unknown timezone"):
            is_in_maintenance_window(
                "0 22 * * *",
                at=datetime(2026, 4, 22, tzinfo=UTC),
                timezone="Bogus/Place",
            )

    def test_in_maintenance_window_impossible_cron_remaps(self) -> None:
        """``"0 0 30 2 *"`` constructs OK but ``get_prev`` raises — must
        remap to our taxonomy via the defensive guard.
        """
        with pytest.raises(CronValidationError, match="invalid cron syntax"):
            is_in_maintenance_window(
                "0 0 30 2 *",
                at=datetime(2026, 4, 22, 12, 0, tzinfo=UTC),
            )

    def test_in_maintenance_window_malformed_window_cron_raises(self) -> None:
        """Malformed ``window_cron`` reaches ``croniter.match`` first (before
        ``_build_croniter`` runs) — that path MUST also remap to our
        taxonomy, otherwise raw ``CroniterError`` subclasses (and the
        operator's raw expression embedded in their message) leak past the
        closed-taxonomy boundary.
        """
        operator_input = "abc def ghi jkl mno"
        with pytest.raises(
            CronValidationError, match="invalid cron syntax"
        ) as exc_info:
            is_in_maintenance_window(
                operator_input,
                at=datetime(2026, 4, 22, 12, 0, tzinfo=UTC),
                window_duration_minutes=60,
            )
        # PII / log-safety: operator input MUST NOT appear in error args.
        assert operator_input not in str(exc_info.value)
        assert operator_input not in repr(exc_info.value)


# ---------------------------------------------------------------------------
# normalize_to_utc
# ---------------------------------------------------------------------------


class TestNormalizeToUtc:
    def test_normalize_to_utc_naive_with_assume_timezone(self) -> None:
        """Naive 12:00 in Europe/Moscow (UTC+3) → 09:00 UTC."""
        naive = datetime(2026, 4, 22, 12, 0)
        result = normalize_to_utc(naive, assume_timezone="Europe/Moscow")
        assert result == datetime(2026, 4, 22, 9, 0, tzinfo=UTC)
        assert result.tzinfo is UTC

    def test_normalize_to_utc_already_aware_preserves_instant(self) -> None:
        """A tz-aware datetime returns the same UTC instant."""
        aware = datetime(2026, 4, 22, 12, 0, tzinfo=ZoneInfo("Europe/Berlin"))
        result = normalize_to_utc(aware)
        assert result == aware.astimezone(UTC)
        assert result.tzinfo is UTC

    def test_normalize_to_utc_naive_default_utc(self) -> None:
        """Without ``assume_timezone`` override, naive is treated as UTC."""
        naive = datetime(2026, 4, 22, 12, 0)
        result = normalize_to_utc(naive)
        assert result == datetime(2026, 4, 22, 12, 0, tzinfo=UTC)

    def test_normalize_to_utc_unknown_timezone_remaps(self) -> None:
        with pytest.raises(CronValidationError, match="unknown timezone"):
            normalize_to_utc(
                datetime(2026, 4, 22, 12, 0), assume_timezone="Nowhere/Land"
            )


# ---------------------------------------------------------------------------
# Module hygiene + dataclass guarantees
# ---------------------------------------------------------------------------


class TestModuleHygiene:
    def test_parsed_cron_is_frozen(self) -> None:
        """Frozen dataclass — callers cannot mutate cached metadata."""
        parsed = validate_cron("*/5 * * * *")
        with pytest.raises(FrozenInstanceError):
            parsed.expression = "evil"  # type: ignore[misc]

    def test_cron_parser_module_has_no_side_effects_on_import(self) -> None:
        """Importing :mod:`src.scheduling.cron_parser` MUST NOT touch the
        network, the filesystem, or any module-level state — the package
        is meant to be safely importable from CLIs and isolated tests.

        Strategy: drop the module from ``sys.modules``, re-import, and
        confirm that no DB / Redis / HTTP modules were dragged in as a
        side-effect of the re-import. We check only modules the module
        is REQUIRED to avoid pulling in (the stdlib + ``croniter`` are
        intentionally allowed).
        """
        forbidden = {"redis", "asyncpg", "sqlalchemy", "httpx", "requests"}
        # Snapshot the set of forbidden modules ALREADY loaded by the
        # broader test session so we measure only this re-import's delta.
        previously_loaded = forbidden & set(sys.modules)

        sys.modules.pop("src.scheduling.cron_parser", None)
        sys.modules.pop("src.scheduling", None)
        importlib.import_module("src.scheduling.cron_parser")

        newly_loaded = (forbidden & set(sys.modules)) - previously_loaded
        assert newly_loaded == set(), (
            f"cron_parser must not import I/O modules; new arrivals: {newly_loaded}"
        )

    def test_public_api_surface_matches_module_all(self) -> None:
        """Defensive: ``__all__`` controls the public surface."""
        module_all = (
            set(cron_parser.__all__) if hasattr(cron_parser, "__all__") else None
        )
        # Module does not declare __all__ explicitly; verify the package
        # re-export at least exposes every documented public name.
        from src import scheduling

        expected = {
            "MAX_CRON_FIELDS",
            "MIN_INTERVAL_SECONDS",
            "CronParserError",
            "CronValidationError",
            "ParsedCron",
            "is_in_maintenance_window",
            "next_fire_time",
            "normalize_to_utc",
            "validate_cron",
        }
        assert expected.issubset(set(scheduling.__all__))
        # And, since module_all may be None, just smoke-check direct access.
        for name in expected:
            assert hasattr(cron_parser, name), f"missing public name: {name}"
        # Silence unused warning when __all__ is absent.
        _ = module_all


# ---------------------------------------------------------------------------
# Error-class taxonomy guarantees
# ---------------------------------------------------------------------------


class TestErrorTaxonomy:
    def test_validation_error_is_parser_error(self) -> None:
        """``CronValidationError`` must inherit from ``CronParserError`` so
        callers can catch the broad base class without naming every
        subtype.
        """
        assert issubclass(CronValidationError, CronParserError)
        assert issubclass(CronParserError, Exception)

    def test_constants_are_well_known(self) -> None:
        """Public constants are declared at the documented values so the
        DOS guard cannot drift silently from the operator-facing
        documentation.
        """
        assert MIN_INTERVAL_SECONDS == 300
        assert MAX_CRON_FIELDS == 5


# ---------------------------------------------------------------------------
# DST helper internals — drive the dedup branch independently of croniter.
# ---------------------------------------------------------------------------


class TestDstFallbackDuplicateInternal:
    """Targeted coverage for :func:`_is_dst_fallback_duplicate`.

    Covered indirectly by :class:`TestNextFireTime` but exercised here
    directly to keep the branch coverage high without relying on
    croniter's exact wall-clock output.
    """

    def test_helper_returns_true_for_duplicate(self) -> None:
        ny = ZoneInfo("America/New_York")
        # Same wall-clock, different UTC instants (the DST fall-back case).
        edt = datetime(2026, 11, 1, 1, 0, tzinfo=ny)  # naturally EDT here
        # Construct the EST counterpart (1 hour later in absolute UTC).
        est_utc = edt.astimezone(UTC) + timedelta(hours=1)
        est = est_utc.astimezone(ny)
        assert edt.hour == est.hour == 1
        assert edt.astimezone(UTC) != est.astimezone(UTC)
        assert cron_parser._is_dst_fallback_duplicate(est, of=edt) is True

    def test_helper_returns_false_for_distinct_dates(self) -> None:
        ny = ZoneInfo("America/New_York")
        a = datetime(2026, 11, 1, 1, 0, tzinfo=ny)
        b = datetime(2026, 11, 2, 1, 0, tzinfo=ny)
        assert cron_parser._is_dst_fallback_duplicate(b, of=a) is False

    def test_helper_returns_false_for_same_instant(self) -> None:
        """Same wall-clock AND same UTC instant → not a duplicate."""
        a = datetime(2026, 4, 22, 12, 0, tzinfo=UTC)
        assert cron_parser._is_dst_fallback_duplicate(a, of=a) is False
