"""Cron expression parser, next-fire calculator, maintenance window logic (T34, ARG-056).

Pure utility module that powers the scheduled-scan plane:

* :func:`validate_cron` — closed-taxonomy validation of operator-supplied
  cron expressions, including a DOS guard (reject expressions that fire
  more often than every ``max_freq_minutes``).
* :func:`next_fire_time` — compute the next fire instant after a given
  ``datetime``, normalised to UTC, with DST safe handling for both
  spring-forward (skipped wall-clocks) and fall-back (duplicate
  wall-clocks, deduplicated).
* :func:`is_in_maintenance_window` — answer "are we currently inside a
  maintenance window?" for a cron-defined recurring interval.
* :func:`normalize_to_utc` — defensive datetime hygiene for callers who
  hand us naive timestamps.

Design constraints honoured here (per
`ai_docs/develop/plans/2026-04-22-argus-cycle6-b4.md` § T34):

* **Pure logic, no I/O** — no DB, no Redis, no network, no module-level
  side effects. Safe to import from CLIs / tests / Celery workers.
* **Closed error taxonomy** — only :class:`CronValidationError` (and its
  base :class:`CronParserError`) cross the package boundary.
  ``croniter``-internal exceptions (``CroniterBadCronError`` etc.) are
  caught and remapped so callers never need to import ``croniter``.
* **Stdlib timezones** — ``zoneinfo.ZoneInfo``; ``pytz`` is intentionally
  avoided (project is Python 3.12).
* **No ``datetime.utcnow()``** — deprecated; ``datetime.now(tz=UTC)`` is
  used everywhere a current timestamp is needed.
* **PII-safe error messages** — operator-supplied expressions are NEVER
  embedded in exception ``args`` or log records, because those traverse
  structured-logging pipelines that can leak into audit / SIEM. Errors
  carry a fixed taxonomy code instead.
* **5-field cron only** — second-level granularity is rejected (DOS
  guard already caps at 5 minutes; second-level offers no operator
  benefit and balloons the schedule keyspace).
* **YAGNI** — no ``previous_fire_time``, ``human_readable``, or
  ``bulk_validate`` helpers. Add them when T33 / T35 prove they're
  needed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Final
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import CroniterError, croniter  # type: ignore[import-untyped]

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

#: Minimum allowed interval between consecutive fires (seconds).
#: Defends the scheduler / Celery broker from a runaway ``* * * * *``
#: schedule. Operators who genuinely need sub-5-minute polling should be
#: routed to a dedicated streaming pipeline, not the scheduled-scan plane.
MIN_INTERVAL_SECONDS: Final[int] = 300

#: Standard cron expression has 5 fields (minute hour day month dow).
#: 6 fields would imply second-level granularity which we explicitly reject.
MAX_CRON_FIELDS: Final[int] = 5

#: Sample size used for the frequency guard. Two future fires give one
#: gap, which is sufficient for periodic patterns; non-periodic patterns
#: (e.g. ``0 0 1 * *``) still reject only when the immediate gap is too
#: small. A larger sample would catch pathological irregular patterns at
#: O(N) extra croniter calls, but the marginal benefit is low.
_FREQ_GUARD_SAMPLE: Final[int] = 2


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class CronParserError(Exception):
    """Base class for all errors raised by :mod:`src.scheduling.cron_parser`.

    Callers SHOULD catch :class:`CronValidationError` for the operator-input
    failure case. ``CronParserError`` exists so the API layer can blanket
    map any future internal failure to HTTP 500 without leaking
    ``croniter``-internal exception types.
    """


class CronValidationError(CronParserError):
    """Raised when an operator-supplied cron expression fails validation.

    The ``args`` carry a short, user-safe taxonomy string (e.g.
    ``"cron expression is empty"``). The original expression is NEVER
    embedded so structured logs / audit rows / API error bodies cannot be
    abused as an information-leak channel for whatever the operator typed.
    """


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ParsedCron:
    """Validated cron expression bundled with derived metadata.

    Attributes:
        expression: Canonical (whitespace-collapsed) form of the cron
            expression. Safe to round-trip back to :func:`validate_cron`.
        timezone: IANA timezone name the expression is interpreted in.
        min_interval_seconds: Smallest observed gap (in seconds) between
            two consecutive fires anchored at construction time. Useful
            for operators tuning maintenance windows / SLA estimates.
            For non-periodic expressions this reflects only the immediate
            gap and is not a guarantee for the entire fire calendar.
    """

    expression: str
    timezone: str
    min_interval_seconds: int


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_zone(name: str) -> ZoneInfo:
    """Return a :class:`ZoneInfo` for ``name`` or raise CronValidationError.

    ``ZoneInfo`` raises ``ZoneInfoNotFoundError`` (a subclass of
    ``KeyError``) for unknown identifiers, plus ``ValueError`` for
    syntactically illegal names.
    """
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise CronValidationError("unknown timezone") from exc


def _ensure_aware(dt: datetime, *, default_tz: tzinfo) -> datetime:
    """Return a tz-aware datetime; naive inputs are interpreted in default_tz."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=default_tz)
    return dt


def _canonicalize_expression(expression: str) -> tuple[str, list[str]]:
    """Strip + collapse whitespace; return ``(canonical, fields)``.

    Operators frequently paste cron expressions with leading/trailing
    whitespace or tabs between fields; a single ``str.split()`` (no
    argument) collapses any run of whitespace, which is the de-facto
    convention used by ``crontab(5)``.
    """
    if not expression or not expression.strip():
        raise CronValidationError("cron expression is empty")
    fields = expression.split()
    canonical = " ".join(fields)
    return canonical, fields


def _validate_field_count(fields: list[str]) -> None:
    """Reject expressions outside the 5-field standard cron grammar."""
    if len(fields) > MAX_CRON_FIELDS:
        raise CronValidationError("second-level granularity not allowed")
    if len(fields) < MAX_CRON_FIELDS:
        raise CronValidationError("cron expression has too few fields")


def _build_croniter(expression: str, anchor: datetime) -> croniter:
    """Construct a ``croniter`` instance, remapping its errors to our taxonomy.

    ``croniter`` raises a small zoo of errors for malformed input; all of
    them inherit from ``CroniterError`` (the public base) so a single
    except clause covers the surface. We deliberately do NOT catch the
    broad :class:`Exception`: a stdlib ``MemoryError`` in croniter would
    indicate something far worse than bad operator input.
    """
    try:
        return croniter(expression, anchor)
    except CroniterError as exc:
        raise CronValidationError("invalid cron syntax") from exc


def _enforce_frequency_guard(iterator: croniter, *, max_freq_seconds: int) -> int:
    """Compute the immediate gap between two future fires; raise if too small.

    Returns the observed gap in seconds so callers can persist it as
    :attr:`ParsedCron.min_interval_seconds`. The guard is one-sided: we
    only reject when the gap is *smaller* than the threshold, never when
    it is larger. Operators are free to schedule yearly cron expressions.
    """
    try:
        fires: list[datetime] = [
            iterator.get_next(datetime) for _ in range(_FREQ_GUARD_SAMPLE)
        ]
    except CroniterError as exc:  # e.g. CroniterBadDateError on impossible patterns
        raise CronValidationError("invalid cron syntax") from exc
    gap_seconds = int((fires[1] - fires[0]).total_seconds())
    if gap_seconds < max_freq_seconds:
        raise CronValidationError("cron expression fires too frequently")
    return gap_seconds


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate_cron(
    expression: str,
    *,
    timezone: str = "UTC",
    max_freq_minutes: int = 5,
) -> ParsedCron:
    """Validate a 5-field cron ``expression`` and return a :class:`ParsedCron`.

    Args:
        expression: Operator-supplied cron expression (e.g. ``"*/5 * * * *"``).
        timezone: IANA timezone name (e.g. ``"Europe/Moscow"``). Defaults
            to UTC. Resolved via stdlib :class:`zoneinfo.ZoneInfo`.
        max_freq_minutes: Reject expressions whose immediate gap between
            consecutive fires is below this threshold. Defaults to 5
            minutes; this is the project-wide DOS guard. Pass a larger
            value (e.g. 60) when validating *maintenance window*
            expressions where minute-level granularity is meaningless.

    Raises:
        CronValidationError: With a closed-taxonomy message:
            ``"cron expression is empty"``,
            ``"second-level granularity not allowed"``,
            ``"cron expression has too few fields"``,
            ``"unknown timezone"``,
            ``"invalid cron syntax"``,
            ``"cron expression fires too frequently"``.
    """
    canonical, fields = _canonicalize_expression(expression)
    _validate_field_count(fields)
    zone = _resolve_zone(timezone)
    anchor = datetime.now(tz=zone)
    iterator = _build_croniter(canonical, anchor)
    gap_seconds = _enforce_frequency_guard(
        iterator, max_freq_seconds=max_freq_minutes * 60
    )
    return ParsedCron(
        expression=canonical,
        timezone=timezone,
        min_interval_seconds=gap_seconds,
    )


def next_fire_time(
    expression: str,
    *,
    after: datetime,
    timezone: str = "UTC",
) -> datetime:
    """Return the next fire instant strictly after ``after``, normalised to UTC.

    Args:
        expression: A cron expression. NOT re-validated here — callers who
            accept operator input MUST first run :func:`validate_cron`.
            This split keeps the function cheap on hot paths (e.g.
            scheduler tick) while still failing closed if the expression
            is malformed (``croniter`` errors are remapped to
            :class:`CronValidationError`).
        after: Reference instant. ``after`` may be naive (interpreted in
            ``timezone``) or tz-aware (used as-is, then translated into
            ``timezone`` for the cron computation).
        timezone: IANA timezone the cron expression is interpreted in.

    Returns:
        UTC-normalised tz-aware :class:`datetime`. The returned instant
        is *strictly* after ``after`` — no fire matches.

    DST handling:

    * **Spring-forward** (e.g. America/New_York, 2026-03-08 02:00 EST →
      03:00 EDT): a cron expression like ``"0 2 * * *"`` skips the
      missing 02:00 and fires at 03:00 EDT — the standard ``croniter``
      behaviour, which we keep.
    * **Fall-back** (e.g. America/New_York, 2026-11-01 02:00 EDT →
      01:00 EST creates a duplicate 01:00): a cron expression like
      ``"0 1 * * *"`` would otherwise fire twice on Nov 1 (once at
      01:00 EDT, once at 01:00 EST). For scheduled scans this is almost
      always undesirable — operators reading "daily 01:00" expect ONE
      fire. We dedupe by detecting a candidate whose calendar date and
      wall-clock match ``after`` (in source timezone) and advancing once
      more.
    """
    zone = _resolve_zone(timezone)
    after_in_zone = _ensure_aware(after, default_tz=UTC).astimezone(zone)
    iterator = _build_croniter(expression, after_in_zone)
    try:
        candidate = iterator.get_next(datetime)
    except CroniterError as exc:
        raise CronValidationError("invalid cron syntax") from exc
    if _is_dst_fallback_duplicate(candidate, of=after_in_zone):
        # Defence-in-depth: the iterator just produced a fire so this second
        # call cannot realistically raise; we re-wrap solely to keep the
        # closed taxonomy if croniter ever changes its mind.
        try:
            candidate = iterator.get_next(datetime)
        except CroniterError as exc:  # pragma: no cover — defensive only
            raise CronValidationError("invalid cron syntax") from exc
    return candidate.astimezone(UTC)


def _is_dst_fallback_duplicate(candidate: datetime, *, of: datetime) -> bool:
    """Detect the DST fall-back duplicate-fire pattern.

    ``candidate`` is a duplicate of ``of`` when:

    * Both are tz-aware (``ZoneInfo``-aware).
    * Their ``(year, month, day, hour, minute)`` tuples are equal.
    * Their absolute UTC instants differ (otherwise it's the same fire).

    During DST fall-back the same wall-clock time occurs twice in the
    source timezone — once before the offset shift and once after. The
    UTC offsets differ, so comparing ``astimezone(UTC)`` values
    distinguishes them; comparing the local components catches the
    duplicate.
    """
    if (
        candidate.year == of.year
        and candidate.month == of.month
        and candidate.day == of.day
        and candidate.hour == of.hour
        and candidate.minute == of.minute
    ):
        return candidate.astimezone(UTC) != of.astimezone(UTC)
    return False


def is_in_maintenance_window(
    window_cron: str,
    *,
    at: datetime,
    window_duration_minutes: int = 60,
    timezone: str = "UTC",
) -> bool:
    """Check if ``at`` falls inside a recurring maintenance window.

    A maintenance window is defined by:

    * ``window_cron`` — a cron expression for *when the window opens*.
    * ``window_duration_minutes`` — how long the window stays open after
      each opening (default 60 minutes).

    The function answers True when ``at`` is on or after the most-recent
    window opening AND within ``window_duration_minutes`` of it.

    Args:
        window_cron: Cron expression. NOT re-validated — call
            :func:`validate_cron` first when accepting operator input.
        at: Reference instant. Naive datetimes are interpreted in
            ``timezone``.
        window_duration_minutes: Window length in minutes; must be > 0.
        timezone: IANA timezone the cron expression is interpreted in.

    Raises:
        CronValidationError: Same taxonomy as :func:`validate_cron` for
            unknown timezones / malformed expressions.
        ValueError: For non-positive ``window_duration_minutes``. This is
            a programmer error (not operator input), so we keep the
            stdlib type rather than wrapping in our taxonomy.
    """
    if window_duration_minutes <= 0:
        raise ValueError("window_duration_minutes must be > 0")
    zone = _resolve_zone(timezone)
    at_in_zone = _ensure_aware(at, default_tz=UTC).astimezone(zone)
    # croniter.match treats `at` as a fire if it lies on a cron tick (at
    # minute granularity), so the window-opening edge is included.
    if croniter.match(window_cron, at_in_zone):
        return True
    iterator = _build_croniter(window_cron, at_in_zone)
    try:
        previous_fire = iterator.get_prev(datetime)
    except CroniterError as exc:
        raise CronValidationError("invalid cron syntax") from exc
    elapsed = at_in_zone - previous_fire
    return elapsed <= timedelta(minutes=window_duration_minutes)


def normalize_to_utc(dt: datetime, *, assume_timezone: str = "UTC") -> datetime:
    """Return a tz-aware UTC datetime equivalent to ``dt``.

    Args:
        dt: Naive or tz-aware :class:`datetime`.
        assume_timezone: When ``dt`` is naive, the IANA timezone it is
            interpreted in BEFORE being converted to UTC. Ignored for
            tz-aware inputs (those are simply :meth:`datetime.astimezone`
            -ed to UTC).

    Returns:
        Tz-aware :class:`datetime` with ``tzinfo=UTC``.

    Raises:
        CronValidationError: When ``assume_timezone`` is unknown.
            Re-uses the cron-parser taxonomy so callers have a single
            error type to handle when wiring this module into FastAPI
            error handlers.
    """
    if dt.tzinfo is None:
        zone = _resolve_zone(assume_timezone)
        dt = dt.replace(tzinfo=zone)
    return dt.astimezone(UTC)
