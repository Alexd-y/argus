"""Injectable clock for Quick budget/lease tests (no sleep).

Production uses :class:`SystemClock`. Unit tests inject :class:`FrozenClock`
and call :meth:`FrozenClock.advance` to simulate time passing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol


def as_utc(instant: datetime) -> datetime:
    """Normalize to timezone-aware UTC (naive values are treated as UTC)."""
    if instant.tzinfo is None:
        return instant.replace(tzinfo=UTC)
    return instant.astimezone(UTC)


class Clock(Protocol):
    """Time source used by :class:`~src.quick.budget.QuickBudgetManager`."""

    def now(self) -> datetime:
        """Return a timezone-aware UTC instant."""
        ...


class SystemClock:
    """Real UTC wall clock."""

    def now(self) -> datetime:
        return datetime.now(UTC)


class FrozenClock:
    """Deterministic clock. ``advance`` does not sleep."""

    def __init__(self, instant: datetime | None = None) -> None:
        self._instant = as_utc(instant) if instant is not None else datetime.now(UTC)

    def now(self) -> datetime:
        return self._instant

    def set(self, instant: datetime) -> None:
        self._instant = as_utc(instant)

    def advance(self, seconds: float) -> datetime:
        """Move the clock forward by ``seconds`` (may be fractional). Returns new instant."""
        self._instant = self._instant + timedelta(seconds=seconds)
        return self._instant


__all__ = [
    "Clock",
    "FrozenClock",
    "SystemClock",
    "as_utc",
]
