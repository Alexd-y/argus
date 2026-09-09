"""Canonical severity taxonomy + deterministic aggregation.

Single source of truth for *how a finding's qualitative severity band is
derived and counted*. It deliberately keeps the four orthogonal axes of a
finding separate (see ``docs/finding-severity-and-counting.md``):

* **severity band** — impact class (this module);
* **validation** — how strongly the finding is confirmed;
* **lifecycle** — open / fixed / accepted_risk / false_positive;
* **remediation priority** — P0–P4 ordering.

Design rules enforced here (FIRST.org CVSS v3.1 §5 for the numeric scale,
ARGUS internal policy for the taxonomy):

* Absence of a CVSS score is :attr:`SeverityBand.UNKNOWN` — **never** ``0.0``.
* A genuine CVSS ``0.0`` ("None" in CVSS nomenclature) surfaces as
  :attr:`SeverityBand.INFORMATIONAL` for display; the raw CVSS ``None``
  semantics stay intact in :func:`src.findings.cvss.severity_label`.
* An unrecognised label maps to :attr:`SeverityBand.UNKNOWN` — it is
  **never** silently coerced to ``low`` or ``informational``.
* Aggregation always emits every band (including ``unknown``) so the
  bucket sum equals the population size (``sum(counts) == total``).

Pure module: stdlib + pydantic only, no I/O, no logging.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field


class SeverityBand(StrEnum):
    """Canonical qualitative severity band."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


#: Deterministic ordering (severity-descending, ``unknown`` last but always
#: present). Aggregation output keys follow this order.
SEVERITY_BANDS: Final[tuple[SeverityBand, ...]] = (
    SeverityBand.CRITICAL,
    SeverityBand.HIGH,
    SeverityBand.MEDIUM,
    SeverityBand.LOW,
    SeverityBand.INFORMATIONAL,
    SeverityBand.UNKNOWN,
)


#: Known synonyms → band. Anything absent from this table normalises to
#: :attr:`SeverityBand.UNKNOWN`; we never guess a plausible band from an
#: unrecognised string.
_LABEL_ALIASES: Final[dict[str, SeverityBand]] = {
    "critical": SeverityBand.CRITICAL,
    "crit": SeverityBand.CRITICAL,
    "high": SeverityBand.HIGH,
    # "important" is the legacy frontend label for High — mapped so historical
    # data and UI round-trips normalise correctly.
    "important": SeverityBand.HIGH,
    "medium": SeverityBand.MEDIUM,
    "moderate": SeverityBand.MEDIUM,
    "med": SeverityBand.MEDIUM,
    "low": SeverityBand.LOW,
    "info": SeverityBand.INFORMATIONAL,
    "informational": SeverityBand.INFORMATIONAL,
    "information": SeverityBand.INFORMATIONAL,
    # CVSS "None" (a real 0.0 score) is surfaced as Informational for display;
    # documented in docs/finding-severity-and-counting.md.
    "none": SeverityBand.INFORMATIONAL,
    "unknown": SeverityBand.UNKNOWN,
    "": SeverityBand.UNKNOWN,
}


def normalize_severity(raw: object) -> SeverityBand:
    """Map any raw severity value to a canonical :class:`SeverityBand`.

    ``None`` / blank / unrecognised → :attr:`SeverityBand.UNKNOWN`. Never
    coerces an unknown label to ``low`` or ``informational``.
    """
    if isinstance(raw, SeverityBand):
        return raw
    if raw is None:
        return SeverityBand.UNKNOWN
    text = str(raw).strip().lower()
    return _LABEL_ALIASES.get(text, SeverityBand.UNKNOWN)


def band_from_cvss_score(score: float | None) -> SeverityBand:
    """Map a numeric CVSS base score to a display band (FIRST.org v3.1 §5).

    * ``None`` → :attr:`SeverityBand.UNKNOWN` (missing score is not ``0``).
    * ``bool`` / ``NaN`` / ``±Inf`` / out of ``[0, 10]`` → ``UNKNOWN``
      (invalid input is not silently treated as a real score).
    * ``0.0`` → :attr:`SeverityBand.INFORMATIONAL` (CVSS "None", displayed).
    * ``0.1``–``3.9`` → ``LOW``; ``4.0``–``6.9`` → ``MEDIUM``;
      ``7.0``–``8.9`` → ``HIGH``; ``9.0``–``10.0`` → ``CRITICAL``.
    """
    if score is None or isinstance(score, bool) or not isinstance(score, (int, float)):
        return SeverityBand.UNKNOWN
    value = float(score)
    if not math.isfinite(value) or value < 0.0 or value > 10.0:
        return SeverityBand.UNKNOWN
    if value == 0.0:
        return SeverityBand.INFORMATIONAL
    if value < 4.0:
        return SeverityBand.LOW
    if value < 7.0:
        return SeverityBand.MEDIUM
    if value < 9.0:
        return SeverityBand.HIGH
    return SeverityBand.CRITICAL


class SeverityCounts(BaseModel):
    """Immutable per-band counts for one population of findings.

    Every band is always present so ``total`` always equals the population
    size; ``unknown`` is a first-class bucket, never dropped.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    informational: int = Field(default=0, ge=0)
    unknown: int = Field(default=0, ge=0)

    @property
    def total(self) -> int:
        """Population size — the sum of every band (including ``unknown``)."""
        return (
            self.critical
            + self.high
            + self.medium
            + self.low
            + self.informational
            + self.unknown
        )

    def as_dict(self) -> dict[str, int]:
        """Ordered ``band -> count`` dict (severity-descending, unknown last)."""
        return {band.value: getattr(self, band.value) for band in SEVERITY_BANDS}


def aggregate_severity(labels: Iterable[object]) -> SeverityCounts:
    """Count ``labels`` into canonical bands.

    Guarantees ``result.total == number of labels`` — every input lands in
    exactly one bucket, unrecognised inputs in ``unknown``.
    """
    acc: dict[SeverityBand, int] = dict.fromkeys(SEVERITY_BANDS, 0)
    for raw in labels:
        acc[normalize_severity(raw)] += 1
    return _counts_from_acc(acc)


def aggregate_counts(pairs: Iterable[tuple[object, int]]) -> SeverityCounts:
    """Sum pre-grouped ``(label, count)`` pairs into canonical bands.

    Use when the population is already aggregated in SQL
    (``GROUP BY severity``) — several raw labels (e.g. ``"info"`` / ``"none"``)
    fold into the same canonical band, and ``NULL`` / unrecognised labels land
    in ``unknown`` instead of being dropped.
    """
    acc: dict[SeverityBand, int] = dict.fromkeys(SEVERITY_BANDS, 0)
    for raw, count in pairs:
        acc[normalize_severity(raw)] += int(count)
    return _counts_from_acc(acc)


def _counts_from_acc(acc: dict[SeverityBand, int]) -> SeverityCounts:
    return SeverityCounts(
        critical=acc[SeverityBand.CRITICAL],
        high=acc[SeverityBand.HIGH],
        medium=acc[SeverityBand.MEDIUM],
        low=acc[SeverityBand.LOW],
        informational=acc[SeverityBand.INFORMATIONAL],
        unknown=acc[SeverityBand.UNKNOWN],
    )


__all__ = [
    "SEVERITY_BANDS",
    "SeverityBand",
    "SeverityCounts",
    "aggregate_counts",
    "aggregate_severity",
    "band_from_cvss_score",
    "normalize_severity",
]
