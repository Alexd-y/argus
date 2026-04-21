"""Thin wrapper around the third-party ``cvss`` package.

This module shields the rest of ARGUS from the slightly inconsistent
return types of :mod:`cvss` (``CVSS3`` returns ``decimal.Decimal``
scores while ``CVSS4`` returns floats). It also enforces our canonical
vector-string regex (mirrored in :class:`src.pipeline.contracts.finding_dto`)
so an upstream parser cannot smuggle a malformed vector into a
:class:`FindingDTO` constructor.

Only stdlib + ``cvss`` is imported here — no I/O, no logging beyond
warnings on parse failure (which surface to the caller as ``ValueError``).
"""

from __future__ import annotations

from decimal import Decimal
from typing import Final, Literal

from cvss import CVSS3, CVSS4
from cvss.exceptions import CVSSError
from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictStr

from src.pipeline.contracts.finding_dto import _CVSS_VECTOR_RE


_CVSSVersion = Literal["3.0", "3.1", "4.0"]


_SEVERITY_THRESHOLDS: Final[tuple[tuple[float, str], ...]] = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
)


class CVSSScore(BaseModel):
    """Parsed CVSS vector with normalised base score and severity label."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: StrictStr = Field(min_length=3, max_length=3)
    base: StrictFloat = Field(ge=0.0, le=10.0)
    severity: StrictStr = Field(min_length=3, max_length=16)
    vector: StrictStr = Field(min_length=8, max_length=128)


def parse_cvss_vector(vector: str) -> CVSSScore:
    """Parse a CVSS v3.x or v4.0 vector string into :class:`CVSSScore`.

    Raises :class:`ValueError` on syntactically or semantically invalid input.
    """
    if not isinstance(vector, str) or not vector:
        raise ValueError("CVSS vector must be a non-empty string")
    if not _CVSS_VECTOR_RE.fullmatch(vector):
        raise ValueError(f"CVSS vector does not match expected shape: {vector!r}")

    if vector.startswith("CVSS:3."):
        try:
            cvss = CVSS3(vector)
        except CVSSError as exc:
            raise ValueError(f"invalid CVSS v3 vector: {exc}") from exc
        version = "3.1" if vector.startswith("CVSS:3.1") else "3.0"
        base_value = (
            float(cvss.base_score)
            if isinstance(cvss.base_score, Decimal)
            else float(cvss.base_score)
        )
        severity_label = _normalise_v3_severity(cvss.severities())
        return CVSSScore(
            version=version,
            base=base_value,
            severity=severity_label,
            vector=vector,
        )

    if vector.startswith("CVSS:4.0"):
        try:
            cvss4 = CVSS4(vector)
        except CVSSError as exc:
            raise ValueError(f"invalid CVSS v4 vector: {exc}") from exc
        return CVSSScore(
            version="4.0",
            base=float(cvss4.base_score),
            severity=str(cvss4.severity),
            vector=vector,
        )

    raise ValueError(f"unsupported CVSS version in vector: {vector!r}")


def severity_label(score: float | None) -> str:
    """Return the qualitative severity label for a numeric CVSS base score.

    Mapping (FIRST.org CVSS v3.1 §5):
    - ``None`` / ``0.0`` → ``"None"``
    - ``0.1``-``3.9`` → ``"Low"``
    - ``4.0``-``6.9`` → ``"Medium"``
    - ``7.0``-``8.9`` → ``"High"``
    - ``9.0``-``10.0`` → ``"Critical"``
    """
    if score is None:
        return "None"
    if not isinstance(score, (int, float)):
        raise TypeError(f"severity_label expects float, got {type(score).__name__}")
    if score < 0.0 or score > 10.0:
        raise ValueError(f"severity_label score must be in [0.0, 10.0]; got {score}")
    if score == 0.0:
        return "None"
    for threshold, label in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "None"


def _normalise_v3_severity(severities: tuple[str, ...]) -> str:
    """Pick the base severity from the (base, temporal, environmental) tuple.

    The :mod:`cvss` library returns three labels — we only care about the base
    one for storage; downstream prioritisation reads the numeric score.
    """
    if not severities:
        return "None"
    base = severities[0]
    if not isinstance(base, str):
        return "None"
    return base


__all__ = [
    "CVSSScore",
    "parse_cvss_vector",
    "severity_label",
]
