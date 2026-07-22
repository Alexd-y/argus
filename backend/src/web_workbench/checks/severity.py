"""Shared coarse severity → representative CVSS v3.1 mapping for WB checks.

A single source of truth for the workbench native checks so every module maps a
coarse severity to the same canonical CVSS vector/score when projecting to a
:class:`~src.pipeline.contracts.finding_dto.FindingDTO`. Scores are the standard
CVSS values for their vectors (conservative but defensible).
"""

from __future__ import annotations

from enum import StrEnum


class CheckSeverity(StrEnum):
    """Coarse severity shared by workbench native checks."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_CVSS: dict[CheckSeverity, tuple[str, float]] = {
    CheckSeverity.INFO: ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
    CheckSeverity.LOW: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    CheckSeverity.MEDIUM: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4),
    CheckSeverity.HIGH: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    CheckSeverity.CRITICAL: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
}


def cvss_for(severity: CheckSeverity) -> tuple[str, float]:
    """Return the (vector, score) pair for a coarse severity (fail-closed)."""
    try:
        return _SEVERITY_CVSS[severity]
    except KeyError as exc:  # pragma: no cover - guards a new unmapped member.
        raise ValueError(f"unmapped check severity: {severity!r}") from exc


__all__ = ["CheckSeverity", "cvss_for"]
