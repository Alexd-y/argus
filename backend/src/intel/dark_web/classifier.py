"""Classify a raw DWM record into exposure_type + severity + confidence + tier.

Rule-driven from the signed ``classifier_rules.yaml`` catalog. The
``evidence_tier`` is HARD-CAPPED at :data:`DWM_EVIDENCE_TIER_CAP` (2) on every
path — DWM is OSINT and never asserts CONFIRMED/EXPLOITED. A unit test asserts
no input can produce tier 3/4.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.intel.dark_web.contracts import (
    DWM_EVIDENCE_TIER_CAP,
    DarkWebConfidence,
    DarkWebRawRecord,
    DarkWebSeverity,
    DwmEvidenceTier,
    ExposureType,
)

#: DWM floor tier (INFORMATIONAL). Named, not a magic number — DWM observations
#: carry their own capped scale (1..2), decided here, NOT a Finding's arbiter tier.
_FLOOR_TIER: int = int(DwmEvidenceTier.INFORMATIONAL)


@dataclass(frozen=True)
class Classification:
    exposure_type: ExposureType
    severity: DarkWebSeverity
    confidence: DarkWebConfidence
    evidence_tier: int


_DEFAULT = Classification(
    exposure_type=ExposureType.MENTION,
    severity=DarkWebSeverity.INFO,
    confidence=DarkWebConfidence.ADVISORY,
    evidence_tier=_FLOOR_TIER,
)


def _cap_tier(value: Any) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return 1
    if v < 1:
        return 1
    return min(v, DWM_EVIDENCE_TIER_CAP)


def _coerce_exposure(value: Any, fallback: ExposureType) -> ExposureType:
    try:
        return ExposureType(str(value))
    except ValueError:
        return fallback


def _coerce_severity(value: Any) -> DarkWebSeverity:
    try:
        return DarkWebSeverity(str(value))
    except ValueError:
        return DarkWebSeverity.INFO


def _coerce_confidence(value: Any) -> DarkWebConfidence:
    try:
        return DarkWebConfidence(str(value))
    except ValueError:
        return DarkWebConfidence.ADVISORY


def classify(record: DarkWebRawRecord, rules: dict[str, Any] | None = None) -> Classification:
    """Return a classification for a raw record; first matching rule wins.

    ``rules`` is the parsed ``classifier_rules.yaml`` (``{defaults, rules}``). If
    omitted, a conservative default (MENTION / INFO / tier 1) is used.
    """

    hay = " ".join(
        [
            (record.exposure_hint.value if record.exposure_hint else ""),
            record.source_ref or "",
            record.content or "",
        ]
    ).lower()

    rules = rules or {}
    defaults = rules.get("defaults") if isinstance(rules.get("defaults"), dict) else {}
    rule_list = rules.get("rules") if isinstance(rules.get("rules"), list) else []

    # Seed from the collector's own exposure hint, then let rules refine.
    hinted = record.exposure_hint or _DEFAULT.exposure_type

    for rule in rule_list:
        if not isinstance(rule, dict):
            continue
        needles = rule.get("match") or []
        if not isinstance(needles, list):
            continue
        if any(isinstance(n, str) and n.lower() in hay for n in needles):
            return Classification(
                exposure_type=_coerce_exposure(rule.get("exposure_type"), hinted),
                severity=_coerce_severity(rule.get("severity")),
                confidence=_coerce_confidence(rule.get("confidence")),
                evidence_tier=_cap_tier(rule.get("evidence_tier", 1)),
            )

    # No rule matched — fall back to defaults (catalog or module default).
    if defaults:
        return Classification(
            exposure_type=_coerce_exposure(defaults.get("exposure_type"), hinted),
            severity=_coerce_severity(defaults.get("severity")),
            confidence=_coerce_confidence(defaults.get("confidence")),
            evidence_tier=_cap_tier(defaults.get("evidence_tier", 1)),
        )
    return Classification(
        exposure_type=hinted,
        severity=_DEFAULT.severity,
        confidence=_DEFAULT.confidence,
        evidence_tier=_FLOOR_TIER,
    )


__all__ = ["Classification", "classify"]
