"""Canonical finding taxonomy — the four orthogonal axes of a finding.

Severity (impact) lives in :mod:`src.findings.severity`. This module owns the
*other three* axes plus record classification, so the whole pipeline
(ingestion → persistence → API → report → frontend/exports) agrees on one
vocabulary instead of overloading ``confidence`` / ``status`` /
``false_positive`` / ``verdict`` in ad-hoc ways.

Axes (see ``docs/finding-severity-and-counting.md``):

* **record_kind** — *what* the record is: a vulnerability, a hardening gap,
  or a pure informational observation. Orthogonal to severity: an
  informational record is not automatically low severity, and a hardening
  gap can still be high impact.
* **validation** — *how strongly proven*: confirmed / suspected /
  inconclusive / rejected. This is evidence strength, NOT lifecycle.
* **lifecycle** — *operational state*: open / fixed / accepted_risk /
  false_positive.
* **remediation_priority** — P0–P4 ordering for the fix queue. Distinct from
  severity: severity is impact, priority folds in exploitability/exposure.

The module is pure (stdlib only). Every ``normalize_*`` helper is total:
unknown/blank input maps to the safest non-destructive default and never
raises, so legacy rows with ad-hoc strings still classify deterministically.
"""

from __future__ import annotations

from typing import Final

from src.findings.severity import SeverityBand, normalize_severity

# The enum vocabulary lives in the contracts layer (pure, no ``findings``
# dependency) to keep the pipeline DTO importable without pulling in the whole
# ``findings`` package. This module owns the *behaviour* (normalisation /
# derivation) and re-exports the enums so callers can use either path.
from src.pipeline.contracts.finding_dto import (
    Lifecycle,
    RecordKind,
    RemediationPriority,
    ValidationState,
)

# --- validation ------------------------------------------------------------

#: Legacy ``confidence`` (DTO ``ConfidenceLevel`` + DB values) → validation.
_CONFIDENCE_TO_VALIDATION: Final[dict[str, ValidationState]] = {
    "confirmed": ValidationState.CONFIRMED,
    "exploitable": ValidationState.CONFIRMED,
    "exploited": ValidationState.CONFIRMED,
    "likely": ValidationState.SUSPECTED,
    "suspected": ValidationState.SUSPECTED,
    "possible": ValidationState.SUSPECTED,
    "advisory": ValidationState.INCONCLUSIVE,
    "inconclusive": ValidationState.INCONCLUSIVE,
    "rejected": ValidationState.REJECTED,
    "false_positive": ValidationState.REJECTED,
}


def normalize_validation(
    *,
    confidence: object = None,
    false_positive: bool | None = None,
    verdict: object = None,
) -> ValidationState:
    """Derive the canonical validation state from legacy fields.

    Precedence: an explicit false-positive flag wins (a rejected finding is
    rejected regardless of how confident the tool was); then ``verdict`` /
    ``confidence`` map through :data:`_CONFIDENCE_TO_VALIDATION`; anything
    unrecognised is :attr:`ValidationState.INCONCLUSIVE` (never silently
    "confirmed").
    """
    if false_positive is True:
        return ValidationState.REJECTED
    for raw in (verdict, confidence):
        if raw is None:
            continue
        mapped = _CONFIDENCE_TO_VALIDATION.get(str(raw).strip().lower())
        if mapped is not None:
            return mapped
    return ValidationState.INCONCLUSIVE


# --- lifecycle -------------------------------------------------------------

#: Legacy ``status`` (DTO ``FindingStatus``) → lifecycle.
_STATUS_TO_LIFECYCLE: Final[dict[str, Lifecycle]] = {
    "new": Lifecycle.OPEN,
    "open": Lifecycle.OPEN,
    "validated": Lifecycle.OPEN,
    "fixed": Lifecycle.FIXED,
    "resolved": Lifecycle.FIXED,
    "accepted_risk": Lifecycle.ACCEPTED_RISK,
    "accepted": Lifecycle.ACCEPTED_RISK,
    "false_positive": Lifecycle.FALSE_POSITIVE,
}


def normalize_lifecycle(
    *,
    status: object = None,
    false_positive: bool | None = None,
) -> Lifecycle:
    """Derive the canonical lifecycle from legacy ``status`` / ``false_positive``.

    A ``false_positive=True`` flag always wins. Otherwise ``status`` maps
    through :data:`_STATUS_TO_LIFECYCLE`; unknown/blank → :attr:`Lifecycle.OPEN`
    (an unclassified finding is still open, never silently closed).
    """
    if false_positive is True:
        return Lifecycle.FALSE_POSITIVE
    if status is not None:
        mapped = _STATUS_TO_LIFECYCLE.get(str(status).strip().lower())
        if mapped is not None:
            return mapped
    return Lifecycle.OPEN


# --- record kind -----------------------------------------------------------

#: Severity bands that, absent other signal, imply an informational record.
_INFORMATIONAL_BANDS: Final[frozenset[SeverityBand]] = frozenset(
    {SeverityBand.INFORMATIONAL}
)

#: OWASP / category tokens that read as hardening rather than an exploitable
#: vulnerability. Kept intentionally small and explicit.
_HARDENING_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "misconfig",
        "misconfiguration",
        "hardening",
        "best_practice",
        "best-practice",
        "security_header",
        "security-header",
        "headers",
        "tls_config",
        "cipher",
    }
)


def normalize_record_kind(
    *,
    category: object = None,
    severity: object = None,
    explicit: object = None,
) -> RecordKind:
    """Classify the record kind.

    Precedence: an ``explicit`` value (already one of the canonical tokens)
    wins; then category tokens flagged as hardening; then an informational
    severity band; otherwise the record is treated as a vulnerability.
    """
    if explicit is not None:
        token = str(explicit).strip().lower()
        for kind in RecordKind:
            if token == kind.value:
                return kind
    cat = str(category or "").strip().lower()
    if cat in _HARDENING_TOKENS:
        return RecordKind.HARDENING
    if normalize_severity(severity) in _INFORMATIONAL_BANDS:
        return RecordKind.INFORMATIONAL
    return RecordKind.VULNERABILITY


# --- remediation priority --------------------------------------------------

#: Default severity-band → priority when no exploitability signal is present.
_BAND_TO_PRIORITY: Final[dict[SeverityBand, RemediationPriority]] = {
    SeverityBand.CRITICAL: RemediationPriority.P0,
    SeverityBand.HIGH: RemediationPriority.P1,
    SeverityBand.MEDIUM: RemediationPriority.P2,
    SeverityBand.LOW: RemediationPriority.P3,
    SeverityBand.INFORMATIONAL: RemediationPriority.P4,
    SeverityBand.UNKNOWN: RemediationPriority.P4,
}


def derive_remediation_priority(
    *,
    severity: object = None,
    kev_listed: bool = False,
    epss_score: float | None = None,
) -> RemediationPriority:
    """Deterministically derive P0–P4 from severity + exploitability signal.

    Severity gives the base band; a KEV listing or high EPSS (>= 0.5) bumps
    the priority one step more urgent (never past ``P0``). This keeps
    remediation priority distinct from raw severity while staying fully
    reproducible for identical inputs.
    """
    base = _BAND_TO_PRIORITY[normalize_severity(severity)]
    order = [
        RemediationPriority.P4,
        RemediationPriority.P3,
        RemediationPriority.P2,
        RemediationPriority.P1,
        RemediationPriority.P0,
    ]
    idx = order.index(base)
    bump = 1 if (kev_listed or (epss_score is not None and epss_score >= 0.5)) else 0
    return order[min(idx + bump, len(order) - 1)]


__all__ = [
    "Lifecycle",
    "RecordKind",
    "RemediationPriority",
    "ValidationState",
    "derive_remediation_priority",
    "normalize_lifecycle",
    "normalize_record_kind",
    "normalize_validation",
]
