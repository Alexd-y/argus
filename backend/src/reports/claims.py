"""Claim contract (Part II, Phase I) — the provability substrate for Valhalla reports.

Normative base: ``EVD-01``…``EVD-08`` in
``docs/valhalla-pentest-report-requirements-2026-09-11.md`` §5, and §13–14 of
``CURSOR_VALHALLA_REPORT_FIX_PROMPT.md``.

Operational meaning of *"100% provable"*: **every statement presented as fact traces
to primary material; everything else is explicitly marked as inference, hypothesis or
not-assessed.** Three rules follow:

1. No evidence → no fact. An ``observed`` / ``confirmed_vulnerability`` claim without a
   resolvable ``evidence_id`` cannot be asserted in the indicative mood.
2. A negation also needs evidence. "Not vulnerable" requires an executed test with a
   recorded result — absence of a scanner finding is ``not_assessed``, not ``passed``.
3. Observation, inference and impact are distinct. Reachability ≠ exploitability;
   reflection ≠ script execution; a version banner ≠ a confirmed build vulnerability.

This module is **pure** (no DB / LLM / network). ``validate_claim`` yields structured
violations; the report release gate (``valhalla_release_blockers``) consumes them so a
defective claim blocks the release instead of shipping an unprovable assertion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class ClaimType(StrEnum):
    """Epistemic status of a report statement (prompt §14.1)."""

    OBSERVED = "observed"
    CONFIRMED_VULNERABILITY = "confirmed_vulnerability"
    DERIVED_INFERENCE = "derived_inference"
    HYPOTHESIS = "hypothesis"
    RECOMMENDATION = "recommendation"
    CLIENT_STATEMENT = "client_statement"
    NOT_ASSESSED = "not_assessed"
    NOT_APPLICABLE = "not_applicable"


#: Claim types that assert a fact in the indicative mood and therefore REQUIRE at least
#: one resolvable evidence id (EVD-01, AC-02).
_EVIDENCE_REQUIRED: frozenset[ClaimType] = frozenset(
    {ClaimType.OBSERVED, ClaimType.CONFIRMED_VULNERABILITY}
)

#: Claim types that must NOT use certainty modality in their text (prompt §14.2).
_NON_ASSERTIVE: frozenset[ClaimType] = frozenset(
    {ClaimType.HYPOTHESIS, ClaimType.DERIVED_INFERENCE}
)

#: Certainty modality tokens forbidden in non-assertive claims (RU + EN).
_CERTAINTY_MODALITY: tuple[str, ...] = (
    "доказано",
    "подтверждено",
    "подтверждена",
    "позволяет",
    "гарантирует",
    "proven",
    "confirmed",
    "demonstrably",
    "allows an attacker to",
)

_CERTAINTY_RE = re.compile("|".join(re.escape(tok) for tok in _CERTAINTY_MODALITY), re.IGNORECASE)


#: Default validator registry (AC-01). A ``validator`` on a claim must be one of these
#: (or registered via :func:`register_validators`) — never a free-form string.
_VALIDATOR_REGISTRY: set[str] = {
    "wrb_exploit_validator",
    "sandbox_replay",
    "oast_interactsh",
    "headless_browser_dom",
    "sqlmap",
    "nuclei",
    "dalfox",
    "manual_reviewer",
    "boolean_control",
    "negative_control",
}


def register_validators(*validator_ids: str) -> None:
    """Extend the validator registry (idempotent). Used at wiring time, not per-claim."""
    for vid in validator_ids:
        v = vid.strip()
        if v:
            _VALIDATOR_REGISTRY.add(v)


def is_registered_validator(validator: str) -> bool:
    return validator.strip() in _VALIDATOR_REGISTRY


@dataclass
class Claim:
    """A single, atomic report statement traceable to primary material (prompt §14.1)."""

    claim_id: str
    claim_type: ClaimType
    text: str
    subject: str
    evidence_ids: list[str] = field(default_factory=list)
    derived_from: list[str] = field(default_factory=list)
    test_execution_ids: list[str] = field(default_factory=list)
    limitations: str = ""
    validator: str | None = None
    reviewer: str | None = None
    confidence: float | None = None
    confidence_calibration: str | None = None
    scope_version: str = ""
    captured_at_utc: str = ""

    def is_high_severity(self) -> bool:
        return False  # severity is a finding property; overridden by callers if needed


@dataclass
class ClaimViolation:
    claim_id: str
    rule: str
    reason: str


def validate_claim(claim: Claim, *, high_severity: bool = False) -> list[ClaimViolation]:
    """Return the blocking violations for a single claim (prompt §14.2).

    ``high_severity`` marks findings with ``severity >= high``: they require a
    registered reviewer sign-off before release.
    """
    v: list[ClaimViolation] = []
    ct = claim.claim_type

    # Evidence required for asserted facts (EVD-01 / AC-02 upstream resolution).
    if ct in _EVIDENCE_REQUIRED and not [e for e in claim.evidence_ids if str(e).strip()]:
        v.append(
            ClaimViolation(
                claim.claim_id,
                "evidence_required",
                f"claim_type '{ct}' asserts a fact but has no evidence_ids",
            )
        )

    # A derived inference must cite the claims it was derived from.
    if ct == ClaimType.DERIVED_INFERENCE and not [d for d in claim.derived_from if str(d).strip()]:
        v.append(
            ClaimViolation(
                claim.claim_id,
                "derived_from_required",
                "derived_inference claim has no derived_from references",
            )
        )

    # Confidence is only admissible when its calibration is described (else dropped).
    if claim.confidence is not None and not (claim.confidence_calibration or "").strip():
        v.append(
            ClaimViolation(
                claim.claim_id,
                "confidence_without_calibration",
                "confidence set without a calibration description — field must be dropped",
            )
        )

    # Non-assertive claims may not use certainty modality.
    if ct in _NON_ASSERTIVE and _CERTAINTY_RE.search(claim.text or ""):
        v.append(
            ClaimViolation(
                claim.claim_id,
                "certainty_in_non_assertive",
                f"claim_type '{ct}' uses certainty modality; rephrase required",
            )
        )

    # Validator must be from the registry (AC-01).
    if claim.validator is not None and not is_registered_validator(claim.validator):
        v.append(
            ClaimViolation(
                claim.claim_id,
                "unregistered_validator",
                f"validator '{claim.validator}' is not in the validator registry",
            )
        )

    # High-severity findings require a human reviewer sign-off before release.
    if high_severity and not (claim.reviewer or "").strip():
        v.append(
            ClaimViolation(
                claim.claim_id,
                "reviewer_required",
                "severity >= high requires a reviewer sign-off before release",
            )
        )

    return v


def sanitized_confidence(claim: Claim) -> float | None:
    """Return the confidence only if calibration is described, else ``None`` (§14.2)."""
    if claim.confidence is not None and (claim.confidence_calibration or "").strip():
        return claim.confidence
    return None


def resolve_evidence_ids(
    claims: list[Claim], available_evidence_ids: set[str]
) -> list[ClaimViolation]:
    """Flag evidence references that do not resolve within the scan's evidence set (AC-02)."""
    violations: list[ClaimViolation] = []
    for claim in claims:
        for eid in claim.evidence_ids:
            if str(eid).strip() and str(eid).strip() not in available_evidence_ids:
                violations.append(
                    ClaimViolation(
                        claim.claim_id,
                        "unresolvable_evidence",
                        f"evidence_id '{eid}' does not resolve in this scan's evidence set",
                    )
                )
    return violations


__all__ = [
    "Claim",
    "ClaimType",
    "ClaimViolation",
    "is_registered_validator",
    "register_validators",
    "resolve_evidence_ids",
    "sanitized_confidence",
    "validate_claim",
]
