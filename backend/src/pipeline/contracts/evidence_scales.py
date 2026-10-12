"""Derived evidence scales (R-5.1.3 – R-5.1.5).

The canonical measure of evidence strength is :class:`EvidenceTier`. Every other
scale in the codebase — ``confidence``, ``validation``, the ``EvidenceQuality``
(none/weak/moderate/strong) scale and the ``EvidenceGate``
(validated/observed/candidate/inconclusive) scale — is **derived** from the
canonical tier by a pure, total, one-way function defined here. There are no
reverse mappings: you never reconstruct a tier from a derived scale.

This module also owns the two shared string aliases
(:data:`EvidenceQualityName`, :data:`EvidenceGateName`) so the several modules
that previously each re-declared the same ``Literal[...]`` import one definition.

Axis note (R-5.1.3 escape hatch): the derivations here map *the canonical tier*
onto each scale. That is distinct from the *input-scoring* helpers
``finding_gate.evidence_quality_of`` (scores a raw finding dict) and
``evidence_gates.calculate_evidence_gate`` (scores PoC-field completeness):
those decide a level from raw inputs and are not derivations from the tier. Both
axes are legitimate; only the tier→scale direction lives here.
"""

from __future__ import annotations

from typing import Literal

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    EvidenceTier,
    ValidationState,
)

#: Shared alias for the none/weak/moderate/strong evidence-quality scale.
EvidenceQualityName = Literal["none", "weak", "moderate", "strong"]
#: Shared alias for the evidence-gate / classification scale.
EvidenceGateName = Literal["validated", "observed", "candidate", "inconclusive"]


# --- tier -> derived scale (pure, total, one-way) ----------------------------

_CONFIDENCE_FOR_TIER: dict[EvidenceTier, ConfidenceLevel] = {
    EvidenceTier.EXPLOITED: ConfidenceLevel.EXPLOITABLE,
    EvidenceTier.CONFIRMED: ConfidenceLevel.CONFIRMED,
    EvidenceTier.SUSPECTED: ConfidenceLevel.LIKELY,
    EvidenceTier.INFORMATIONAL: ConfidenceLevel.SUSPECTED,
}

_VALIDATION_FOR_TIER: dict[EvidenceTier, ValidationState] = {
    EvidenceTier.EXPLOITED: ValidationState.CONFIRMED,
    EvidenceTier.CONFIRMED: ValidationState.CONFIRMED,
    EvidenceTier.SUSPECTED: ValidationState.SUSPECTED,
    EvidenceTier.INFORMATIONAL: ValidationState.INCONCLUSIVE,
}

_QUALITY_FOR_TIER: dict[EvidenceTier, EvidenceQualityName] = {
    EvidenceTier.EXPLOITED: "strong",
    EvidenceTier.CONFIRMED: "strong",
    EvidenceTier.SUSPECTED: "moderate",
    EvidenceTier.INFORMATIONAL: "weak",
}

_GATE_FOR_TIER: dict[EvidenceTier, EvidenceGateName] = {
    EvidenceTier.EXPLOITED: "validated",
    EvidenceTier.CONFIRMED: "validated",
    EvidenceTier.SUSPECTED: "observed",
    EvidenceTier.INFORMATIONAL: "candidate",
}


def confidence_for_tier(tier: EvidenceTier) -> ConfidenceLevel:
    """Derive the legacy ``confidence`` level from the canonical tier."""
    return _CONFIDENCE_FOR_TIER[tier]


def validation_for_tier(tier: EvidenceTier) -> ValidationState:
    """Derive the ``validation`` (evidence-strength) state from the tier."""
    return _VALIDATION_FOR_TIER[tier]


def evidence_quality_for_tier(tier: EvidenceTier) -> EvidenceQualityName:
    """Derive the none/weak/moderate/strong quality name from the tier."""
    return _QUALITY_FOR_TIER[tier]


def evidence_gate_for_tier(tier: EvidenceTier) -> EvidenceGateName:
    """Derive the validated/observed/candidate/inconclusive gate from the tier."""
    return _GATE_FOR_TIER[tier]


__all__ = [
    "EvidenceGateName",
    "EvidenceQualityName",
    "confidence_for_tier",
    "evidence_gate_for_tier",
    "evidence_quality_for_tier",
    "validation_for_tier",
]
