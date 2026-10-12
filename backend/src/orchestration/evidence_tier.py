"""Evidence tier classification for pentest findings.

The canonical ``EvidenceTier`` enum and its label/description tables live in
:mod:`src.pipeline.contracts.finding_dto` (R-5.1.1) — the shared contracts
package, where ``EvidenceDTO`` / ``FindingDTO`` already live. This module
re-exports them so the existing consumers that import from
``src.orchestration.evidence_tier`` keep working unchanged during the
transition.

``classify_finding`` is retained here as a *legacy* mapping from the model's
self-assessed ``ConfidenceLevel`` to a tier. Deriving a tier from the model's
own confidence is exactly what wave 1 moves away from; the sanctioned path is
the artifact-driven arbiter in
:mod:`src.pipeline.contracts.evidence_arbiter`. This function is kept only for
callers that do not yet have collected artifacts available.
"""

from __future__ import annotations

import warnings

from src.pipeline.contracts.finding_dto import (
    EVIDENCE_TIER_DESCRIPTIONS,
    EVIDENCE_TIER_LABELS,
    ConfidenceLevel,
    EvidenceTier,
)


def classify_finding(
    confidence: ConfidenceLevel,
    has_payload: bool = False,
    has_evidence: bool = False,
) -> EvidenceTier:
    """Map an existing ``ConfidenceLevel`` to an ``EvidenceTier``.

    .. deprecated:: wave-1
        This derives the evidence tier from the model's *self-assessed*
        ``ConfidenceLevel`` rather than from collected artifacts — exactly the
        conflation of "the model is confident" with "it is proven" that wave 1
        removes (R-5.1.2, R-5.1.6). Decide tiers with
        :func:`src.pipeline.contracts.evidence_arbiter.adjudicate`, which takes
        only collected ``EvidenceDTO`` artifacts. This shim is kept only for
        callers that do not yet have artifacts available (see their
        ``TODO(wave-2)`` markers) and will be removed once wave 2 wires
        evidence collection everywhere.

    Mapping rules:

    * ``EXPLOITABLE`` + working payload → ``EXPLOITED``
    * ``EXPLOITABLE`` without payload → ``CONFIRMED``
    * ``CONFIRMED`` → ``CONFIRMED``
    * ``LIKELY`` + any evidence → ``SUSPECTED``
    * ``LIKELY`` without evidence → ``INFORMATIONAL``
    * ``SUSPECTED`` → ``INFORMATIONAL``

    Parameters
    ----------
    confidence:
        The legacy confidence level from the finding.
    has_payload:
        Whether a working exploit payload was demonstrated.
    has_evidence:
        Whether any tool evidence supports the finding.

    Returns
    -------
    EvidenceTier
    """
    warnings.warn(
        "classify_finding derives an evidence tier from the model's "
        "self-assessed ConfidenceLevel; use evidence_arbiter.adjudicate with "
        "collected artifacts instead (R-5.1.2/R-5.1.6).",
        DeprecationWarning,
        stacklevel=2,
    )
    if confidence == ConfidenceLevel.EXPLOITABLE:
        if has_payload:
            return EvidenceTier.EXPLOITED
        return EvidenceTier.CONFIRMED
    if confidence == ConfidenceLevel.CONFIRMED:
        return EvidenceTier.CONFIRMED
    if confidence == ConfidenceLevel.LIKELY:
        if has_evidence:
            return EvidenceTier.SUSPECTED
        return EvidenceTier.INFORMATIONAL
    return EvidenceTier.INFORMATIONAL


__all__ = [
    "EVIDENCE_TIER_DESCRIPTIONS",
    "EVIDENCE_TIER_LABELS",
    "EvidenceTier",
    "classify_finding",
]
