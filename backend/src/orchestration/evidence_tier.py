"""Evidence tier classification for pentest findings.

Implements a 4-level evidence hierarchy inspired by Shannon's
""No Exploit, No Report"" policy but more granular:

- EXPLOITED (4): Working payload, proven impact.  The highest bar.
- CONFIRMED (3): Vulnerability reproduced but full exploit not demonstrated.
- SUSPECTED (2): Code analysis / taint analysis found a path; exploitation
  did not succeed (WAF, timeout, context limit, etc.).
- INFORMATIONAL (1): Recommendation or best-practice finding without
  direct exploitation evidence.

This replaces the binary ""exploited / not-exploited"" approach with a
staircase that gives CISOs the full picture rather than silently
discarding findings that couldn't be exploited within the scan window.
"""

from __future__ import annotations

from enum import IntEnum

from src.pipeline.contracts.finding_dto import ConfidenceLevel


class EvidenceTier(IntEnum):
    """4-level evidence classification for pentest findings.

    Higher values mean stronger evidence of exploitability.
    Ordered so that ``tier_a > tier_b`` comparisons work naturally.
    """

    INFORMATIONAL = 1
    SUSPECTED = 2
    CONFIRMED = 3
    EXPLOITED = 4


EVIDENCE_TIER_LABELS: dict[EvidenceTier, str] = {
    EvidenceTier.EXPLOITED: "Exploited",
    EvidenceTier.CONFIRMED: "Confirmed",
    EvidenceTier.SUSPECTED: "Suspected",
    EvidenceTier.INFORMATIONAL: "Informational",
}

EVIDENCE_TIER_DESCRIPTIONS: dict[EvidenceTier, str] = {
    EvidenceTier.EXPLOITED: (
        "Working proof-of-concept exploit demonstrated. "
        "Impact is proven with screenshot, pcap, or shell access."
    ),
    EvidenceTier.CONFIRMED: (
        "Vulnerability is confirmed to exist (e.g., reflected input, "
        "error leak, timing delta) but a full exploit chain was not "
        "demonstrated."
    ),
    EvidenceTier.SUSPECTED: (
        "Source code or taint analysis identified a vulnerable path, "
        "but exploitation did not succeed (WAF, timeout, context limit, "
        "or other environmental constraint)."
    ),
    EvidenceTier.INFORMATIONAL: (
        "Recommendation or best-practice finding without direct "
        "exploitation evidence (e.g., missing security headers, "
        "verbose error messages, insecure configuration)."
    ),
}


def classify_finding(
    confidence: ConfidenceLevel,
    has_payload: bool = False,
    has_evidence: bool = False,
) -> EvidenceTier:
    """Map an existing ``ConfidenceLevel`` to an ``EvidenceTier``.

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
