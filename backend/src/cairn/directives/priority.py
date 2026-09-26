"""Deterministic directive priority (§18.7).

The score is computed by the application (not the model) so it is reproducible for a
given input. The model only supplies the human-readable rationale text.
"""

from __future__ import annotations

_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
    "informational": 0.1,
}


def compute_priority_score(
    *,
    severity: str | None = None,
    cvss: float | None = None,
    epss: float | None = None,
    kev_listed: bool = False,
    evidence_tier: int | None = None,
    public_poc: bool = False,
    novelty: float = 0.5,
    already_explored_penalty: float = 0.0,
) -> float:
    """Return a reproducible priority in ``[0, 1]``.

    Weighted blend of severity/CVSS, EPSS, KEV membership, evidence tier, public-PoC
    availability, and how much new ground the direction covers, minus a penalty for
    proximity to already-explored directions.
    """
    sev = _SEVERITY_WEIGHT.get((severity or "").strip().lower(), 0.3)
    cvss_norm = max(0.0, min(1.0, (cvss or 0.0) / 10.0))
    epss_norm = max(0.0, min(1.0, epss or 0.0))
    kev = 1.0 if kev_listed else 0.0
    poc = 1.0 if public_poc else 0.0
    # Lower confirmed evidence → higher priority to validate (unknowns are valuable).
    tier_norm = 1.0 if evidence_tier is None else max(0.0, min(1.0, (4 - evidence_tier) / 3.0))
    nov = max(0.0, min(1.0, novelty))

    score = (
        0.28 * max(sev, cvss_norm)
        + 0.22 * epss_norm
        + 0.18 * kev
        + 0.12 * poc
        + 0.10 * tier_norm
        + 0.10 * nov
    )
    score -= max(0.0, min(1.0, already_explored_penalty)) * 0.3
    return round(max(0.0, min(1.0, score)), 4)


__all__ = ["compute_priority_score"]
