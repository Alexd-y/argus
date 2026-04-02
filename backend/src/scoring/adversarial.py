"""Adversarial Prioritization Score — ranks findings by realistic exploitability.

Formula: (Impact × Exploitability) / Detection_Time, with boost modifiers.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_SEVERITY_IMPACT: dict[str, float] = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.5,
}

_CONFIDENCE_EXPLOITABILITY: dict[str, float] = {
    "confirmed": 9.0,
    "likely": 7.0,
    "possible": 4.0,
    "theoretical": 1.0,
    "advisory": 0.5,
}

_SILENT_OWASP: frozenset[str] = frozenset({"A01", "A04", "A10"})
_NOISY_OWASP: frozenset[str] = frozenset({"A03", "A05"})

_HIGH_IMPACT_OWASP: frozenset[str] = frozenset({"A01", "A02", "A07"})


def compute_adversarial_score(finding: dict[str, Any]) -> float:
    """Compute adversarial prioritization score for a finding dict.

    Args:
        finding: dict with keys matching Finding model fields.
            Required: severity
            Optional: cvss, confidence, owasp_category, cvss_vector,
                      shodan_confirmed, exploit_public, poc_code/proof_of_concept

    Returns:
        Score 0.0-10.0 (clamped).
    """
    impact = _impact_score(finding)
    exploitability = _exploitability_score(finding)
    detection = _detection_time_score(finding)

    base = (impact * exploitability) / max(detection, 1.0)

    if finding.get("shodan_confirmed"):
        base *= 1.5
    if finding.get("exploit_public"):
        base *= 2.0
    poc = finding.get("proof_of_concept") or finding.get("poc_code")
    if poc:
        base *= 1.3

    return round(min(base, 10.0), 2)


def _impact_score(f: dict[str, Any]) -> float:
    severity = (f.get("severity") or "medium").lower()
    base = _SEVERITY_IMPACT.get(severity, 3.0)

    cvss = f.get("cvss")
    if isinstance(cvss, (int, float)) and 0 <= cvss <= 10:
        base = float(cvss)

    owasp = _normalize_owasp(f.get("owasp_category"))
    if owasp in _HIGH_IMPACT_OWASP:
        base = min(base * 1.2, 10.0)

    return base


def _exploitability_score(f: dict[str, Any]) -> float:
    confidence = (f.get("confidence") or "likely").lower()
    score = _CONFIDENCE_EXPLOITABILITY.get(confidence, 5.0)

    cvss_vec = f.get("cvss_vector") or ""
    if isinstance(cvss_vec, str) and "AV:N/AC:L/PR:N" in cvss_vec:
        score = min(score + 2.0, 10.0)

    return score


def _detection_time_score(f: dict[str, Any]) -> float:
    """Higher = harder to detect = more dangerous (used as divisor)."""
    owasp = _normalize_owasp(f.get("owasp_category"))
    if owasp in _SILENT_OWASP:
        return 8.0
    if owasp in _NOISY_OWASP:
        return 3.0
    return 5.0


def _normalize_owasp(val: Any) -> str:
    if not isinstance(val, str) or not val.strip():
        return ""
    v = val.strip().upper()
    if v.startswith("A") and len(v) >= 3:
        return v[:3]
    return v


def score_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Compute adversarial_score for each finding and sort descending."""
    for f in findings:
        f["adversarial_score"] = compute_adversarial_score(f)
    return sorted(findings, key=lambda f: f.get("adversarial_score", 0), reverse=True)
