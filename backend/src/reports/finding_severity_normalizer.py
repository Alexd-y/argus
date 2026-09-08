"""Normalize severity based on CVSS v3.1 score ranges."""

from __future__ import annotations

import logging

from src.findings.cvss import parse_cvss_vector

logger = logging.getLogger(__name__)

# Representative base score per severity band, used when the declared severity is
# authoritative but the numeric score/vector contradicts it (auto-generated
# garbage). Midpoint-ish values keep score↔severity internally consistent.
_REPRESENTATIVE_SCORE: dict[str, float] = {
    "info": 0.0,
    "low": 3.5,
    "medium": 5.5,
    "high": 7.5,
    "critical": 9.0,
}

CVSS_SEVERITY_RANGES: list[tuple[float, float, str]] = [
    (0.0, 0.0, "info"),
    (0.1, 3.9, "low"),
    (4.0, 6.9, "medium"),
    (7.0, 8.9, "high"),
    (9.0, 10.0, "critical"),
]


def normalize_findings_severity(findings: list) -> list:
    """
    For each finding with a CVSS score, verify that the assigned severity
    matches the CVSS v3.1 standard ranges. If not, override severity
    with the CVSS-derived value and log a warning.
    """
    if not findings:
        return findings

    corrected_count = 0
    for f in findings:
        cvss = _get_cvss(f)
        if cvss is None:
            continue

        current_severity = (_get_attr(f, "severity") or "").strip().lower()
        expected_severity = severity_from_cvss(cvss)

        if expected_severity and current_severity != expected_severity:
            logger.warning(
                "Severity mismatch corrected: assigned=%s, cvss=%.1f, expected=%s",
                current_severity,
                cvss,
                expected_severity,
            )
            _set_attr(f, "severity", expected_severity)
            corrected_count += 1

    if corrected_count > 0:
        logger.info(
            "Severity normalization corrected %d findings",
            corrected_count,
        )

    return findings


def severity_from_cvss(cvss: float) -> str | None:
    """Map a CVSS v3.1 score to its standard severity string."""
    for low, high, severity in CVSS_SEVERITY_RANGES:
        if low <= cvss <= high:
            return severity
    return None


def _vector_base_score(vector: str) -> float | None:
    """Authoritative base score from a CVSS vector, or ``None`` if unparseable."""
    v = (vector or "").strip()
    if not v:
        return None
    try:
        return float(parse_cvss_vector(v).base)
    except (ValueError, TypeError):
        return None


def reconcile_findings_cvss(findings: list) -> list:
    """Make ``severity`` / ``cvss`` / ``cvss_score`` / ``cvss_vector`` agree.

    Historical defect: independent producers stamped a numeric ``cvss``, a
    computed ``cvss_score``, and a ``cvss_vector`` that all disagreed (e.g. a
    "no CAA record" finding declared ``severity=low`` yet carried a
    ``cvss_vector`` scoring 7.4). The report then showed contradictory numbers.

    Deterministic reconciliation (no severity inflation):

    1. Trust ``cvss_vector`` only when it parses AND (no declared severity, or
       its band equals the declared severity band). A contradicting vector is
       treated as auto-generated noise and dropped.
    2. Otherwise use the numeric score (``cvss_score`` then ``cvss``).
    3. If a declared severity still contradicts the chosen numeric band, the
       declared severity wins (it is rule/analyst-assigned) and the score is set
       to a representative value for that band.
    4. Write the single agreed ``cvss`` == ``cvss_score`` == derived base and
       ``severity`` == band(base); keep ``cvss_vector`` only when consistent.
    """
    if not findings:
        return findings

    for f in findings:
        declared = (_get_attr(f, "severity") or "").strip().lower()
        declared = declared if declared in _REPRESENTATIVE_SCORE else ""
        vector = str(_get_attr(f, "cvss_vector") or "").strip()

        base: float | None = None
        keep_vector = False

        vec_base = _vector_base_score(vector)
        if vec_base is not None:
            vec_band = severity_from_cvss(vec_base)
            if not declared or vec_band == declared:
                base, keep_vector = vec_base, True

        if base is None:
            numeric = _get_cvss(f)  # cvss_score → cvss → poc mirror
            if numeric is not None:
                num_band = severity_from_cvss(numeric)
                if not declared or num_band == declared:
                    base = numeric
                else:
                    base = _REPRESENTATIVE_SCORE[declared]  # declared severity wins
            elif declared:
                base = _REPRESENTATIVE_SCORE[declared]

        if base is None:
            continue  # no CVSS signal at all — leave untouched

        final_sev = severity_from_cvss(base) or declared
        _set_attr(f, "cvss_score", round(base, 1))
        _set_attr(f, "cvss", round(base, 1))
        if final_sev:
            _set_attr(f, "severity", final_sev)
        if not keep_vector and vector:
            _set_attr(f, "cvss_vector", None)

    return findings


def _get_cvss(finding) -> float | None:
    """Extract CVSS score as float, handling both field names and PoC mirrors."""
    raw = _get_attr(finding, "cvss_score")
    if raw is None:
        raw = _get_attr(finding, "cvss")
    if raw is None:
        poc = _get_attr(finding, "proof_of_concept")
        if isinstance(poc, dict):
            for k in ("cvss_score", "cvss_base_score", "cvss", "base_score"):
                if k in poc and poc.get(k) is not None:
                    raw = poc.get(k)
                    break
    if raw is None:
        return None
    try:
        val = float(raw)
        return val if 0.0 <= val <= 10.0 else None
    except (ValueError, TypeError):
        return None


def _get_attr(obj, name: str):
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _set_attr(obj, name: str, value):
    if isinstance(obj, dict):
        obj[name] = value
    else:
        setattr(obj, name, value)
