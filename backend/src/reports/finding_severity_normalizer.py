"""Normalize severity based on CVSS v3.1 score ranges."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

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
