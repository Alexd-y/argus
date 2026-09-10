"""Deterministic severity *floor* for well-understood hardening findings.

Aligns backend finding severity with the product's declared severity policy
(the Frontend curated model in ``Frontend/src/lib/scan-results.ts``). It only
**raises** the severity band for a small, unambiguous set of under-rated
hardening categories, matched by CWE + a title signature. It never lowers a
severity, and it deliberately leaves *present-but-weak* conditions (SPF
``~all``, DMARC without ``rua``, missing CAA) untouched — raising those would
overstate the real risk relative to the observed evidence.

Conservative policy (see the product decision recorded in
``docs/finding-severity-and-counting.md``):

* Missing / incomplete security response headers (CWE-693) → **HIGH**.
* DNSSEC not enabled → **HIGH**.
* DKIM not detected → **MEDIUM**.

Pure module: stdlib only, no I/O, no logging. A single source of truth applied
on BOTH the persist path (pipeline → DB) and the read path (public findings
API), so the customer-facing report and the stored record never disagree. The
evidence gate (:mod:`src.orchestration.finding_gate`) runs first, so only
evidence-bearing findings ever reach this floor.
"""

from __future__ import annotations

from collections.abc import Callable

from src.findings.severity import SeverityBand, normalize_severity

#: "Raise only" ordering. ``unknown`` / ``informational`` share the lowest rank
#: so any policy band strictly above them triggers a raise.
_BAND_RANK: dict[SeverityBand, int] = {
    SeverityBand.UNKNOWN: 0,
    SeverityBand.INFORMATIONAL: 0,
    SeverityBand.LOW: 1,
    SeverityBand.MEDIUM: 2,
    SeverityBand.HIGH: 3,
    SeverityBand.CRITICAL: 4,
}

#: Representative CVSS base score per band (FIRST.org v3.1 band midpoints).
#: Used to keep the numeric score consistent when a band is raised, mirroring
#: the report normalizer's representative scores so UI and PDF never diverge.
_REPRESENTATIVE_CVSS: dict[str, float] = {
    "medium": 5.5,
    "high": 7.5,
    "critical": 9.0,
}


def _sig_security_headers(title: str) -> bool:
    return "header" in title and ("missing" in title or "incomplete" in title)


def _sig_dnssec(title: str) -> bool:
    return "dnssec" in title and any(
        kw in title for kw in ("not enabled", "disabled", "not detected", "missing")
    )


def _sig_dkim(title: str) -> bool:
    return "dkim" in title and any(
        kw in title for kw in ("not detected", "not found", "missing", "not configured")
    )


#: Authoritative CWE → floor (independent of the finding's title wording).
_CWE_FLOORS: dict[str, SeverityBand] = {
    "CWE-693": SeverityBand.HIGH,  # Protection Mechanism Failure (security headers)
}

#: Title-signature → floor. First match wins. Used only when no CWE floor hit.
_TITLE_FLOORS: tuple[tuple[Callable[[str], bool], SeverityBand], ...] = (
    (_sig_security_headers, SeverityBand.HIGH),
    (_sig_dnssec, SeverityBand.HIGH),
    (_sig_dkim, SeverityBand.MEDIUM),
)


def severity_floor_band(severity: object, cwe: object, title: object) -> SeverityBand | None:
    """Return the raised :class:`SeverityBand`, or ``None`` when no raise applies.

    ``None`` means "leave the finding's current severity untouched" — either no
    policy matched, or the current severity already meets/exceeds the floor.
    """
    current = normalize_severity(severity)
    cwe_norm = str(cwe or "").strip().upper()
    title_norm = str(title or "").strip().lower()

    floor = _CWE_FLOORS.get(cwe_norm)
    if floor is None:
        for matches, band in _TITLE_FLOORS:
            if matches(title_norm):
                floor = band
                break
    if floor is None:
        return None
    return floor if _BAND_RANK[floor] > _BAND_RANK[current] else None


def _raised_cvss(current_cvss: object, band: SeverityBand) -> float | None:
    """Representative CVSS for ``band`` when it exceeds the current score, else the current value."""
    rep = _REPRESENTATIVE_CVSS.get(band.value)
    try:
        cur = float(current_cvss) if current_cvss is not None else None
    except (TypeError, ValueError):
        cur = None
    if rep is not None and (cur is None or cur < rep):
        return rep
    return cur


def resolve_display_severity(
    severity: object, cwe: object, title: object, cvss: object
) -> tuple[object, object]:
    """Return the ``(severity, cvss)`` pair to display, applying the floor.

    Non-mutating: used on the read path where the ORM row must stay untouched.
    Returns the inputs unchanged when no policy applies.
    """
    band = severity_floor_band(severity, cwe, title)
    if band is None:
        return severity, cvss
    return band.value, _raised_cvss(cvss, band)


def apply_floor_to_dict(finding: dict) -> None:
    """Raise ``severity`` (and ``cvss``) in-place on a finding dict.

    Used on the persist path so the stored record carries the policy-aligned
    severity. Idempotent and raise-only.
    """
    if not isinstance(finding, dict):
        return
    band = severity_floor_band(finding.get("severity"), finding.get("cwe"), finding.get("title"))
    if band is None:
        return
    finding["severity"] = band.value
    finding["cvss"] = _raised_cvss(finding.get("cvss"), band)


def apply_floor_to_findings(findings: list) -> list:
    """Apply :func:`apply_floor_to_dict` to every dict finding (in-place)."""
    for finding in findings:
        apply_floor_to_dict(finding)
    return findings


__all__ = [
    "apply_floor_to_dict",
    "apply_floor_to_findings",
    "resolve_display_severity",
    "severity_floor_band",
]
