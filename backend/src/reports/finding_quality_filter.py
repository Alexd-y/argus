"""Filter, classify, and sort findings by evidence tier before report generation.

Implements the ARGUS dual reporting policy: ALL findings are included in
the report, but each is classified by evidence tier (EXPLOITED > CONFIRMED
> SUSPECTED > INFORMATIONAL). Findings are sorted by tier so that the
strongest evidence appears first, ensuring CISOs see the full picture.
"""

from __future__ import annotations

import logging
from typing import Any

from src.orchestration.evidence_tier import (
    EvidenceTier,
    classify_finding,
)
from src.pipeline.contracts.finding_dto import ConfidenceLevel

logger = logging.getLogger(__name__)

_INVALID_TITLES = frozenset({
    "unknown finding",
    "unknown",
    "untitled",
    "n/a",
    "none",
    "test",
    "placeholder",
})

_MIN_DESCRIPTION_LENGTH = 10


def _title_preview(title: object) -> str:
    if title is None:
        return "<empty>"
    if isinstance(title, str):
        s = title.strip()
        return s[:50] if s else "<empty>"
    return repr(title)[:50]


def filter_valid_findings(findings: list) -> list:
    """Remove degenerate findings that would add noise to the report.

    A finding is removed if:
    - title is empty or matches a known placeholder pattern
    - description is empty or too short (< 10 chars)

    IMPORTANT: Findings are NEVER removed based on evidence tier.
    Even SUSPECTED and INFORMATIONAL findings are preserved — they are
    classified, not filtered. This is the key difference from Shannon's
    "No Exploit, No Report" policy.

    AI triage labels (supported / contradicted / insufficient) also never
    drop a finding. ``classification=contradicted`` is an assessment, not
    a delete/suppress signal.
    """
    if not findings:
        return findings

    valid = []
    removed_count = 0

    for f in findings:
        title = _get_attr(f, "title")
        description = _get_attr(f, "description")

        if not _is_valid_title(title):
            removed_count += 1
            logger.info(
                "Filtered finding with invalid title: %r",
                _title_preview(title),
            )
            continue

        if not _is_valid_description(description):
            removed_count += 1
            logger.info(
                "Filtered finding with insufficient description, title=%r",
                _title_preview(title),
            )
            continue

        valid.append(f)

    if removed_count > 0:
        logger.info(
            "Quality filter removed %d findings (%d -> %d)",
            removed_count, len(findings), len(valid),
        )

    return valid


def classify_finding_evidence_tier(finding: Any) -> EvidenceTier:
    """Classify a finding into an EvidenceTier based on its attributes.

    Uses the explicit ``evidence_tier`` field if present, otherwise
    derives it from ``confidence`` level and available evidence.
    """
    explicit_tier = _get_attr(finding, "evidence_tier")
    if explicit_tier is not None:
        if isinstance(explicit_tier, EvidenceTier):
            return explicit_tier
        try:
            return EvidenceTier(int(explicit_tier))
        except (ValueError, TypeError):
            pass

    confidence_str = _get_attr(finding, "confidence")
    if confidence_str is None:
        confidence = ConfidenceLevel.SUSPECTED
    elif isinstance(confidence_str, ConfidenceLevel):
        confidence = confidence_str
    else:
        try:
            confidence = ConfidenceLevel(str(confidence_str).lower())
        except ValueError:
            confidence = ConfidenceLevel.SUSPECTED

    has_payload = bool(_get_attr(finding, "payload_successful") or _get_attr(finding, "poc"))
    has_evidence = bool(
        _get_attr(finding, "evidence")
        or _get_attr(finding, "tool_output")
        or _get_attr(finding, "screenshot_urls")
    )

    return classify_finding(confidence, has_payload=has_payload, has_evidence=has_evidence)


def sort_findings_by_evidence_tier(findings: list) -> list:
    """Sort findings by evidence tier (EXPLOITED first, INFORMATIONAL last).

    Within the same tier, findings are sorted by CVSS score descending.
    This ensures the report leads with the most impactful, best-evidenced
    findings while preserving ALL findings for completeness.
    """
    if not findings:
        return findings

    def sort_key(f):
        tier = classify_finding_evidence_tier(f)
        cvss = float(_get_attr(f, "cvss_v3_score") or 0)
        return (-tier, -cvss)

    return sorted(findings, key=sort_key)


def group_findings_by_evidence_tier(findings: list) -> dict[str, list]:
    """Group findings into evidence tier buckets for report sections.

    Returns a dict with keys "exploited", "confirmed", "suspected",
    "informational" — each containing the list of findings in that tier.
    """
    groups: dict[str, list] = {
        "exploited": [],
        "confirmed": [],
        "suspected": [],
        "informational": [],
    }

    for f in findings:
        tier = classify_finding_evidence_tier(f)
        if tier == EvidenceTier.EXPLOITED:
            groups["exploited"].append(f)
        elif tier == EvidenceTier.CONFIRMED:
            groups["confirmed"].append(f)
        elif tier == EvidenceTier.SUSPECTED:
            groups["suspected"].append(f)
        else:
            groups["informational"].append(f)

    return groups


def format_evidence_tier_badge(tier: EvidenceTier) -> str:
    """Format an evidence tier as a human-readable badge string for reports."""
    labels = {
        EvidenceTier.EXPLOITED: "[EXPLOITED]",
        EvidenceTier.CONFIRMED: "[CONFIRMED]",
        EvidenceTier.SUSPECTED: "[SUSPECTED]",
        EvidenceTier.INFORMATIONAL: "[INFO]",
    }
    return labels.get(tier, "[UNKNOWN]")


def _is_valid_title(title) -> bool:
    if not title or not isinstance(title, str):
        return False
    normalized = title.strip().lower()
    if not normalized:
        return False
    return normalized not in _INVALID_TITLES


def _is_valid_description(description) -> bool:
    if not description or not isinstance(description, str):
        return False
    return len(description.strip()) >= _MIN_DESCRIPTION_LENGTH


def _get_attr(obj, name: str):
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)
