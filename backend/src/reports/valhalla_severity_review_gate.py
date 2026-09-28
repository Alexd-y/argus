"""Severity / CVSS / review release rules (Part II, Phase O — prompt §20).

Blocking rules (not warnings):

* CVSS must be given with a **vector and version**; a ``high``/``critical`` finding
  without a CVSS vector blocks release (§20.1).
* Impact may not be overclaimed: a finding whose vector asserts ``C:H`` / ``I:H`` /
  ``A:H`` but whose status is not proven (``confirmed`` / ``exploitable``) has no
  demonstrated impact — a theoretical vulnerability is Medium at most (§20.1).
* ``critical`` / ``high`` findings require human review (``review_status=approved``)
  before the release can be marked ready (§20.2).

Pure module: consumes :class:`ReportFinding` objects and returns human-readable
blocking reasons. No DB / LLM / network.
"""

from __future__ import annotations

import re

from src.reports.report_document import ReportFinding

_PROVEN = frozenset({"confirmed", "exploitable"})
_HIGH_BANDS = frozenset({"critical", "high"})
_HIGH_IMPACT_RE = re.compile(r"\b[CIA]:H\b")
_CVSS_VERSION_RE = re.compile(r"^(?:CVSS:3\.[01]/)?(?:AV:[NALP])", re.IGNORECASE)


def _has_high_impact_metric(vector: str) -> bool:
    return bool(_HIGH_IMPACT_RE.search(vector or ""))


def severity_review_blockers(
    findings: list[ReportFinding],
    *,
    require_review: bool = True,
) -> list[str]:
    """Return blocking reasons for severity/CVSS/review violations (§20)."""
    blockers: list[str] = []
    for f in findings:
        band = (f.severity or "").strip().lower()
        vector = (f.cvss_vector or "").strip()

        # High/critical requires a CVSS vector.
        if band in _HIGH_BANDS and not vector:
            blockers.append(f"O-CVSS: finding {f.finding_id} is {band} but has no CVSS vector")

        if vector:
            # Version must be identifiable (a bare risk score is not CVSS, §20.1).
            if not _CVSS_VERSION_RE.match(vector) and not f.cvss_version:
                blockers.append(
                    f"O-CVSS: finding {f.finding_id} CVSS vector lacks an identifiable "
                    "version (do not call an external risk score CVSS)"
                )
            # Impact overclaim: high-impact metric without proven impact.
            if _has_high_impact_metric(vector) and f.verification_status not in _PROVEN:
                blockers.append(
                    f"O-IMPACT: finding {f.finding_id} claims C/I/A:H without proven "
                    f"impact (status={f.verification_status}); theoretical max is Medium"
                )

        # Human review for high/critical.
        if require_review and band in _HIGH_BANDS and f.review_status != "approved":
            blockers.append(
                f"O-REVIEW: finding {f.finding_id} ({band}) requires review_status="
                f"approved before release (current: {f.review_status})"
            )
    return blockers


__all__ = ["severity_review_blockers"]
