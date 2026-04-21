"""VHQ-002 — Deduplicate findings before report generation.

Removes duplicate findings that appear from both tool detection and LLM
heuristics (e.g. "missing security headers" as both confirmed and
web_vuln_heuristics finding).

Two findings are considered duplicates when:
- **Hard dedup**: identical CWE *and* identical normalised affected URL.
- **Soft dedup**: title similarity > 85 % (handles LLM paraphrase variants).

When a duplicate pair is detected the finding with the richer data
(description, PoC, CVSS) is kept.
"""

from __future__ import annotations

import logging
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_TITLE_SIMILARITY_THRESHOLD = 0.85


def deduplicate_findings(findings: list[Any]) -> list[Any]:
    """Return a new list with duplicate findings removed.

    Keeps the finding with the higher *richness score* when a duplicate
    pair is detected.  The input list is not mutated.
    """
    if not findings:
        return findings

    seen: list[Any] = []
    removed_count = 0

    for candidate in findings:
        is_dup = False
        for i, existing in enumerate(seen):
            if _is_hard_duplicate(candidate, existing) or _is_soft_duplicate(candidate, existing):
                is_dup = True

            if is_dup:
                if _richness_score(candidate) > _richness_score(existing):
                    seen[i] = candidate
                removed_count += 1
                break

        if not is_dup:
            seen.append(candidate)

    if removed_count > 0:
        logger.info(
            "finding_dedup_complete",
            extra={
                "component": "finding_dedup",
                "event": "dedup_complete",
                "removed": removed_count,
                "before": len(findings),
                "after": len(seen),
            },
        )

    return seen


# ---------------------------------------------------------------------------
# Duplicate detection helpers
# ---------------------------------------------------------------------------

def _is_hard_duplicate(candidate: Any, existing: Any) -> bool:
    """Same CWE + same normalised affected URL."""
    cand_cwe = _get_attr(candidate, "cwe")
    exist_cwe = _get_attr(existing, "cwe")
    if not cand_cwe or not exist_cwe or cand_cwe != exist_cwe:
        return False

    cand_url = _normalize_url(_get_attr(candidate, "affected_url") or "")
    exist_url = _normalize_url(_get_attr(existing, "affected_url") or "")
    return bool(cand_url and exist_url and cand_url == exist_url)


def _is_soft_duplicate(candidate: Any, existing: Any) -> bool:
    """Title similarity above threshold (catches LLM paraphrase duplicates)."""
    cand_title = (_get_attr(candidate, "title") or "").lower().strip()
    exist_title = (_get_attr(existing, "title") or "").lower().strip()
    if not cand_title or not exist_title:
        return False
    return SequenceMatcher(None, cand_title, exist_title).ratio() > _TITLE_SIMILARITY_THRESHOLD


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Lowercase, strip fragments and trailing slashes for comparison."""
    if not url:
        return ""
    try:
        parsed = urlparse(url.strip().lower())
        path = parsed.path.rstrip("/")
        return f"{parsed.scheme}://{parsed.netloc}{path}"
    except Exception:
        return url.strip().lower()


def _get_attr(obj: Any, name: str) -> Any:
    """Retrieve attribute from dict-like or object transparently."""
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _richness_score(finding: Any) -> int:
    """Higher score = more useful data attached to this finding."""
    score = 0
    desc = _get_attr(finding, "description")
    if desc and str(desc).strip():
        score += 2
    poc = _get_attr(finding, "proof_of_concept") or _get_attr(finding, "poc")
    if poc and (isinstance(poc, dict) and poc or str(poc).strip()):
        score += 3
    cvss = _get_attr(finding, "cvss") or _get_attr(finding, "cvss_score")
    try:
        if cvss is not None and float(cvss) > 0:
            score += 1
    except (TypeError, ValueError):
        pass
    cwe = _get_attr(finding, "cwe")
    if cwe:
        score += 1
    return score
