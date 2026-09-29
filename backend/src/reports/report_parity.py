"""Cross-format finding-count parity (Part III, Phase Q — R-11).

The shipped bundle had the main ``.md`` show 1 finding in its registry while the
canonical set listed 9 — a divergence the existing ``assert_canonical_parity`` could
not catch (it compares canonical artifacts to each other, not to the main report).

These pure helpers compare the *total* finding count across every source (main
markdown, canonical JSON, and the snapshot) so a "1 vs 9" split is impossible. The
total is registry findings **plus** unconfirmed observations — a finding moved to the
unconfirmed section still counts.
"""

from __future__ import annotations

import json
import re

_MD_FINDINGS_HEADER_RE = re.compile(r"^##+\s*Findings\s*\((\d+)\)", re.IGNORECASE | re.MULTILINE)
_MD_UNCONFIRMED_RE = re.compile(
    r"^##+\s*Unconfirmed Observations\s*\((\d+)\)", re.IGNORECASE | re.MULTILINE
)


def count_findings_in_markdown(md_text: str) -> int | None:
    """Total findings in a rendered markdown report = registry + unconfirmed.

    Returns ``None`` when no ``## Findings (N)`` header is present (nothing to compare).
    """
    header = _MD_FINDINGS_HEADER_RE.search(md_text or "")
    if not header:
        return None
    total = int(header.group(1))
    unconfirmed = _MD_UNCONFIRMED_RE.search(md_text or "")
    if unconfirmed:
        total += int(unconfirmed.group(1))
    return total


def count_findings_in_canonical_json(json_text: str) -> int | None:
    """Total findings in a canonical JSON = findings + unconfirmed_observations."""
    try:
        data = json.loads(json_text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    findings = data.get("findings")
    if not isinstance(findings, list):
        return None
    total = len(findings)
    unconfirmed = data.get("unconfirmed_observations")
    if isinstance(unconfirmed, list):
        total += len(unconfirmed)
    return total


def finding_count_parity(counts_by_source: dict[str, int]) -> list[str]:
    """Return blocking reasons when sources disagree on the total finding count (R-11).

    ``counts_by_source`` maps a source label (``main_md`` / ``canonical_json`` /
    ``snapshot`` …) to its total finding count. Sources reporting ``None`` are skipped
    by the caller. Any disagreement is a release blocker.
    """
    distinct = set(counts_by_source.values())
    if len(distinct) <= 1:
        return []
    detail = ", ".join(f"{k}={v}" for k, v in sorted(counts_by_source.items()))
    return [f"R-11: finding count differs across formats ({detail})"]


__all__ = [
    "count_findings_in_canonical_json",
    "count_findings_in_markdown",
    "finding_count_parity",
]
