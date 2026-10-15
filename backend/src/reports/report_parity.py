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


def finding_ids_in_canonical_json(json_text: str) -> set[str] | None:
    """Return the set of ``finding_id`` values in a canonical JSON (registry only).

    ``None`` when the JSON has no findings array to compare. This is the structured,
    reliable id source for set-based parity (R-6.2.4) — more precise than a count.
    """
    try:
        data = json.loads(json_text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        return None
    return {str(f.get("finding_id")) for f in data["findings"] if isinstance(f, dict)}


def finding_id_set_parity(
    id_sets_by_source: dict[str, set[str]],
    *,
    reference: str,
    subset_ok: frozenset[str] = frozenset(),
) -> list[str]:
    """Compare finding-ID *sets* across sources — the identity check counts can't make.

    Two sources can report the same *count* yet expose different findings (one dropped,
    one phantom). ``reference`` names the authoritative set (the API / full finding set).
    For every other source:

    * **phantom** ids (source − reference) are *always* a blocker — the source exposes a
      finding the authority does not have;
    * **missing** ids (reference − source) are a blocker *unless* the source is listed in
      ``subset_ok`` — a deliberate tier projection (e.g. Midgard top-N) may carry a strict
      subset, but it may never invent a finding.

    R-6.2.4. Returns one blocker per divergent source (empty == the sets agree).
    """
    ref = id_sets_by_source.get(reference)
    if ref is None:
        return [f"R-6.2.4: parity reference '{reference}' absent"]
    out: list[str] = []
    for source, ids in id_sets_by_source.items():
        if source == reference:
            continue
        phantom = ids - ref
        if phantom:
            out.append(
                f"R-6.2.4: '{source}' exposes finding id(s) absent from '{reference}': "
                f"{sorted(phantom)[:5]}"
            )
        missing = ref - ids
        if missing and source not in subset_ok:
            out.append(
                f"R-6.2.4: '{source}' is missing finding id(s) present in '{reference}': "
                f"{sorted(missing)[:5]}"
            )
    return out


def midgard_projection_blockers(full_ids: set[str], projected_ids: set[str]) -> list[str]:
    """Verify the Midgard top-N projection: a subset, never a superset (R-6.2.4).

    The Midgard tier deliberately renders only the top-N findings, so the projected set
    is expected to be a *subset* of the full set. The invariants that must still hold:
    the projection may not invent a finding (phantom), and the findings it drops must be
    a real subset of the full set. Returns a blocker on any phantom id; the dropped ids
    are legitimate and are expected to be accounted elsewhere (count note / ledger).
    """
    phantom = projected_ids - full_ids
    if phantom:
        return [
            f"R-6.2.4: Midgard projection invented finding id(s): {sorted(phantom)[:5]}"
        ]
    return []


__all__ = [
    "count_findings_in_canonical_json",
    "count_findings_in_markdown",
    "finding_count_parity",
    "finding_id_set_parity",
    "finding_ids_in_canonical_json",
    "midgard_projection_blockers",
]
