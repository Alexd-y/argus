"""Wave 4 / Stage 5 — API/report finding-set parity by ID set (R-6.2.4).

Counts can agree while the actual findings differ (one dropped, one phantom). These
prove the set-based comparison and that the Midgard top-N projection is covered: the
projected set is a subset of the full set, never a superset.
"""

from __future__ import annotations

from src.api.schemas import Finding
from src.reports.generators import ReportData, ReportSummary
from src.reports.report_bundle import ReportTier
from src.reports.report_parity import (
    finding_id_set_parity,
    finding_ids_in_canonical_json,
    midgard_projection_blockers,
)
from src.reports.tier_classifier import MIDGARD_TOP_FINDINGS, classify_for_tier


def test_finding_ids_in_canonical_json() -> None:
    js = '{"findings": [{"finding_id": "A"}, {"finding_id": "B"}], "unconfirmed_observations": []}'
    assert finding_ids_in_canonical_json(js) == {"A", "B"}
    assert finding_ids_in_canonical_json("{}") is None


def test_equal_sets_are_clean() -> None:
    assert (
        finding_id_set_parity(
            {"api": {"A", "B"}, "report": {"A", "B"}}, reference="api"
        )
        == []
    )


def test_phantom_id_always_blocks() -> None:
    blockers = finding_id_set_parity(
        {"api": {"A"}, "report": {"A", "GHOST"}}, reference="api"
    )
    assert any("exposes finding id" in b and "GHOST" in b for b in blockers)


def test_missing_id_blocks_unless_subset_allowed() -> None:
    sets = {"api": {"A", "B", "C"}, "report": {"A"}}
    assert any("missing finding id" in b for b in finding_id_set_parity(sets, reference="api"))
    # A projection source is allowed to carry a strict subset.
    assert (
        finding_id_set_parity(sets, reference="api", subset_ok=frozenset({"report"})) == []
    )


def test_phantom_blocks_even_for_subset_source() -> None:
    sets = {"api": {"A", "B"}, "report": {"A", "GHOST"}}
    blockers = finding_id_set_parity(sets, reference="api", subset_ok=frozenset({"report"}))
    assert any("GHOST" in b for b in blockers)  # missing B tolerated, phantom GHOST not


def _finding(fid: str, sev: str, cvss: float) -> Finding:
    return Finding(finding_id=fid, severity=sev, title=f"t-{fid}", description="d", cvss=cvss)


def test_midgard_projection_is_a_subset_of_full() -> None:
    n = MIDGARD_TOP_FINDINGS + 5
    findings = [_finding(f"F-{i:02d}", "high", 9.0 - 0.1 * i) for i in range(n)]
    data = ReportData(
        report_id="r-1",
        target="https://x.test",
        summary=ReportSummary(total_findings=n),
        findings=findings,
        technologies=[],
    )
    projected = classify_for_tier(data, ReportTier.MIDGARD)
    full_ids = {f.finding_id for f in findings}
    proj_ids = {f.finding_id for f in projected.findings}

    # B3 (2026-10-30): Midgard lists EVERY finding (no top-N cap), so the projected
    # set equals the full set — and still never invents a finding.
    assert len(proj_ids) == n
    assert proj_ids == full_ids
    assert midgard_projection_blockers(full_ids, proj_ids) == []


def test_midgard_projection_blockers_catches_phantom() -> None:
    assert midgard_projection_blockers({"A", "B"}, {"A", "PHANTOM"})
