"""Part III Phase Q — 21-section registry + cross-format finding-count parity (R-11)."""

from __future__ import annotations

from src.reports.report_parity import (
    count_findings_in_canonical_json,
    count_findings_in_markdown,
    finding_count_parity,
)
from src.reports.section_registry import SECTION_ORDER, section_ids


def test_registry_has_all_21_contract_sections():
    ids = section_ids()
    for required in (
        "passport",
        "executive_summary",
        "engagement",
        "surface_inventory",
        "methodology",
        "priority_findings",
        "findings_by_asset",
        "findings",
        "unconfirmed_observations",
        "test_executions",
        "attack_narrative",
        "exploit_chains",
        "priority_plan",
        "retest_closure",
        "evidence_inventory",
        "client_impact",
        "appendix_all_findings",
        "appendix_assets",
        "appendix_tool_runs",
        "appendix_verification_kit",
        "disclaimer",
    ):
        assert required in ids, required
    # Order: priority findings precede detailed findings precede appendices.
    assert ids.index("priority_findings") < ids.index("findings")
    assert ids.index("findings") < ids.index("appendix_all_findings")
    assert ids[-1] == "disclaimer"
    # No duplicate section ids.
    assert len(ids) == len(set(ids))
    assert len(SECTION_ORDER) >= 21


# --------------------------------------------------------------------------- R-11
def test_count_findings_in_markdown_sums_registry_and_unconfirmed():
    md = "# Report\n\n## Findings (1)\n\n### F-1\n\n## Unconfirmed Observations (8)\n\n- x\n"
    assert count_findings_in_markdown(md) == 9  # 1 + 8, never "1 vs 9"


def test_count_findings_in_canonical_json():
    js = '{"findings": [1,2,3,4,5,6,7,8,9], "unconfirmed_observations": []}'
    assert count_findings_in_canonical_json(js) == 9


def test_finding_count_parity_across_all_formats():
    # The exact "1 vs 9" defect from the shipped bundle.
    assert finding_count_parity({"main_md": 1, "canonical_json": 9})
    # Agreement (registry+unconfirmed on both sides) → no blocker.
    assert finding_count_parity({"main_md": 9, "canonical_json": 9, "snapshot": 9}) == []


def test_markdown_without_findings_header_returns_none():
    assert count_findings_in_markdown("# Report\n\nNo findings section here.") is None
