"""GC target-scoping for prior report bundles (§1 idempotency/GC).

Guards the SAFETY contract of ``_gc_prior_reports``: only auto-generated
``generate_all`` bundle rows that no operator owns are ever deletable. The
finalize/base report, single-tier API reports, and operator-assigned reports
MUST be excluded — findings/ledger CASCADE off reports, so an over-broad target
set is destructive.
"""

from __future__ import annotations

from src.reports.bundle_enqueue import _select_gc_targets


def test_generate_all_unassigned_is_a_target() -> None:
    rows = [("r1", {"generate_all": True, "bundle_id": "b1"}, None)]
    assert _select_gc_targets(rows) == ["r1"]


def test_operator_assigned_report_is_excluded() -> None:
    rows = [("r1", {"generate_all": True}, "analyst@example.com")]
    assert _select_gc_targets(rows) == []


def test_non_bundle_reports_are_excluded() -> None:
    # finalize/base + single-tier API reports carry no generate_all flag.
    rows = [
        ("finalize", {"source": "post_scan_complete"}, None),
        ("single", {"generate_all": False}, None),
        ("manual", {}, None),
    ]
    assert _select_gc_targets(rows) == []


def test_missing_or_non_dict_metadata_is_excluded() -> None:
    rows = [
        ("none", None, None),
        ("list", ["generate_all"], None),
        ("str", "generate_all", None),
    ]
    assert _select_gc_targets(rows) == []


def test_only_matching_rows_are_returned_from_a_mix() -> None:
    rows = [
        ("keep_finalize", {"source": "post_scan_complete"}, None),
        ("gc_a", {"generate_all": True}, None),
        ("keep_owned", {"generate_all": True}, "owner"),
        ("gc_b", {"generate_all": True, "bundle_id": "b2"}, ""),
        ("keep_single", {"generate_all": False}, None),
    ]
    assert _select_gc_targets(rows) == ["gc_a", "gc_b"]
