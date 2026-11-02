"""GC target-scoping for prior report bundles (§1 idempotency/GC).

Guards the SAFETY contract of ``_gc_prior_reports``: only auto-generated
``generate_all`` bundle rows that are terminal and that no operator retention
signal protects are ever deletable. The finalize/base report, single-tier API
reports, operator-assigned / compliance-tagged reports, and in-flight (pending/
processing/queued) reports MUST be excluded — findings/ledger/share-links CASCADE
off reports, so an over-broad target set is destructive.

``rows`` tuples are (id, report_metadata, assigned_to, compliance_tags,
generation_status).
"""

from __future__ import annotations

from src.reports.bundle_enqueue import _select_gc_targets


def test_generate_all_terminal_unprotected_is_a_target() -> None:
    rows = [("r1", {"generate_all": True, "bundle_id": "b1"}, None, None, "completed")]
    assert _select_gc_targets(rows) == ["r1"]


def test_operator_assigned_report_is_excluded() -> None:
    rows = [("r1", {"generate_all": True}, "analyst@example.com", None, "completed")]
    assert _select_gc_targets(rows) == []


def test_compliance_tagged_report_is_excluded() -> None:
    rows = [("r1", {"generate_all": True}, None, ["soc2"], "completed")]
    assert _select_gc_targets(rows) == []


def test_in_flight_reports_are_excluded() -> None:
    rows = [
        ("pending", {"generate_all": True}, None, None, "pending"),
        ("processing", {"generate_all": True}, None, None, "processing"),
        ("queued", {"generate_all": True}, None, None, "queued"),
    ]
    assert _select_gc_targets(rows) == []


def test_non_bundle_reports_are_excluded() -> None:
    # finalize/base + single-tier API reports carry no generate_all flag.
    rows = [
        ("finalize", {"source": "post_scan_complete"}, None, None, "completed"),
        ("single", {"generate_all": False}, None, None, "ready"),
        ("manual", {}, None, None, "ready"),
    ]
    assert _select_gc_targets(rows) == []


def test_missing_or_non_dict_metadata_is_excluded() -> None:
    rows = [
        ("none", None, None, None, "ready"),
        ("list", ["generate_all"], None, None, "ready"),
        ("str", "generate_all", None, None, "ready"),
    ]
    assert _select_gc_targets(rows) == []


def test_only_matching_rows_are_returned_from_a_mix() -> None:
    rows = [
        ("keep_finalize", {"source": "post_scan_complete"}, None, None, "completed"),
        ("gc_a", {"generate_all": True}, None, None, "completed"),
        ("keep_owned", {"generate_all": True}, "owner", None, "completed"),
        ("gc_b", {"generate_all": True, "bundle_id": "b2"}, "", None, "failed"),
        ("keep_pending", {"generate_all": True}, None, None, "pending"),
        ("keep_single", {"generate_all": False}, None, None, "ready"),
    ]
    assert _select_gc_targets(rows) == ["gc_a", "gc_b"]
