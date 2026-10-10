"""Phase 4 — silent truncation (RC-14) and AI-section status honesty (RC-15)."""

from __future__ import annotations

import types

from src.reports import limits
from src.reports.finding_metadata import format_evidence_cell
from src.reports.snapshot_builder import build_snapshot_from_report_data
from src.services.reporting import ReportGenerator


def test_cap_with_overflow_counts_dropped():
    kept, dropped = limits.cap_with_overflow([1, 2, 3, 4, 5], 3)
    assert kept == [1, 2, 3]
    assert dropped == 2


def test_cap_with_overflow_no_drop():
    kept, dropped = limits.cap_with_overflow([1, 2], 5)
    assert kept == [1, 2]
    assert dropped == 0


def test_overflow_note_mentions_remainder():
    note = limits.overflow_note(shown=4, total=11)
    assert "4" in note and "11" in note
    assert limits.overflow_note(shown=4, total=4) == ""


def test_format_evidence_cell_announces_remainder():
    refs = [f"e{i}" for i in range(12)]
    cell = format_evidence_cell("http", refs)
    # 8 shown, 4 more — the remainder count is explicit, not a bare ellipsis.
    assert "4" in cell


def test_ai_results_to_text_map_only_ok():
    mapped = ReportGenerator.ai_results_to_text_map(
        {
            "a": {"status": "ok", "text": "kept"},
            "b": {"status": "skipped_no_llm", "text": "skipped-text"},
            "c": {"status": "failed", "error": "llm_unavailable", "text": "failed-text"},
        }
    )
    assert mapped == {"a": "kept"}


def test_ai_section_failures_records_non_ok():
    records = ReportGenerator.ai_section_failures(
        {
            "a": {"status": "ok", "text": "kept"},
            "b": {"status": "skipped_no_llm", "text": "x"},
            "c": {"status": "failed", "error": "generation_failed"},
        }
    )
    wheres = {r["where"] for r in records}
    assert wheres == {"ai_section:b", "ai_section:c"}
    assert all(r["reason_code"] for r in records)


def test_snapshot_threads_failures_and_skipped_from_meta():
    report_data = types.SimpleNamespace(findings=[], evidence=[], target="https://t")
    doc = build_snapshot_from_report_data(
        report_data,
        scan_meta={
            "tier": "valhalla",
            "failures": [{"where": "ai_section:c", "reason_code": "generation_failed", "message": "m"}],
            "skipped_reasons": [{"where": "ai_section:b", "reason_code": "skipped_no_llm"}],
        },
    )
    assert any(f.where == "ai_section:c" for f in doc.failures)
    assert any("skipped_no_llm" in str(s) for s in doc.skipped_reasons)
