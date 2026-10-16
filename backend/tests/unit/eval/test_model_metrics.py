"""Wave 5 / R-9.7 — model-quality metrics from the arbiter-outcome link."""

from __future__ import annotations

from src.eval.model_metrics import TaskOutcomeMetrics, compute_outcome_metrics


def test_empty_rows_yield_only_overall_zero():
    m = compute_outcome_metrics([])
    assert set(m) == {"__all__"}
    assert m["__all__"].total == 0
    assert m["__all__"].confirmed_rate == 0.0


def test_per_task_confirmed_and_rejected_rates_over_applicable():
    rows = [
        ("VULN_ANALYSIS", "confirmed", True),
        ("VULN_ANALYSIS", "confirmed", True),
        ("VULN_ANALYSIS", "rejected", True),
        ("VULN_ANALYSIS", "not_applicable", False),  # excluded from the rate denom
        ("EXPLOIT_GENERATION", "suspected", True),
    ]
    m = compute_outcome_metrics(rows)

    va = m["VULN_ANALYSIS"]
    assert isinstance(va, TaskOutcomeMetrics)
    assert va.total == 4
    assert va.applicable_total == 3  # the not_applicable one is excluded
    assert va.confirmed_rate == 2 / 3
    assert va.rejected_rate == 1 / 3
    assert va.not_applicable_rate == 1 / 4

    ex = m["EXPLOIT_GENERATION"]
    assert ex.suspected_rate == 1.0
    assert ex.applicable_total == 1


def test_overall_rollup_spans_all_tasks():
    rows = [
        ("A", "confirmed", True),
        ("B", "rejected", True),
        ("B", "not_applicable", False),
    ]
    overall = compute_outcome_metrics(rows)["__all__"]
    assert overall.total == 3
    assert overall.applicable_total == 2
    assert overall.confirmed_rate == 1 / 2
    assert overall.rejected_rate == 1 / 2
    assert overall.not_applicable_rate == 1 / 3


def test_unknown_stays_in_applicable_denominator():
    rows = [
        ("T", "unknown", True),
        ("T", "confirmed", True),
    ]
    t = compute_outcome_metrics(rows)["T"]
    assert t.applicable_total == 2  # unknown is an applicable-but-untiered proposal
    assert t.confirmed_rate == 1 / 2
    assert t.unknown == 1


def test_missing_task_label_bucketed_as_unknown():
    m = compute_outcome_metrics([("", "confirmed", True)])
    assert "unknown" in m
    assert m["unknown"].confirmed == 1
