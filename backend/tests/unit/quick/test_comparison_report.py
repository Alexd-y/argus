"""QUICK-010 — comparison-report precision/recall vs labeled fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from src.quick import comparison as comparison_mod
from src.quick.comparison import (
    ComparisonMetrics,
    EvalConfig,
    EvalTarget,
    LabeledFixture,
    ObservedTarget,
    build_report,
    compare_files,
    compute_metrics,
    evaluate_targets,
    load_eval_config,
    render_json,
    render_markdown,
    write_report,
)

_FIXTURE_DIR = (
    Path(__file__).resolve().parents[2] / "fixtures" / "quick" / "baselines"
)


def _labeled(*rows: LabeledFixture) -> tuple[LabeledFixture, ...]:
    return rows


def _observed(*rows: ObservedTarget) -> tuple[ObservedTarget, ...]:
    return rows


def test_perfect_match_is_full_precision_and_recall() -> None:
    labeled = _labeled(
        LabeledFixture(target="http://a.lab", expected_finding_ids=("f1", "f2")),
    )
    observed = _observed(
        ObservedTarget(
            target="http://a.lab",
            observed_finding_ids=("f2", "f1"),
            planned_coverage_pairs=3,
            recorded_coverage_pairs=3,
            deadline_met=True,
        ),
    )
    metrics, counts = compute_metrics(labeled, observed)
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.coverage_accounting_rate == 1.0
    assert metrics.deadline_completion_rate == 1.0
    assert metrics.out_of_scope_requests == 0
    assert counts.true_positives == 2
    assert counts.false_positives == 0
    assert counts.false_negatives == 0


def test_extra_finding_lowers_precision_not_recall() -> None:
    labeled = _labeled(LabeledFixture(target="http://a.lab", expected_finding_ids=("f1",)))
    observed = _observed(
        ObservedTarget(target="http://a.lab", observed_finding_ids=("f1", "fp")),
    )
    metrics, counts = compute_metrics(labeled, observed)
    assert metrics.precision == 0.5
    assert metrics.recall == 1.0
    assert counts.false_positives == 1
    assert counts.false_negatives == 0


def test_missed_finding_lowers_recall_not_precision() -> None:
    labeled = _labeled(
        LabeledFixture(target="http://a.lab", expected_finding_ids=("f1", "f2")),
    )
    observed = _observed(
        ObservedTarget(target="http://a.lab", observed_finding_ids=("f1",)),
    )
    metrics, counts = compute_metrics(labeled, observed)
    assert metrics.precision == 1.0
    assert metrics.recall == 0.5
    assert counts.false_negatives == 1


def test_empty_labeled_and_observed_is_vacuous_one() -> None:
    metrics, counts = compute_metrics((), ())
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.coverage_accounting_rate == 1.0
    assert metrics.deadline_completion_rate == 1.0
    assert counts.true_positives == 0


def test_coverage_accounting_uses_recorded_over_planned() -> None:
    labeled = _labeled(LabeledFixture(target="http://a.lab"))
    observed = _observed(
        ObservedTarget(
            target="http://a.lab",
            planned_coverage_pairs=4,
            recorded_coverage_pairs=2,
        ),
    )
    metrics, _counts = compute_metrics(labeled, observed)
    assert metrics.coverage_accounting_rate == 0.5


def test_deadline_completion_rate_averages_observed_rows() -> None:
    labeled = _labeled(
        LabeledFixture(target="http://a.lab"),
        LabeledFixture(target="http://b.lab"),
    )
    observed = _observed(
        ObservedTarget(target="http://a.lab", deadline_met=True),
        ObservedTarget(target="http://b.lab", deadline_met=False),
    )
    metrics, counts = compute_metrics(labeled, observed)
    assert metrics.deadline_completion_rate == 0.5
    assert counts.deadline_scans == 2
    assert counts.deadline_met == 1


def test_out_of_scope_requests_are_summed() -> None:
    labeled = _labeled(
        LabeledFixture(target="http://evil.example", expected_finding_ids=(), in_scope=False),
    )
    observed = _observed(
        ObservedTarget(
            target="http://evil.example",
            observed_finding_ids=(),
            out_of_scope_requests=3,
        ),
    )
    metrics, _counts = compute_metrics(labeled, observed)
    assert metrics.out_of_scope_requests == 3
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0


def test_vs_previous_emits_deltas_for_core_metrics() -> None:
    labeled = _labeled(LabeledFixture(target="http://a.lab", expected_finding_ids=("f1",)))
    observed = _observed(
        ObservedTarget(
            target="http://a.lab",
            observed_finding_ids=("f1",),
            planned_coverage_pairs=1,
            recorded_coverage_pairs=1,
            deadline_met=True,
        ),
    )
    previous = ComparisonMetrics(
        precision=0.5,
        recall=1.0,
        coverage_accounting_rate=1.0,
        deadline_completion_rate=1.0,
        out_of_scope_requests=1,
    )
    report = build_report(labeled, observed, previous=previous)
    assert report.precision == 1.0
    assert report.recall == 1.0
    assert report.vs_previous["precision"].delta == 0.5
    assert report.vs_previous["out_of_scope_requests"].delta == -1
    assert report.vs_previous["recall"].previous == 1.0


def test_missing_previous_leaves_delta_null() -> None:
    report = build_report((), ())
    assert report.vs_previous["precision"].previous is None
    assert report.vs_previous["precision"].delta is None
    assert report.eval_passed is None


def test_json_and_markdown_include_required_keys() -> None:
    labeled = _labeled(LabeledFixture(target="http://a.lab", expected_finding_ids=("f1",)))
    observed = _observed(
        ObservedTarget(target="http://a.lab", observed_finding_ids=("f1",)),
    )
    report = build_report(labeled, observed)
    payload = json.loads(render_json(report))
    for key in (
        "precision",
        "recall",
        "coverage_accounting_rate",
        "deadline_completion_rate",
        "out_of_scope_requests",
        "vs_previous",
    ):
        assert key in payload
    markdown = render_markdown(report)
    assert "`precision`" in markdown
    assert "`recall`" in markdown
    assert "`coverage_accounting_rate`" in markdown
    assert "`deadline_completion_rate`" in markdown
    assert "`out_of_scope_requests`" in markdown
    assert "Absence of a finding" in markdown


def test_write_report_creates_json_and_markdown(tmp_path: Path) -> None:
    report = build_report((), ())
    json_path = tmp_path / "out" / "report.json"
    md_path = tmp_path / "out" / "report.md"
    write_report(report, json_path=json_path, markdown_path=md_path)
    assert json_path.is_file()
    assert md_path.is_file()
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["precision"] == 1.0


def test_example_fixtures_match_baseline() -> None:
    report = compare_files(
        labeled_path=_FIXTURE_DIR / "labeled_fixtures.json",
        observed_path=_FIXTURE_DIR / "example_observed.json",
        previous_path=_FIXTURE_DIR / "example_baseline.json",
        eval_config_path=_FIXTURE_DIR / "eval_config.json",
    )
    assert report.precision == 1.0
    assert report.recall == 1.0
    assert report.coverage_accounting_rate == 1.0
    assert report.deadline_completion_rate == 1.0
    assert report.out_of_scope_requests == 0
    assert report.eval_passed is True
    assert report.vs_previous["precision"].delta == 0.0


def test_eval_thresholds_come_from_config_not_module_source() -> None:
    source = Path(comparison_mod.__file__).read_text(encoding="utf-8")
    assert "0.9" not in source
    assert "0.95" not in source
    config = load_eval_config(_FIXTURE_DIR / "eval_config.json")
    deadline = config.targets["deadline_completion_rate"]
    assert deadline.op == "gte"
    assert deadline.value == 0.95
    coverage = config.targets["coverage_accounting_rate"]
    assert coverage.op == "eq"
    assert coverage.value == 1.0


def test_eval_config_fails_when_coverage_is_incomplete() -> None:
    metrics = ComparisonMetrics(
        precision=1.0,
        recall=1.0,
        coverage_accounting_rate=0.5,
        deadline_completion_rate=1.0,
        out_of_scope_requests=0,
    )
    config = EvalConfig(
        targets={
            "coverage_accounting_rate": EvalTarget(op="eq", value=1.0),
            "out_of_scope_network_requests": EvalTarget(op="eq", value=0),
        }
    )
    checks, passed = evaluate_targets(metrics, config)
    assert passed is False
    by_name = {check.name: check for check in checks}
    assert by_name["coverage_accounting_rate"].passed is False
    assert by_name["out_of_scope_network_requests"].passed is True


def test_gte_baseline_requires_no_regression() -> None:
    current = ComparisonMetrics(
        precision=0.8,
        recall=0.7,
        coverage_accounting_rate=1.0,
        deadline_completion_rate=1.0,
        out_of_scope_requests=0,
    )
    previous = ComparisonMetrics(
        precision=1.0,
        recall=0.7,
        coverage_accounting_rate=1.0,
        deadline_completion_rate=1.0,
        out_of_scope_requests=0,
    )
    config = EvalConfig(
        targets={
            "verified_finding_precision": EvalTarget(op="gte_baseline"),
            "high_signal_fixture_recall": EvalTarget(op="gte_baseline"),
        }
    )
    checks, passed = evaluate_targets(current, previous=previous, config=config)
    assert passed is False
    by_name = {check.name: check for check in checks}
    assert by_name["verified_finding_precision"].passed is False
    assert by_name["high_signal_fixture_recall"].passed is True
