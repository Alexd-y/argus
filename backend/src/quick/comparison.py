"""Quick comparison-report: precision/recall vs labeled fixtures (QUICK-010).

Offline eval helper — not on the scan runtime path. Product quality targets
live in eval JSON config, never as magic thresholds in this module.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
)

logger = logging.getLogger(__name__)

RATIO_DIGITS = 4
COVERAGE_DIGITS = 2

_CORE_METRIC_NAMES: tuple[str, ...] = (
    "precision",
    "recall",
    "coverage_accounting_rate",
    "deadline_completion_rate",
    "out_of_scope_requests",
)

_EVAL_METRIC_ALIASES: dict[str, str] = {
    "out_of_scope_network_requests": "out_of_scope_requests",
    "high_signal_fixture_recall": "recall",
    "verified_finding_precision": "precision",
}

EvalOp = Literal["gte", "eq", "lte", "gte_baseline"]


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LabeledFixture(_Frozen):
    """Expected finding ids for one target in the labeled fixture set."""

    target: StrictStr
    expected_finding_ids: tuple[str, ...] = ()
    in_scope: StrictBool = True


class ObservedTarget(_Frozen):
    """Observed Quick run row for one target."""

    target: StrictStr
    observed_finding_ids: tuple[str, ...] = ()
    planned_coverage_pairs: StrictInt = Field(default=0, ge=0)
    recorded_coverage_pairs: StrictInt = Field(default=0, ge=0)
    deadline_met: StrictBool = True
    out_of_scope_requests: StrictInt = Field(default=0, ge=0)
    cross_tenant_data_exposure: StrictInt = Field(default=0, ge=0)
    untracked_tool_executions: StrictInt = Field(default=0, ge=0)
    report_without_coverage: StrictInt = Field(default=0, ge=0)


class ComparisonCounts(_Frozen):
    true_positives: StrictInt = Field(ge=0)
    false_positives: StrictInt = Field(ge=0)
    false_negatives: StrictInt = Field(ge=0)
    planned_coverage_pairs: StrictInt = Field(ge=0)
    recorded_coverage_pairs: StrictInt = Field(ge=0)
    deadline_scans: StrictInt = Field(ge=0)
    deadline_met: StrictInt = Field(ge=0)
    cross_tenant_data_exposure: StrictInt = Field(ge=0)
    untracked_tool_executions: StrictInt = Field(ge=0)
    report_without_coverage: StrictInt = Field(ge=0)


class MetricDelta(_Frozen):
    current: StrictFloat | StrictInt
    previous: StrictFloat | StrictInt | None = None
    delta: StrictFloat | StrictInt | None = None


class EvalCheck(_Frozen):
    name: StrictStr
    op: StrictStr
    expected: StrictFloat | StrictInt | StrictStr | None = None
    actual: StrictFloat | StrictInt
    passed: StrictBool


class ComparisonMetrics(_Frozen):
    precision: StrictFloat
    recall: StrictFloat
    coverage_accounting_rate: StrictFloat
    deadline_completion_rate: StrictFloat
    out_of_scope_requests: StrictInt
    cross_tenant_data_exposure: StrictInt = 0
    untracked_tool_executions: StrictInt = 0
    report_without_coverage: StrictInt = 0


class ComparisonReport(_Frozen):
    precision: StrictFloat
    recall: StrictFloat
    coverage_accounting_rate: StrictFloat
    deadline_completion_rate: StrictFloat
    out_of_scope_requests: StrictInt
    counts: ComparisonCounts
    vs_previous: dict[str, MetricDelta]
    eval_results: tuple[EvalCheck, ...] = ()
    eval_passed: StrictBool | None = None
    generated_at: StrictStr


class EvalTarget(_Frozen):
    op: EvalOp
    value: StrictFloat | StrictInt | None = None


class EvalConfig(_Frozen):
    schema_version: StrictInt = 1
    targets: dict[str, EvalTarget]


def _id_set(ids: Sequence[str]) -> set[str]:
    return {item.strip() for item in ids if item and str(item).strip()}


def _ratio(numerator: int, denominator: int, *, digits: int = RATIO_DIGITS) -> float:
    if denominator <= 0:
        return 1.0
    return round(numerator / denominator, digits)


def _index_unique(items: Sequence[LabeledFixture] | Sequence[ObservedTarget]) -> dict[str, Any]:
    indexed: dict[str, Any] = {}
    for item in items:
        if item.target in indexed:
            raise ValueError(f"duplicate target in comparison input: {item.target}")
        indexed[item.target] = item
    return indexed


def compute_precision_recall(
    labeled: Sequence[LabeledFixture],
    observed: Sequence[ObservedTarget],
) -> tuple[float, float, int, int, int]:
    """Micro-averaged precision/recall over finding ids per target."""
    labeled_map = _index_unique(labeled)
    observed_map = _index_unique(observed)
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    targets = set(labeled_map) | set(observed_map)
    for target in targets:
        expected = _id_set(labeled_map[target].expected_finding_ids) if target in labeled_map else set()
        found = _id_set(observed_map[target].observed_finding_ids) if target in observed_map else set()
        true_positives += len(expected & found)
        false_positives += len(found - expected)
        false_negatives += len(expected - found)
    precision = _ratio(true_positives, true_positives + false_positives)
    recall = _ratio(true_positives, true_positives + false_negatives)
    return precision, recall, true_positives, false_positives, false_negatives


def compute_metrics(
    labeled: Sequence[LabeledFixture],
    observed: Sequence[ObservedTarget],
) -> tuple[ComparisonMetrics, ComparisonCounts]:
    precision, recall, true_positives, false_positives, false_negatives = compute_precision_recall(
        labeled, observed
    )
    planned = sum(row.planned_coverage_pairs for row in observed)
    recorded = sum(row.recorded_coverage_pairs for row in observed)
    deadline_scans = len(observed)
    deadline_met = sum(1 for row in observed if row.deadline_met)
    out_of_scope = sum(row.out_of_scope_requests for row in observed)
    cross_tenant = sum(row.cross_tenant_data_exposure for row in observed)
    untracked = sum(row.untracked_tool_executions for row in observed)
    report_gaps = sum(row.report_without_coverage for row in observed)
    counts = ComparisonCounts(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        planned_coverage_pairs=planned,
        recorded_coverage_pairs=recorded,
        deadline_scans=deadline_scans,
        deadline_met=deadline_met,
        cross_tenant_data_exposure=cross_tenant,
        untracked_tool_executions=untracked,
        report_without_coverage=report_gaps,
    )
    metrics = ComparisonMetrics(
        precision=precision,
        recall=recall,
        coverage_accounting_rate=_ratio(recorded, planned, digits=COVERAGE_DIGITS),
        deadline_completion_rate=_ratio(deadline_met, deadline_scans),
        out_of_scope_requests=out_of_scope,
        cross_tenant_data_exposure=cross_tenant,
        untracked_tool_executions=untracked,
        report_without_coverage=report_gaps,
    )
    return metrics, counts


def metrics_from_mapping(raw: Mapping[str, Any]) -> ComparisonMetrics:
    """Load a previous-run snapshot. Extra keys (run_id, schema_version) ignored."""
    payload = {
        "precision": raw["precision"],
        "recall": raw["recall"],
        "coverage_accounting_rate": raw["coverage_accounting_rate"],
        "deadline_completion_rate": raw["deadline_completion_rate"],
        "out_of_scope_requests": raw["out_of_scope_requests"],
        "cross_tenant_data_exposure": raw.get("cross_tenant_data_exposure", 0),
        "untracked_tool_executions": raw.get("untracked_tool_executions", 0),
        "report_without_coverage": raw.get("report_without_coverage", 0),
    }
    return ComparisonMetrics.model_validate(payload)


def compare_to_previous(
    current: ComparisonMetrics,
    previous: ComparisonMetrics | None,
) -> dict[str, MetricDelta]:
    names = (
        *_CORE_METRIC_NAMES,
        "cross_tenant_data_exposure",
        "untracked_tool_executions",
        "report_without_coverage",
    )
    deltas: dict[str, MetricDelta] = {}
    for name in names:
        current_value = getattr(current, name)
        previous_value = getattr(previous, name) if previous is not None else None
        delta: float | int | None
        if previous_value is None:
            delta = None
        elif isinstance(current_value, int) and isinstance(previous_value, int):
            delta = current_value - previous_value
        else:
            delta = round(float(current_value) - float(previous_value), RATIO_DIGITS)
        deltas[name] = MetricDelta(current=current_value, previous=previous_value, delta=delta)
    return deltas


def _metric_value(metrics: ComparisonMetrics, name: str) -> float | int:
    resolved = _EVAL_METRIC_ALIASES.get(name, name)
    if not hasattr(metrics, resolved):
        raise ValueError(f"unknown eval metric: {name}")
    return getattr(metrics, resolved)


def evaluate_targets(
    metrics: ComparisonMetrics,
    config: EvalConfig,
    previous: ComparisonMetrics | None = None,
) -> tuple[tuple[EvalCheck, ...], bool]:
    """Apply eval-config gates. Thresholds come from config, not this module."""
    checks: list[EvalCheck] = []
    for name, target in config.targets.items():
        actual = _metric_value(metrics, name)
        op = target.op
        expected: float | int | str | None = target.value
        if op == "gte_baseline":
            if previous is None:
                passed = True
                expected = "baseline"
            else:
                baseline = _metric_value(previous, name)
                passed = float(actual) >= float(baseline)
                expected = baseline
        elif op == "gte":
            if target.value is None:
                raise ValueError(f"eval target {name} gte requires value")
            passed = float(actual) >= float(target.value)
        elif op == "lte":
            if target.value is None:
                raise ValueError(f"eval target {name} lte requires value")
            passed = float(actual) <= float(target.value)
        elif op == "eq":
            if target.value is None:
                raise ValueError(f"eval target {name} eq requires value")
            if isinstance(actual, int) and isinstance(target.value, int):
                passed = actual == target.value
            else:
                passed = round(float(actual), COVERAGE_DIGITS) == round(
                    float(target.value), COVERAGE_DIGITS
                )
        else:
            raise ValueError(f"unsupported eval op: {op}")
        checks.append(
            EvalCheck(
                name=name,
                op=op,
                expected=expected,
                actual=actual,
                passed=passed,
            )
        )
    passed_all = all(check.passed for check in checks) if checks else True
    return tuple(checks), passed_all


def build_report(
    labeled: Sequence[LabeledFixture],
    observed: Sequence[ObservedTarget],
    *,
    previous: ComparisonMetrics | None = None,
    eval_config: EvalConfig | None = None,
    generated_at: datetime | None = None,
) -> ComparisonReport:
    metrics, counts = compute_metrics(labeled, observed)
    eval_results: tuple[EvalCheck, ...] = ()
    eval_passed: bool | None = None
    if eval_config is not None:
        eval_results, eval_passed = evaluate_targets(metrics, eval_config, previous)
    stamp = generated_at if generated_at is not None else datetime.now(UTC)
    return ComparisonReport(
        precision=metrics.precision,
        recall=metrics.recall,
        coverage_accounting_rate=metrics.coverage_accounting_rate,
        deadline_completion_rate=metrics.deadline_completion_rate,
        out_of_scope_requests=metrics.out_of_scope_requests,
        counts=counts,
        vs_previous=compare_to_previous(metrics, previous),
        eval_results=eval_results,
        eval_passed=eval_passed,
        generated_at=stamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
    )


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_labeled_fixtures(path: Path) -> tuple[LabeledFixture, ...]:
    raw = _read_json(path)
    items = raw["fixtures"] if isinstance(raw, dict) else raw
    return tuple(LabeledFixture.model_validate(item) for item in items)


def load_observed_run(path: Path) -> tuple[ObservedTarget, ...]:
    raw = _read_json(path)
    items = raw["targets"] if isinstance(raw, dict) else raw
    return tuple(ObservedTarget.model_validate(item) for item in items)


def load_previous_metrics(path: Path) -> ComparisonMetrics:
    raw = _read_json(path)
    if not isinstance(raw, dict):
        raise TypeError("previous baseline must be a JSON object")
    return metrics_from_mapping(raw)


def load_eval_config(path: Path) -> EvalConfig:
    raw = _read_json(path)
    if not isinstance(raw, dict):
        raise TypeError("eval config must be a JSON object")
    targets_raw = raw.get("targets", {})
    targets = {name: EvalTarget.model_validate(spec) for name, spec in targets_raw.items()}
    schema_version = int(raw.get("schema_version", 1))
    return EvalConfig(schema_version=schema_version, targets=targets)


def compare_files(
    *,
    labeled_path: Path,
    observed_path: Path,
    previous_path: Path | None = None,
    eval_config_path: Path | None = None,
) -> ComparisonReport:
    previous = load_previous_metrics(previous_path) if previous_path is not None else None
    eval_config = load_eval_config(eval_config_path) if eval_config_path is not None else None
    return build_report(
        load_labeled_fixtures(labeled_path),
        load_observed_run(observed_path),
        previous=previous,
        eval_config=eval_config,
    )


def render_json(report: ComparisonReport) -> str:
    payload = report.model_dump(mode="json")
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _fmt(value: float | None) -> str:
    if value is None:
        return "—"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return f"{float(value):.4f}"


def render_markdown(report: ComparisonReport) -> str:
    lines = [
        "# Quick comparison report",
        "",
        f"Generated at `{report.generated_at}`.",
        "",
        "| Metric | Current | Previous | Delta |",
        "|---|---:|---:|---:|",
    ]
    for name in (
        *_CORE_METRIC_NAMES,
        "cross_tenant_data_exposure",
        "untracked_tool_executions",
        "report_without_coverage",
    ):
        delta = report.vs_previous[name]
        lines.append(
            f"| `{name}` | {_fmt(delta.current)} | {_fmt(delta.previous)} | {_fmt(delta.delta)} |"
        )
    lines.extend(
        [
            "",
            "## Counts",
            "",
            f"- true_positives: {report.counts.true_positives}",
            f"- false_positives: {report.counts.false_positives}",
            f"- false_negatives: {report.counts.false_negatives}",
            f"- planned_coverage_pairs: {report.counts.planned_coverage_pairs}",
            f"- recorded_coverage_pairs: {report.counts.recorded_coverage_pairs}",
            "",
        ]
    )
    if report.eval_results:
        lines.extend(["## Eval gates (from config)", ""])
        for check in report.eval_results:
            mark = "pass" if check.passed else "fail"
            lines.append(
                f"- `{check.name}` {check.op} {check.expected}: actual={check.actual} ({mark})"
            )
        overall = "pass" if report.eval_passed else "fail"
        lines.extend(["", f"Overall eval: **{overall}**", ""])
    lines.extend(
        [
            "> Absence of a finding is not evidence that a vulnerability is absent.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(
    report: ComparisonReport,
    *,
    json_path: Path,
    markdown_path: Path,
) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(render_json(report), encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    logger.info(
        "quick_comparison_report_written",
        extra={
            "event": "quick_comparison_report_written",
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
        },
    )


__all__ = [
    "COVERAGE_DIGITS",
    "RATIO_DIGITS",
    "ComparisonCounts",
    "ComparisonMetrics",
    "ComparisonReport",
    "EvalCheck",
    "EvalConfig",
    "EvalTarget",
    "LabeledFixture",
    "MetricDelta",
    "ObservedTarget",
    "build_report",
    "compare_files",
    "compare_to_previous",
    "compute_metrics",
    "compute_precision_recall",
    "evaluate_targets",
    "load_eval_config",
    "load_labeled_fixtures",
    "load_observed_run",
    "load_previous_metrics",
    "metrics_from_mapping",
    "render_json",
    "render_markdown",
    "write_report",
]
