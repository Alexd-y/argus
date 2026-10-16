"""Model-quality metrics from the arbiter-outcome link (Wave 5, R-9.7).

Stage A (R-9.2) persisted, per finding an LLM proposal produced, the wave-1
arbiter's objective verdict (``llm_invocation_outcomes``). This module turns
those rows into the measurable model-quality rates the measurement stage needs:
per task, the share of model proposals the arbiter **confirmed** vs **rejected**
as false — computed over the *applicable* proposals only (out-of-domain findings
carry no objective signal, so they are excluded from the rate denominator but
reported separately).

The aggregation is a pure function over ``(task, outcome, applicable)`` rows so
it is fully testable offline; the async loader is a thin query over the table.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

# Outcome labels produced by src/llm/invocation_outcome.derive_outcome.
_CONFIRMED = "confirmed"
_REJECTED = "rejected"
_SUSPECTED = "suspected"
_NOT_APPLICABLE = "not_applicable"
_UNKNOWN = "unknown"


@dataclass(frozen=True)
class TaskOutcomeMetrics:
    """Arbiter-outcome rates for one task (or ``"__all__"`` for the overall roll-up)."""

    task: str
    total: int
    applicable_total: int
    # Over applicable proposals (the objective-signal denominator):
    confirmed_rate: float
    rejected_rate: float
    suspected_rate: float
    # Over all proposals:
    not_applicable_rate: float
    # Raw counts for traceability / baseline storage.
    confirmed: int
    rejected: int
    suspected: int
    not_applicable: int
    unknown: int


def _ratio(num: int, den: int) -> float:
    return num / den if den > 0 else 0.0


def _metrics_for(task: str, rows: list[tuple[str, bool]]) -> TaskOutcomeMetrics:
    total = len(rows)
    confirmed = sum(1 for o, _ in rows if o == _CONFIRMED)
    rejected = sum(1 for o, _ in rows if o == _REJECTED)
    suspected = sum(1 for o, _ in rows if o == _SUSPECTED)
    not_applicable = sum(1 for o, _ in rows if o == _NOT_APPLICABLE)
    unknown = sum(1 for o, _ in rows if o == _UNKNOWN)
    # Applicable denominator = proposals the arbiter could judge (everything the
    # arbiter deemed in-domain). not_applicable are excluded; unknown stays in
    # because it IS an applicable proposal the arbiter simply could not tier.
    applicable_total = total - not_applicable
    return TaskOutcomeMetrics(
        task=task,
        total=total,
        applicable_total=applicable_total,
        confirmed_rate=_ratio(confirmed, applicable_total),
        rejected_rate=_ratio(rejected, applicable_total),
        suspected_rate=_ratio(suspected, applicable_total),
        not_applicable_rate=_ratio(not_applicable, total),
        confirmed=confirmed,
        rejected=rejected,
        suspected=suspected,
        not_applicable=not_applicable,
        unknown=unknown,
    )


def compute_outcome_metrics(
    rows: Iterable[tuple[str, str, bool]],
) -> dict[str, TaskOutcomeMetrics]:
    """Aggregate ``(task, outcome, applicable)`` rows into per-task metrics.

    Returns a dict keyed by task plus an ``"__all__"`` overall roll-up. An empty
    input yields a single ``"__all__"`` entry with zero totals.
    """
    by_task: dict[str, list[tuple[str, bool]]] = {}
    all_rows: list[tuple[str, bool]] = []
    for row in rows:  # tolerate (task, outcome, applicable[, model]) — model ignored here
        task, outcome, applicable = row[0], row[1], row[2]
        key = task or "unknown"
        by_task.setdefault(key, []).append((outcome, applicable))
        all_rows.append((outcome, applicable))

    result = {task: _metrics_for(task, rws) for task, rws in by_task.items()}
    result["__all__"] = _metrics_for("__all__", all_rows)
    return result


def compute_task_model_metrics(
    rows: Iterable[tuple[str, str, bool, str]],
) -> dict[str, TaskOutcomeMetrics]:
    """Aggregate ``(task, outcome, applicable, model)`` rows per ``task::model`` (R-9.11).

    The key is ``f"{task}::{model}"`` (model ``""`` when unknown). This is the
    task→model quality pairing the measurement stage compares: the same task may
    be routed to different models, and a small model with a hard schema often
    matches a large one on classification at a fraction of the cost — a decision
    to be made on these numbers, not by default.
    """
    by_key: dict[str, list[tuple[str, bool]]] = {}
    for row in rows:
        task = row[0] or "unknown"
        outcome = row[1]
        applicable = row[2]
        model = (row[3] if len(row) > 3 else "") or ""
        key = f"{task}::{model}"
        by_key.setdefault(key, []).append((outcome, applicable))
    return {key: _metrics_for(key, rws) for key, rws in by_key.items()}


async def load_outcome_rows(
    session,
    tenant_id: str,
    *,
    scan_id: str | None = None,
) -> list[tuple[str, str, bool, str]]:
    """Load ``(task, outcome, applicable, model)`` rows for a tenant (optionally one scan)."""
    from sqlalchemy import select

    from src.db.models import LlmInvocationOutcome

    stmt = select(
        LlmInvocationOutcome.task,
        LlmInvocationOutcome.outcome,
        LlmInvocationOutcome.applicable,
        LlmInvocationOutcome.model,
    ).where(LlmInvocationOutcome.tenant_id == tenant_id)
    if scan_id:
        stmt = stmt.where(LlmInvocationOutcome.scan_id == scan_id)
    res = await session.execute(stmt)
    return [(t or "unknown", o or _UNKNOWN, bool(a), m or "") for t, o, a, m in res.all()]


__all__ = [
    "TaskOutcomeMetrics",
    "compute_outcome_metrics",
    "compute_task_model_metrics",
    "load_outcome_rows",
]
