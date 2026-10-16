"""Metric baseline storage + regression gate (Wave 5, R-9.8).

A measured baseline is only useful if later changes are judged against it and a
regression blocks release. This module:

* snapshots the current model-quality metrics into a ``benchmark_runs`` row
  (the table existed but had no writer — this is the greenfield writer);
* loads the latest stored baseline;
* compares a current snapshot against a baseline through a set of directional
  gates, returning the regressions (a pure, fully testable function).

Metrics are a flat ``{name: float}`` map so any stage (structured-parse rate,
arbiter confirmed/rejected rates, …) can contribute without schema churn.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class MetricGate:
    """How to judge one metric against its baseline.

    ``direction`` is ``"higher"`` when larger is better (parse rate, confirmed
    rate) or ``"lower"`` when smaller is better (parse-failure rate). ``tolerance``
    is the slack allowed before a change counts as a regression.
    """

    direction: str = "higher"
    tolerance: float = 0.0


@dataclass(frozen=True)
class Regression:
    metric: str
    baseline: float
    current: float
    direction: str
    delta: float


def check_regression(
    baseline: Mapping[str, float],
    current: Mapping[str, float],
    gates: Mapping[str, MetricGate],
) -> list[Regression]:
    """Return the gated metrics that regressed relative to ``baseline``.

    A metric missing from either snapshot is skipped (cannot be judged). For a
    ``higher`` gate a regression is ``current < baseline - tolerance``; for a
    ``lower`` gate it is ``current > baseline + tolerance``.
    """
    out: list[Regression] = []
    for name, gate in gates.items():
        if name not in baseline or name not in current:
            continue
        b = float(baseline[name])
        c = float(current[name])
        regressed = (
            c > b + gate.tolerance if gate.direction == "lower" else c < b - gate.tolerance
        )
        if regressed:
            out.append(
                Regression(
                    metric=name,
                    baseline=b,
                    current=c,
                    direction=gate.direction,
                    delta=round(c - b, 6),
                )
            )
    return out


async def persist_baseline(
    session,
    *,
    name: str,
    metrics: Mapping[str, float],
    model: str = "",
    profile: str = "wave5",
    datasets: list | None = None,
) -> str:
    """Write a completed ``benchmark_runs`` baseline row; return its id."""
    from src.db.models import BenchmarkRun

    row_id = str(uuid.uuid4())
    row = BenchmarkRun(
        id=row_id,
        name=name,
        model=model or None,
        profile=profile,
        datasets=datasets,
        metrics_json=dict(metrics),
        status="completed",
    )
    session.add(row)
    await session.commit()
    return row_id


async def load_latest_baseline(session, *, name: str) -> dict[str, float] | None:
    """Return the metrics of the most recent completed baseline with ``name``."""
    from sqlalchemy import desc, select

    from src.db.models import BenchmarkRun

    stmt = (
        select(BenchmarkRun.metrics_json)
        .where(BenchmarkRun.name == name, BenchmarkRun.status == "completed")
        .order_by(desc(BenchmarkRun.created_at))
        .limit(1)
    )
    res = await session.execute(stmt)
    row = res.first()
    if row is None or row[0] is None:
        return None
    return {str(k): float(v) for k, v in row[0].items() if isinstance(v, (int, float))}


__all__ = [
    "MetricGate",
    "Regression",
    "check_regression",
    "load_latest_baseline",
    "persist_baseline",
]
