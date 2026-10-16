"""Wave 5 / R-9.8 — metric baseline storage + regression gate."""

from __future__ import annotations

import asyncio

import pytest
from src.eval.baseline import (
    MetricGate,
    check_regression,
    load_latest_baseline,
    persist_baseline,
)


def test_higher_is_better_regression_detected():
    gates = {"direct_parse_rate": MetricGate(direction="higher", tolerance=0.02)}
    regs = check_regression({"direct_parse_rate": 0.80}, {"direct_parse_rate": 0.70}, gates)
    assert len(regs) == 1
    assert regs[0].metric == "direct_parse_rate"
    assert regs[0].delta == pytest.approx(-0.10)


def test_within_tolerance_is_not_a_regression():
    gates = {"confirmed_rate": MetricGate(direction="higher", tolerance=0.05)}
    assert check_regression({"confirmed_rate": 0.80}, {"confirmed_rate": 0.78}, gates) == []


def test_improvement_is_not_a_regression():
    gates = {"confirmed_rate": MetricGate(direction="higher")}
    assert check_regression({"confirmed_rate": 0.70}, {"confirmed_rate": 0.90}, gates) == []


def test_lower_is_better_regression_detected():
    gates = {"parse_failure_rate": MetricGate(direction="lower", tolerance=0.0)}
    regs = check_regression({"parse_failure_rate": 0.05}, {"parse_failure_rate": 0.12}, gates)
    assert len(regs) == 1 and regs[0].direction == "lower"


def test_missing_metric_is_skipped():
    gates = {"x": MetricGate(), "y": MetricGate()}
    regs = check_regression({"x": 1.0}, {"x": 0.0}, gates)  # y absent from both
    assert [r.metric for r in regs] == ["x"]


class _FakeSession:
    def __init__(self, first_row=None):
        self.added = []
        self.committed = False
        self._first_row = first_row

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.committed = True

    async def execute(self, _stmt):
        first_row = self._first_row

        class _Res:
            def first(self_inner):
                return first_row

        return _Res()


def test_persist_baseline_writes_completed_row():
    session = _FakeSession()
    row_id = asyncio.run(
        persist_baseline(session, name="wave5-baseline", metrics={"direct_parse_rate": 0.8})
    )
    assert row_id
    assert session.committed is True
    row = session.added[0]
    assert row.name == "wave5-baseline"
    assert row.status == "completed"
    assert row.metrics_json == {"direct_parse_rate": 0.8}


def test_load_latest_baseline_returns_float_metrics():
    session = _FakeSession(first_row=({"direct_parse_rate": 0.8, "n": 5, "note": "x"},))
    metrics = asyncio.run(load_latest_baseline(session, name="wave5-baseline"))
    # non-numeric values are dropped
    assert metrics == {"direct_parse_rate": 0.8, "n": 5.0}


def test_load_latest_baseline_none_when_absent():
    session = _FakeSession(first_row=None)
    assert asyncio.run(load_latest_baseline(session, name="missing")) is None
