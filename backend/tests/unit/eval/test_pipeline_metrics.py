"""Wave 5 / R-9.5 — full-pipeline eval metric snapshot."""

from __future__ import annotations

import asyncio

import pytest
from src.eval import rates
from src.eval.pipeline_metrics import build_scan_metrics


class _Res:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeSession:
    def __init__(self, rows, *, raise_on_execute=False):
        self._rows = rows
        self._raise = raise_on_execute

    async def execute(self, _stmt):
        if self._raise:
            raise RuntimeError("db down")
        return _Res(self._rows)


@pytest.fixture(autouse=True)
def _reset_parse():
    rates.reset_structured_parse_rates()
    yield
    rates.reset_structured_parse_rates()


def test_assembles_outcome_and_parse_metrics():
    rates.record_json_parse(tier="direct")
    rates.record_json_parse(tier="failed")
    rows = [
        ("VULN_ANALYSIS", "confirmed", True, "wrb"),
        ("VULN_ANALYSIS", "rejected", True, "wrb"),
        ("RECON", "not_applicable", False, ""),
    ]
    m = asyncio.run(build_scan_metrics(_FakeSession(rows), "tenant", "scan"))
    assert m["arbiter_confirmed_rate"] == 0.5  # 1 confirmed / 2 applicable
    assert m["arbiter_rejected_rate"] == 0.5
    assert m["arbiter_not_applicable_rate"] == pytest.approx(1 / 3)
    assert m["outcome_total"] == 3.0
    assert m["outcome_applicable_total"] == 2.0
    assert m["structured_direct_parse_rate"] == 0.5
    assert m["structured_parse_failure_rate"] == 0.5
    assert m["structured_parse_total"] == 2.0


def test_best_effort_returns_empty_on_error():
    m = asyncio.run(build_scan_metrics(_FakeSession([], raise_on_execute=True), "t", "s"))
    assert m == {}
