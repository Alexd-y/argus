"""QUICK-009 — mocked integration: partial tool failure does not abort the scan."""

from __future__ import annotations

from src.core import unified_ai_metrics as m
from src.quick.circuit_breaker import QuickCircuitBreaker
from src.quick.metrics import record_task, record_tool_failure


def test_partial_tool_failure_continues_scan() -> None:
    m.reset_unified_ai_metrics()
    breaker = QuickCircuitBreaker(failure_threshold=3)
    host = "app.example"
    outcomes: list[str] = []
    for idx in range(5):
        if breaker.is_open("nuclei", host):
            outcomes.append("skipped")
            record_task(stage="test", status="skipped", tool="nuclei")
            continue
        if idx < 3:
            breaker.record_failure("nuclei", host)
            record_tool_failure(tool="nuclei", reason="error")
            outcomes.append("failed")
            continue
        outcomes.append("would_run")
    assert outcomes.count("failed") == 3
    assert outcomes.count("skipped") == 2
    assert breaker.is_open("nuclei", host) is True
    record_task(stage="report", status="succeeded", tool="nuclei")
    assert m.get_quick_tasks_total() >= 1
    m.reset_unified_ai_metrics()
