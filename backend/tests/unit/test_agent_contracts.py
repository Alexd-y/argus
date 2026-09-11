"""Tests for typed agent-task contracts (§4)."""

from __future__ import annotations

import pytest
from src.orchestration.agent_contracts import (
    AgentResult,
    AgentTaskSpec,
    AgentUsage,
    AttemptOutcome,
    CoverageStatus,
    compute_input_fingerprint,
    make_idempotency_key,
)


def test_fingerprint_is_order_independent():
    a = compute_input_fingerprint({"x": 1, "y": 2})
    b = compute_input_fingerprint({"y": 2, "x": 1})
    assert a == b


def test_fingerprint_changes_with_content():
    assert compute_input_fingerprint({"x": 1}) != compute_input_fingerprint({"x": 2})


def test_with_fingerprint_derives_idempotency_key():
    spec = AgentTaskSpec(tenant_id="t1", scan_id="s1", phase="vuln", agent_role="injection")
    stamped = spec.with_fingerprint({"target": "asset-1", "findings": [1, 2]})
    assert stamped.input_fingerprint
    expected = make_idempotency_key("t1", "s1", "injection", stamped.input_fingerprint, 1)
    assert stamped.idempotency_key == expected


def test_empty_result_is_not_success():
    # A result must declare outcome/coverage explicitly; an empty payload with a
    # FAILED/NOT_TESTED coverage is not success.
    r = AgentResult(
        task_id="t", attempt_id="a",
        outcome=AttemptOutcome.FAILED, coverage=CoverageStatus.FAILED,
    )
    assert r.is_success is False


def test_tested_no_findings_is_success_but_distinct_from_not_tested():
    tested = AgentResult(
        task_id="t", attempt_id="a",
        outcome=AttemptOutcome.SUCCEEDED, coverage=CoverageStatus.TESTED_NO_FINDINGS,
    )
    not_tested = AgentResult(
        task_id="t", attempt_id="a",
        outcome=AttemptOutcome.INCONCLUSIVE, coverage=CoverageStatus.NOT_TESTED,
    )
    assert tested.is_success is True
    assert not_tested.is_success is False
    assert tested.coverage != not_tested.coverage


def test_local_model_usage_cost_is_not_asserted_zero():
    # No money estimate -> cost stays None, tokens/duration still recorded.
    u = AgentUsage(input_tokens=10, output_tokens=20, duration_seconds=1.5, model="wrb")
    assert u.cost_usd is None
    assert u.total_tokens == 30


def test_estimated_flag_distinguishes_metadata_from_estimate():
    metadata = AgentUsage(input_tokens=5, output_tokens=5, estimated=False)
    estimate = AgentUsage(input_tokens=5, output_tokens=5, estimated=True)
    assert metadata.estimated is False
    assert estimate.estimated is True


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
