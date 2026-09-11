"""Tests for observability metric-label discipline (§13) and pool leases (§8)."""

from __future__ import annotations

import pytest
from src.orchestration.observability import log_event, metric_labels
from src.orchestration.pool_leases import pool_capacity, pool_slot


def test_metric_labels_drops_high_cardinality_ids():
    labels = metric_labels(
        phase="vuln", outcome="ok", tenant_id="t1", scan_id="s1", task_id="x", attempt_id="a"
    )
    assert labels == {"phase": "vuln", "outcome": "ok"}
    # High-cardinality identifiers must never become Prometheus labels.
    for forbidden in ("tenant_id", "scan_id", "task_id", "attempt_id"):
        assert forbidden not in labels


def test_metric_labels_ignores_unknown_keys():
    assert metric_labels(bogus="x", pool="browser") == {"pool": "browser"}


def test_log_event_does_not_raise():
    # Structured event with correlation fields is allowed in logs (not metrics).
    log_event("agent_task_claimed", tenant_id="t1", scan_id="s1", task_id="tk", phase="vuln")


def test_pool_slot_noop_when_disabled():
    # lease_enabled defaults False -> pool_slot yields None (no enforcement).
    with pool_slot("browser", "scan-1") as handle:
        assert handle is None


def test_pool_capacity_unknown_is_zero():
    assert pool_capacity("does-not-exist") == 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
