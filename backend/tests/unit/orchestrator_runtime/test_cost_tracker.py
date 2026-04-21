"""Unit tests for :mod:`src.orchestrator.cost_tracker` (ARG-008)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from src.orchestrator.cost_tracker import CostRecord, CostSummary, CostTracker
from src.orchestrator.prompt_registry import AgentRole


def _record(
    tracker: CostTracker,
    *,
    tenant_id: UUID,
    scan_id: UUID,
    role: AgentRole = AgentRole.PLANNER,
    prompt_tokens: int = 10,
    completion_tokens: int = 20,
    usd_cost: float = 0.001,
    attempt: int = 1,
    prompt_id: str = "planner_v1",
    model_id: str = "test-model",
) -> CostRecord:
    return tracker.record(
        correlation_id=uuid4(),
        tenant_id=tenant_id,
        scan_id=scan_id,
        agent_role=role,
        prompt_id=prompt_id,
        model_id=model_id,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        usd_cost=usd_cost,
        latency_ms=42,
        attempt=attempt,
    )


# ---------------------------------------------------------------------------
# CostRecord schema invariants
# ---------------------------------------------------------------------------


class TestCostRecord:
    def test_negative_tokens_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CostRecord(
                correlation_id=uuid4(),
                tenant_id=uuid4(),
                scan_id=uuid4(),
                agent_role=AgentRole.PLANNER,
                prompt_id="p",
                model_id="m",
                prompt_tokens=-1,
                completion_tokens=0,
                usd_cost=0.0,
                latency_ms=0,
                attempt=1,
            )

    def test_attempt_upper_bound(self) -> None:
        with pytest.raises(ValidationError):
            CostRecord(
                correlation_id=uuid4(),
                tenant_id=uuid4(),
                scan_id=uuid4(),
                agent_role=AgentRole.PLANNER,
                prompt_id="p",
                model_id="m",
                prompt_tokens=0,
                completion_tokens=0,
                usd_cost=0.0,
                latency_ms=0,
                attempt=99,
            )

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CostRecord(
                correlation_id=uuid4(),
                tenant_id=uuid4(),
                scan_id=uuid4(),
                agent_role=AgentRole.PLANNER,
                prompt_id="p",
                model_id="m",
                prompt_tokens=0,
                completion_tokens=0,
                usd_cost=0.0,
                latency_ms=0,
                attempt=1,
                extra="x",  # type: ignore[call-arg]
            )


# ---------------------------------------------------------------------------
# CostTracker behaviour
# ---------------------------------------------------------------------------


class TestCostTrackerAggregations:
    def test_total_for_empty_scan(self) -> None:
        summary = CostTracker().total_for_scan(uuid4())
        assert summary.record_count == 0
        assert summary.total_usd == 0.0

    def test_total_for_scan_aggregates(self) -> None:
        tracker = CostTracker()
        tenant = uuid4()
        scan = uuid4()
        _record(
            tracker,
            tenant_id=tenant,
            scan_id=scan,
            prompt_tokens=10,
            completion_tokens=20,
        )
        _record(
            tracker,
            tenant_id=tenant,
            scan_id=scan,
            prompt_tokens=5,
            completion_tokens=8,
        )
        summary = tracker.total_for_scan(scan)
        assert summary.record_count == 2
        assert summary.total_prompt_tokens == 15
        assert summary.total_completion_tokens == 28
        assert summary.total_usd > 0

    def test_scope_isolation_between_scans(self) -> None:
        tracker = CostTracker()
        tenant = uuid4()
        scan_a, scan_b = uuid4(), uuid4()
        _record(tracker, tenant_id=tenant, scan_id=scan_a, prompt_tokens=10)
        _record(tracker, tenant_id=tenant, scan_id=scan_b, prompt_tokens=99)
        sa = tracker.total_for_scan(scan_a)
        sb = tracker.total_for_scan(scan_b)
        assert sa.total_prompt_tokens == 10
        assert sb.total_prompt_tokens == 99

    def test_scope_isolation_between_tenants(self) -> None:
        tracker = CostTracker()
        tenant_a, tenant_b = uuid4(), uuid4()
        scan = uuid4()
        _record(tracker, tenant_id=tenant_a, scan_id=scan, prompt_tokens=10)
        _record(tracker, tenant_id=tenant_b, scan_id=scan, prompt_tokens=30)
        ta = tracker.total_for_tenant(tenant_a)
        tb = tracker.total_for_tenant(tenant_b)
        assert ta.total_prompt_tokens == 10
        assert tb.total_prompt_tokens == 30

    def test_by_role_breakdown(self) -> None:
        tracker = CostTracker()
        tenant, scan = uuid4(), uuid4()
        _record(
            tracker,
            tenant_id=tenant,
            scan_id=scan,
            role=AgentRole.PLANNER,
            prompt_tokens=10,
            completion_tokens=2,
        )
        _record(
            tracker,
            tenant_id=tenant,
            scan_id=scan,
            role=AgentRole.CRITIC,
            prompt_tokens=5,
            completion_tokens=1,
        )
        _record(
            tracker,
            tenant_id=tenant,
            scan_id=scan,
            role=AgentRole.PLANNER,
            prompt_tokens=3,
            completion_tokens=1,
        )
        summary = tracker.total_for_scan(scan)
        assert summary.by_role["planner"] == (10 + 2) + (3 + 1)
        assert summary.by_role["critic"] == 5 + 1

    def test_since_filter_on_tenant_summary(self) -> None:
        tracker = CostTracker()
        tenant, scan = uuid4(), uuid4()
        # Pin two records with explicit timestamps that bracket the cutoff
        # so the test is deterministic regardless of wall-clock skew.
        cutoff = datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)
        old = CostRecord(
            correlation_id=uuid4(),
            tenant_id=tenant,
            scan_id=scan,
            agent_role=AgentRole.PLANNER,
            prompt_id="planner_v1",
            model_id="m",
            prompt_tokens=99,
            completion_tokens=1,
            usd_cost=0.0,
            latency_ms=0,
            attempt=1,
            created_at=cutoff - timedelta(minutes=5),
        )
        new = CostRecord(
            correlation_id=uuid4(),
            tenant_id=tenant,
            scan_id=scan,
            agent_role=AgentRole.CRITIC,
            prompt_id="critic_v1",
            model_id="m",
            prompt_tokens=11,
            completion_tokens=2,
            usd_cost=0.0,
            latency_ms=0,
            attempt=1,
            created_at=cutoff + timedelta(minutes=5),
        )
        # Tracker is a thin in-memory aggregator: directly seeding the
        # internal lists is the only way to assert ``since`` semantics
        # without sleeping the test process.
        tracker._records_by_tenant[tenant].extend([old, new])  # noqa: SLF001
        tracker._records_by_scan[scan].extend([old, new])  # noqa: SLF001

        summary_all = tracker.total_for_tenant(tenant)
        summary_since = tracker.total_for_tenant(tenant, since=cutoff)
        assert summary_all.record_count == 2
        assert summary_since.record_count == 1
        assert summary_since.total_prompt_tokens == 11
        assert summary_since.by_role == {"critic": 13}

    def test_since_must_be_timezone_aware(self) -> None:
        tracker = CostTracker()
        with pytest.raises(ValueError, match="timezone-aware"):
            tracker.total_for_tenant(uuid4(), since=datetime(2026, 1, 1))

    def test_list_records_for_scan_returns_copy(self) -> None:
        tracker = CostTracker()
        tenant, scan = uuid4(), uuid4()
        _record(tracker, tenant_id=tenant, scan_id=scan)
        records = tracker.list_records_for_scan(scan)
        assert len(records) == 1
        records.clear()
        assert len(tracker.list_records_for_scan(scan)) == 1


# ---------------------------------------------------------------------------
# CostSummary
# ---------------------------------------------------------------------------


class TestCostSummary:
    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CostSummary(
                total_prompt_tokens=0,
                total_completion_tokens=0,
                total_usd=0.0,
                record_count=0,
                bogus=1,  # type: ignore[call-arg]
            )

    def test_negative_record_count_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CostSummary(
                total_prompt_tokens=0,
                total_completion_tokens=0,
                total_usd=0.0,
                record_count=-1,
            )
