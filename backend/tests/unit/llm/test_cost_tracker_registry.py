"""ISS-fix-004 regression: per-scan ScanCostTracker registry helpers.

Validates that ``src.llm.cost_tracker`` exposes the registry helpers
(``_tracker_registry``, ``get_tracker``, ``pop_tracker``) used by
``src.llm.facade._record_llm_cost`` to attribute LLM spend to a scan.

These tests previously lived at ``tests/test_fix_004_cost_tracking.py``
and failed collection because the helpers were never restored after a
refactor. Class names are prefixed with ``CostTracker`` to keep them
unique across the suite (see ISS-pytest-test-prefix-collisions).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.llm.cost_tracker import (
    ScanCostTracker,
    _tracker_registry,
    get_tracker,
    pop_tracker,
)


class TestCostTrackerGet:
    """``get_tracker`` must lazily create and then return the same instance."""

    def setup_method(self) -> None:
        _tracker_registry.clear()

    def teardown_method(self) -> None:
        _tracker_registry.clear()

    def test_returns_scan_cost_tracker(self) -> None:
        tracker = get_tracker("scan-001")
        assert isinstance(tracker, ScanCostTracker)

    def test_returns_same_instance_for_same_scan_id(self) -> None:
        first = get_tracker("scan-001")
        second = get_tracker("scan-001")
        assert first is second

    def test_different_scan_ids_get_different_trackers(self) -> None:
        first = get_tracker("scan-001")
        second = get_tracker("scan-002")
        assert first is not second

    def test_tracker_carries_scan_id(self) -> None:
        tracker = get_tracker("scan-xyz")
        assert tracker.scan_id == "scan-xyz"

    def test_max_cost_only_applies_on_first_creation(self) -> None:
        first = get_tracker("scan-001", max_cost_usd=5.0)
        assert first.max_cost_usd == 5.0
        second = get_tracker("scan-001", max_cost_usd=999.0)
        assert second is first
        assert second.max_cost_usd == 5.0


class TestCostTrackerPop:
    """``pop_tracker`` must remove the tracker and return it (or ``None``)."""

    def setup_method(self) -> None:
        _tracker_registry.clear()

    def teardown_method(self) -> None:
        _tracker_registry.clear()

    def test_pop_existing_returns_tracker(self) -> None:
        get_tracker("scan-001")
        result = pop_tracker("scan-001")
        assert isinstance(result, ScanCostTracker)

    def test_pop_removes_from_registry(self) -> None:
        get_tracker("scan-001")
        pop_tracker("scan-001")
        assert "scan-001" not in _tracker_registry

    def test_pop_nonexistent_returns_none(self) -> None:
        assert pop_tracker("nonexistent") is None


class TestCostTrackerRecord:
    """``ScanCostTracker.record`` accumulates calls and produces a breakdown."""

    def test_record_adds_call(self) -> None:
        tracker = ScanCostTracker("test", max_cost_usd=100.0)
        tracker.record("recon", "test_task", "gpt-4o-mini", 100, 50)
        assert len(tracker.calls) == 1

    def test_record_returns_positive_cost(self) -> None:
        tracker = ScanCostTracker("test", max_cost_usd=100.0)
        cost = tracker.record("recon", "test_task", "gpt-4o-mini", 1000, 500)
        assert cost > 0

    def test_breakdown_has_expected_keys(self) -> None:
        tracker = ScanCostTracker("test", max_cost_usd=100.0)
        tracker.record("recon", "task1", "gpt-4o-mini", 100, 50)
        breakdown = tracker.breakdown()
        assert "scan_id" in breakdown
        assert "total_cost_usd" in breakdown
        assert "by_phase" in breakdown
        assert "recon" in breakdown["by_phase"]


class TestCostTrackerFacadeIntegration:
    """``call_llm_unified`` must invoke ``_record_llm_cost`` only when ``scan_id`` is given."""

    @pytest.mark.asyncio
    async def test_records_cost_when_scan_id_provided(self) -> None:
        mock_response = MagicMock()
        mock_response.text = "response"
        mock_response.model = "test-model"
        mock_response.prompt_tokens = 100
        mock_response.completion_tokens = 50

        _tracker_registry.clear()
        try:
            with (
                patch(
                    "src.llm.facade._task_router_call",
                    AsyncMock(return_value=mock_response),
                ),
                patch("src.llm.facade._record_llm_cost") as mock_record,
            ):
                from src.llm.facade import call_llm_unified

                await call_llm_unified(
                    "sys",
                    "usr",
                    task=MagicMock(value="test"),
                    scan_id="scan-cost-test",
                    phase="recon",
                )
                mock_record.assert_called_once()
                call_args = mock_record.call_args
                assert call_args[0][0] == "scan-cost-test"
        finally:
            _tracker_registry.clear()

    @pytest.mark.asyncio
    async def test_no_cost_record_without_scan_id(self) -> None:
        mock_response = MagicMock()
        mock_response.text = "response"

        with (
            patch(
                "src.llm.facade._task_router_call",
                AsyncMock(return_value=mock_response),
            ),
            patch("src.llm.facade._record_llm_cost") as mock_record,
        ):
            from src.llm.facade import call_llm_unified

            await call_llm_unified("sys", "usr", task=MagicMock(value="test"))
            mock_record.assert_not_called()
