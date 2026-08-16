"""QUICK-009 — mocked integration: LLM timeout falls back to deterministic plan."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from src.quick.llm_routes import plan_with_ai
from src.quick.planner import QuickPlannerRequest, QuickPlannerTarget
from src.quick.schemas import (
    AssetFingerprint,
    QuickBudget,
    QuickProfileName,
    QuickScanConfig,
    SeverityFloor,
)

_SCAN_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_ASSET_ID = "99999999-8888-7777-6666-555555555555"
_DEADLINE = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


def _request() -> QuickPlannerRequest:
    return QuickPlannerRequest(
        scan_id=_SCAN_ID,
        config=QuickScanConfig(
            profile=QuickProfileName.BALANCED,
            wall_clock_budget_seconds=900,
            ai_budget_seconds=90,
            reserve_for_validation_percent=20,
            max_targets=10,
            max_urls_per_host=50,
            crawl_depth=2,
            severity_floor=SeverityFloor.MEDIUM,
            enable_ai=True,
        ),
        budget=QuickBudget(
            wall_clock_budget_seconds=900,
            discovery_budget_seconds=180,
            fingerprint_budget_seconds=120,
            verification_budget_seconds=180,
            ai_budget_seconds=90,
            report_budget_seconds=90,
            request_budget=500,
            per_host_budget=50,
            concurrency_budget=4,
            reserve_for_validation_percent=20,
        ),
        deadline_at=_DEADLINE,
        fingerprints=(AssetFingerprint(asset_id=_ASSET_ID),),
        targets=(
            QuickPlannerTarget(
                target_ref="https://app.example/",
                asset_id=_ASSET_ID,
                in_scope=True,
            ),
        ),
    )


@pytest.mark.asyncio
async def test_llm_timeout_falls_back_to_deterministic_plan() -> None:
    with patch(
        "src.quick.llm_routes.call_llm_unified",
        new=AsyncMock(side_effect=TimeoutError("deadline")),
    ):
        result = await plan_with_ai(_request(), timeout_seconds=1.0)
    assert result.used_ai is False
    assert result.fallback_reason == "ai_timeout"
    assert result.value.scan_id == _SCAN_ID
    assert "ai_timeout" in result.degraded
