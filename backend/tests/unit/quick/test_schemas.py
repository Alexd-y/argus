"""QUICK-001 — frozen Quick Pydantic contracts (extra=forbid)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from src.quick.schemas import (
    QuickBudget,
    QuickCoverageRecord,
    QuickCoverageState,
    QuickPlanRevision,
    QuickProfileName,
    QuickScanConfig,
    QuickScanPlan,
    QuickTask,
    QuickTaskStage,
    QuickTaskStatus,
    SeverityFloor,
)

_SCAN_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_TASK_ID = "11111111-2222-3333-4444-555555555555"
_ASSET_ID = "99999999-8888-7777-6666-555555555555"
_DEADLINE = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


def _budget(**overrides) -> QuickBudget:
    base = dict(
        wall_clock_budget_seconds=900,
        discovery_budget_seconds=180,
        fingerprint_budget_seconds=120,
        verification_budget_seconds=240,
        ai_budget_seconds=90,
        report_budget_seconds=60,
        request_budget=500,
        per_host_budget=50,
        concurrency_budget=4,
        reserve_for_validation_percent=20,
    )
    base.update(overrides)
    return QuickBudget(**base)


def _config(**overrides) -> QuickScanConfig:
    base = dict(
        profile=QuickProfileName.BALANCED,
        wall_clock_budget_seconds=900,
        ai_budget_seconds=90,
        reserve_for_validation_percent=20,
        max_targets=10,
        max_urls_per_host=50,
        crawl_depth=2,
        severity_floor=SeverityFloor.MEDIUM,
    )
    base.update(overrides)
    return QuickScanConfig(**base)


def _task(**overrides) -> QuickTask:
    base = dict(
        task_id=_TASK_ID,
        stage=QuickTaskStage.FINGERPRINT,
        target_ref="https://app.example/",
        tool_id="nuclei",
        capability_id="http.fingerprint",
        estimated_seconds=30,
        estimated_requests=20,
        priority_score=0.7,
        idempotency_key="scan:task:nuclei:fingerprint",
    )
    base.update(overrides)
    return QuickTask(**base)


def _coverage(**overrides) -> QuickCoverageRecord:
    base = dict(
        asset_id=_ASSET_ID,
        capability_id="http.fingerprint",
        state=QuickCoverageState.TESTED,
        reason_code="completed",
    )
    base.update(overrides)
    return QuickCoverageRecord(**base)


def _plan(**overrides) -> QuickScanPlan:
    base = dict(
        scan_id=_SCAN_ID,
        profile=QuickProfileName.BALANCED,
        deadline_at=_DEADLINE,
        budget=_budget(),
        tasks=(_task(),),
        coverage_intent=(_coverage(),),
        plan_version=1,
        prompt_version="quick-planner-v1",
        model_route="wrb",
    )
    base.update(overrides)
    return QuickScanPlan(**base)


def _revision(**overrides) -> QuickPlanRevision:
    base = dict(
        scan_id=_SCAN_ID,
        from_version=1,
        to_version=2,
        revision_reason="new_host_discovered",
        cost_estimate_seconds=45,
        remaining_budget_seconds=600,
        created_at=_DEADLINE,
    )
    base.update(overrides)
    return QuickPlanRevision(**base)


def test_valid_quick_scan_config() -> None:
    cfg = _config()
    assert cfg.profile is QuickProfileName.BALANCED
    assert cfg.severity_floor is SeverityFloor.MEDIUM
    assert cfg.cloud_llm_allowed is False
    assert cfg.template_policy_id == "quick-default"
    assert cfg.authenticated_context_id is None


def test_valid_quick_scan_plan_task_coverage_revision() -> None:
    task = _task()
    assert task.status is QuickTaskStatus.QUEUED
    assert task.stage is QuickTaskStage.FINGERPRINT

    coverage = _coverage()
    assert coverage.state is QuickCoverageState.TESTED

    plan = _plan()
    assert plan.mode == "quick"
    assert plan.tasks == (task,)
    assert plan.coverage_intent == (coverage,)

    revision = _revision()
    assert revision.from_version == 1
    assert revision.to_version == 2
    assert revision.revision_reason == "new_host_discovered"


def test_extra_fields_rejected_on_config() -> None:
    with pytest.raises(ValidationError):
        QuickScanConfig(
            profile=QuickProfileName.COMPACT,
            wall_clock_budget_seconds=300,
            ai_budget_seconds=30,
            reserve_for_validation_percent=10,
            max_targets=1,
            max_urls_per_host=10,
            crawl_depth=1,
            password="should-never-be-here",
        )


@pytest.mark.parametrize(
    "factory",
    [_budget, _config, _task, _coverage, _plan, _revision],
)
def test_extra_fields_rejected_on_all_quick_models(factory) -> None:
    obj = factory()
    payload = obj.model_dump()
    payload["unexpected_field"] = "boom"
    with pytest.raises(ValidationError):
        type(obj).model_validate(payload)


def test_json_round_trip_stable() -> None:
    cfg = _config(authenticated_context_id="ctx-ref-not-a-secret")
    plan = _plan()
    revision = _revision()
    for obj in (cfg, plan, revision, _task(), _coverage(), _budget()):
        dumped = obj.model_dump(mode="json")
        restored = type(obj).model_validate(dumped)
        assert restored == obj
        again = restored.model_dump(mode="json")
        assert again == dumped


def test_frozen_models_reject_mutation() -> None:
    cfg = _config()
    with pytest.raises(ValidationError):
        cfg.profile = QuickProfileName.EXTENDED  # type: ignore[misc]


def test_invalid_profile_rejected() -> None:
    with pytest.raises(ValidationError):
        _config(profile="turbo")


def test_invalid_severity_rejected() -> None:
    with pytest.raises(ValidationError):
        _config(severity_floor="urgent")


def test_invalid_budget_bounds_rejected() -> None:
    with pytest.raises(ValidationError):
        _config(wall_clock_budget_seconds=0)
    with pytest.raises(ValidationError):
        _budget(concurrency_budget=0)
    with pytest.raises(ValidationError):
        _budget(reserve_for_validation_percent=51)


def test_plan_mode_must_be_quick() -> None:
    with pytest.raises(ValidationError):
        _plan(mode="lab_unrestricted")
    with pytest.raises(ValidationError):
        _plan(mode="production")


def test_authenticated_context_id_is_ref_not_credential() -> None:
    cfg = _config(authenticated_context_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    dumped = cfg.model_dump()
    assert dumped["authenticated_context_id"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert "password" not in dumped
    assert "token" not in dumped
    assert "secret" not in dumped
