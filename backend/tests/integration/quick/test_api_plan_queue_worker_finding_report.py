"""QUICK-009 — mocked plan → queue → finding → report path (no live broker)."""

from __future__ import annotations

from datetime import UTC, datetime

from src.orchestration.coverage_phase_sink import (
    CoveragePhaseSink,
    InMemoryCoverageStore,
)
from src.quick.budget import QuickBudgetManager
from src.quick.circuit_breaker import QuickCircuitBreaker
from src.quick.clock import FrozenClock
from src.quick.coverage import coverage_accounting_rate, write_quick_coverage
from src.quick.idempotency import QuickIdempotencyStore
from src.quick.llm_routes import _template_report
from src.quick.planner import QuickPlanner, QuickPlannerRequest, QuickPlannerTarget
from src.quick.profiles import DeploymentQuickClamps, load_quick_profiles
from src.quick.resolver import QuickProfileResolver
from src.quick.scheduler import QuickScheduler
from src.quick.schemas import (
    AssetFingerprint,
    FingerprintFact,
    QuickBudget,
    QuickProfileName,
    QuickScanConfig,
    SeverityFloor,
)
from src.quick.workflow import QuickWorkflow

_SCAN_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_ASSET_ID = "99999999-8888-7777-6666-555555555555"
_TENANT = "11111111-2222-3333-4444-555555555555"
_DEADLINE = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


def test_plan_queue_finding_report_mocked() -> None:
    config = QuickScanConfig(
        profile=QuickProfileName.BALANCED,
        wall_clock_budget_seconds=900,
        ai_budget_seconds=90,
        reserve_for_validation_percent=20,
        max_targets=10,
        max_urls_per_host=50,
        crawl_depth=2,
        severity_floor=SeverityFloor.MEDIUM,
        enable_ai=False,
    )
    budget = QuickBudget(
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
    )
    plan = QuickPlanner().plan(
        QuickPlannerRequest(
            scan_id=_SCAN_ID,
            config=config,
            budget=budget,
            deadline_at=_DEADLINE,
            fingerprints=(
                AssetFingerprint(
                    asset_id=_ASSET_ID,
                    protocol=FingerprintFact(value="https", confidence=1.0),
                    service=FingerprintFact(value="http", confidence=0.9),
                ),
            ),
            targets=(
                QuickPlannerTarget(
                    target_ref="https://app.example/",
                    asset_id=_ASSET_ID,
                    in_scope=True,
                ),
            ),
        )
    )
    clock = FrozenClock(_DEADLINE)
    manager = QuickBudgetManager(
        clock=clock,
        catalog=load_quick_profiles(),
        clamps=DeploymentQuickClamps(),
    )
    manager.open_scan(
        tenant_id=_TENANT,
        scan_id=_SCAN_ID,
        config=QuickProfileResolver(
            catalog=load_quick_profiles(),
            clamps=DeploymentQuickClamps(),
        ).resolve(_TENANT, QuickProfileName.BALANCED),
        started_at=_DEADLINE,
    )
    scheduler = QuickScheduler(
        QuickWorkflow(plan.tasks),
        budget_manager=manager,
        circuit_breaker=QuickCircuitBreaker(),
        idempotency=QuickIdempotencyStore(),
        clock=clock,
    )
    pick = scheduler.pick_next(
        scan_id=_SCAN_ID,
        completed_ids=set(),
        running_ids=set(),
    )
    sink = CoveragePhaseSink(store=InMemoryCoverageStore())
    written = write_quick_coverage(
        tenant_id=_TENANT,
        scan_id=_SCAN_ID,
        records=plan.coverage_intent,
        sink=sink,
    )
    assert coverage_accounting_rate(plan.coverage_intent, written) == 1.0
    report = _template_report(
        scan_id=_SCAN_ID,
        profile=config.profile,
        findings=({"finding_id": "f1", "verdict": "hypothesis", "severity": "medium"},),
        coverage=plan.coverage_intent,
        budget_usage={"elapsed_seconds": 12},
        failures=(),
        versions={"planner": "deterministic-v1"},
        assets=(_ASSET_ID,),
    )
    assert report.scan_id == _SCAN_ID
    assert pick.task is None or pick.task.tool_id != "sqlmap"
