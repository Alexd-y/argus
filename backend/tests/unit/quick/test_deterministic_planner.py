"""QUICK-003 — deterministic QuickPlanner: same input → same plan; denylist; scope."""

from __future__ import annotations

from datetime import UTC, datetime

from src.capabilities.graph import CapabilityGraph
from src.capabilities.schemas import (
    CapabilityApplicability,
    CapabilityFamily,
    CapabilityNode,
    ProductionRisk,
)
from src.execution_mode.mode import ExecutionMode
from src.nuclei.schemas import NucleiTemplateManifest, TemplateSource
from src.nuclei.template_registry import NucleiTemplateRegistry
from src.quick.disallowed import (
    DISALLOWED_TOOL_IDS,
    NOT_SCHEDULED_BY_QUICK_PROFILE,
    SKIPPED_COVERAGE_CLASSES,
    QuickDisallowedReason,
)
from src.quick.planner import QuickPlanner, QuickPlannerRequest, QuickPlannerTarget
from src.quick.schemas import (
    AssetFingerprint,
    FingerprintFact,
    QuickBudget,
    QuickCoverageState,
    QuickProfileName,
    QuickScanConfig,
    SeverityFloor,
)

_SCAN_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_ASSET_ID = "99999999-8888-7777-6666-555555555555"
_DEADLINE = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
_SHA256 = "a" * 64
_TARGET = "https://app.example/"
_DISALLOWED_SAMPLE = (
    "sqlmap",
    "hydra",
    "clusterbomb",
    "ffuf-wordlist-full",
    "linpeas",
    "impacket",
    "dalfox",
)


def _budget() -> QuickBudget:
    return QuickBudget(
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


def _config() -> QuickScanConfig:
    return QuickScanConfig(
        profile=QuickProfileName.BALANCED,
        wall_clock_budget_seconds=900,
        ai_budget_seconds=90,
        reserve_for_validation_percent=20,
        max_targets=10,
        max_urls_per_host=50,
        crawl_depth=2,
        severity_floor=SeverityFloor.MEDIUM,
    )


def _https_fingerprint(asset_id: str = _ASSET_ID) -> AssetFingerprint:
    return AssetFingerprint(
        asset_id=asset_id,
        protocol=FingerprintFact(value="https", confidence=1.0),
        service=FingerprintFact(value="http", confidence=0.9),
        product=FingerprintFact(value="nginx", confidence=0.8),
    )


def _web_node(
    node_id: str,
    *,
    tools: tuple[str, ...],
    quick_eligible: bool = True,
    allowed_phases: tuple[str, ...] = ("vuln_analysis",),
    production_risk: ProductionRisk = ProductionRisk.ACTIVE,
    family: CapabilityFamily = CapabilityFamily.WEB_APPLICATION,
) -> CapabilityNode:
    return CapabilityNode(
        id=node_id,
        family=family,
        asset_types=("web_app",),
        production_risk=production_risk,
        allowed_phases=allowed_phases,
        tools=tools,
        quick_eligible=quick_eligible,
        estimated_cost_seconds=30,
        applicability=CapabilityApplicability(protocols=("http", "https")),
    )


def _graph_with_denylist_bait() -> CapabilityGraph:
    return CapabilityGraph(
        nodes=(
            _web_node("web.application.cve.known_product", tools=("nuclei",)),
            _web_node(
                "web.application.auth.session",
                tools=("sqlmap", "hydra", "clusterbomb", "ffuf-wordlist-full", "nuclei"),
            ),
            _web_node(
                "linux.postex.persist",
                tools=("linpeas", "impacket"),
                allowed_phases=("post_exploitation",),
                family=CapabilityFamily.PRIVILEGE_ESCALATION_LINUX,
            ),
            _web_node(
                "web.application.forms.input_validation",
                tools=("dalfox", "ffuf"),
                quick_eligible=False,
                allowed_phases=("quick_fuzz",),
            ),
        ),
        edges=(),
    )


def _registry_with_http_template() -> NucleiTemplateRegistry:
    registry = NucleiTemplateRegistry()
    registry.register(
        NucleiTemplateManifest(
            template_id="http-cve-nginx",
            version="1",
            source=TemplateSource.INTERNAL,
            sha256=_SHA256,
            signature="sig",
            verified=True,
            protocols=("http",),
            risk_level="passive",
            tags=("cve", "nginx"),
            product="nginx",
            severity="high",
        ),
        mode=ExecutionMode.QUICK,
    )
    return registry


def _request(**overrides) -> QuickPlannerRequest:
    base = dict(
        scan_id=_SCAN_ID,
        config=_config(),
        budget=_budget(),
        deadline_at=_DEADLINE,
        fingerprints=(_https_fingerprint(),),
        targets=(
            QuickPlannerTarget(
                target_ref=_TARGET,
                asset_id=_ASSET_ID,
                in_scope=True,
            ),
        ),
        catalog_versions=(("tools", "v1"), ("payloads", "v1")),
        oast_available=False,
        headless_signal=False,
        asset_criticality=0.5,
    )
    base.update(overrides)
    return QuickPlannerRequest(**base)


def _planner() -> QuickPlanner:
    return QuickPlanner(graph=_graph_with_denylist_bait(), registry=_registry_with_http_template())


def test_same_input_yields_identical_plan() -> None:
    planner = _planner()
    request = _request()
    first = planner.plan(request)
    second = planner.plan(request)
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.tasks == second.tasks
    assert first.coverage_intent == second.coverage_intent
    assert first.prompt_version == "deterministic-v1"
    assert first.model_route == "deterministic"


def test_plan_never_schedules_disallowed_or_post_ex_tools() -> None:
    plan = _planner().plan(_request())
    tool_ids = {task.tool_id for task in plan.tasks}
    assert tool_ids
    assert tool_ids.isdisjoint(DISALLOWED_TOOL_IDS)
    for banned in _DISALLOWED_SAMPLE:
        assert banned not in tool_ids
    capability_ids = {task.capability_id for task in plan.tasks}
    assert "linux.postex.persist" not in capability_ids
    assert all(task.tool_id != "linpeas" for task in plan.tasks)
    skipped = {record.capability_id for record in plan.coverage_intent}
    for capability_id, _reason in SKIPPED_COVERAGE_CLASSES:
        assert capability_id in skipped


def test_out_of_scope_flag_yields_zero_network_tasks() -> None:
    plan = _planner().plan(_request(scope_allowed=False))
    assert plan.tasks == ()
    assert any(
        f"scope={QuickDisallowedReason.OUT_OF_SCOPE.value}" in item
        for item in plan.assumptions
    )
    assert all(
        record.state is QuickCoverageState.NOT_SCHEDULED for record in plan.coverage_intent
    )


def test_all_targets_out_of_scope_yields_zero_network_tasks() -> None:
    plan = _planner().plan(
        _request(
            targets=(
                QuickPlannerTarget(
                    target_ref=_TARGET,
                    asset_id=_ASSET_ID,
                    in_scope=False,
                ),
            )
        )
    )
    assert plan.tasks == ()


def test_empty_targets_and_fingerprints_yield_zero_network_tasks() -> None:
    plan = _planner().plan(_request(fingerprints=(), targets=()))
    assert plan.tasks == ()
    reasons = {record.reason_code for record in plan.coverage_intent}
    assert NOT_SCHEDULED_BY_QUICK_PROFILE in reasons


def test_select_candidates_is_deterministic_and_sorted() -> None:
    planner = _planner()
    request = _request()
    first = planner.select_candidates(request)
    second = planner.select_candidates(request)
    assert first == second
    scores = [item.priority_score for item in first]
    assert scores == sorted(scores, reverse=True)
    assert all(item.tool_id not in DISALLOWED_TOOL_IDS for item in first)
