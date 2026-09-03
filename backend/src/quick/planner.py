"""Deterministic Quick baseline planner (QUICK-003). No LLM CLI generation."""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
)

from src.capabilities.graph import CapabilityGraph, default_capability_graph
from src.capabilities.schemas import CapabilityNode
from src.nuclei.template_registry import NucleiTemplateRegistry
from src.quick.applicability import (
    expected_impact_for_node,
    exploitability_for_node,
    is_applicable,
    mean_evidence_confidence,
)
from src.quick.audit import emit_quick_audit_event
from src.quick.disallowed import (
    NOT_SCHEDULED_BY_QUICK_PROFILE,
    SKIPPED_COVERAGE_CLASSES,
    QuickDisallowedReason,
    allowed_tools_for_quick,
    node_excluded_from_quick,
)
from src.quick.metrics import (
    record_assets_discovered,
    record_plan_revision,
    record_task,
    record_templates_selected,
)
from src.quick.schemas import (
    AssetFingerprint,
    FingerprintFact,
    QuickBudget,
    QuickCoverageRecord,
    QuickCoverageState,
    QuickProfileName,
    QuickScanConfig,
    QuickScanPlan,
    QuickTask,
    QuickTaskStage,
    QuickTaskStatus,
    SeverityFloor,
    coerce_quick_config,
)
from src.quick.scoring import (
    DEFAULT_SCORING_WEIGHTS,
    ScoringComponents,
    ScoringWeights,
    compute_priority,
    tie_break_key,
)
from src.quick.template_selector import QuickTemplateSelector

_PLAN_STAGES: tuple[str, ...] = (
    QuickTaskStage.DISCOVERY.value,
    QuickTaskStage.FINGERPRINT.value,
    QuickTaskStage.TEST.value,
    QuickTaskStage.VERIFY.value,
    QuickTaskStage.TRIAGE.value,
    QuickTaskStage.REPORT.value,
)
_SCAN_LEVEL_ASSET_ID = "00000000-0000-4000-8000-000000000000"
_DETERMINISTIC_PROMPT = "deterministic-v1"
_DETERMINISTIC_ROUTE = "deterministic"


class QuickPlannerTarget(BaseModel):
    """One target considered by the planner, with an explicit scope flag."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_ref: StrictStr = Field(min_length=1, max_length=256)
    asset_id: StrictStr = Field(min_length=1, max_length=36)
    in_scope: StrictBool = True


class QuickPlannerRequest(BaseModel):
    """Typed planner input. Same request + catalog versions → same plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: StrictStr = Field(min_length=1, max_length=36)
    config: QuickScanConfig
    budget: QuickBudget
    deadline_at: datetime
    fingerprints: tuple[AssetFingerprint, ...] = Field(default_factory=tuple)
    targets: tuple[QuickPlannerTarget, ...] = Field(default_factory=tuple)
    scope_allowed: StrictBool | None = None
    catalog_versions: tuple[tuple[StrictStr, StrictStr], ...] = Field(default_factory=tuple)
    oast_available: StrictBool = False
    headless_signal: StrictBool = False
    asset_criticality: StrictFloat = Field(default=0.5, ge=0.0, le=1.0)
    prompt_version: StrictStr = Field(default=_DETERMINISTIC_PROMPT, min_length=1, max_length=128)
    model_route: StrictStr = Field(default=_DETERMINISTIC_ROUTE, min_length=1, max_length=128)
    plan_version: StrictInt = Field(default=1, ge=1)


class QuickPlanCandidate(BaseModel):
    """Typed candidate for optional AI rerank (QUICK-006). Planner works without AI."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability_id: StrictStr = Field(min_length=1, max_length=256)
    tool_id: StrictStr = Field(min_length=1, max_length=128)
    target_ref: StrictStr = Field(min_length=1, max_length=256)
    asset_id: StrictStr = Field(min_length=1, max_length=36)
    template_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    template_digest: StrictStr | None = Field(default=None, min_length=64, max_length=64)
    priority_score: StrictFloat = Field(ge=0.0, le=1.0)
    estimated_seconds: StrictInt = Field(ge=0, le=86_400)
    estimated_requests: StrictInt = Field(ge=0)


def _stable_uuid(*parts: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, ":".join(parts)))


def _fingerprint_for_asset(
    fingerprints: Sequence[AssetFingerprint],
    asset_id: str,
) -> AssetFingerprint | None:
    for fingerprint in fingerprints:
        if fingerprint.asset_id == asset_id:
            return fingerprint
    return None


def _in_scope_targets(request: QuickPlannerRequest) -> tuple[QuickPlannerTarget, ...]:
    if request.scope_allowed is False:
        return ()
    if request.targets:
        return tuple(target for target in request.targets if target.in_scope)
    return tuple(
        QuickPlannerTarget(
            target_ref=fingerprint.asset_id,
            asset_id=fingerprint.asset_id,
            in_scope=True,
        )
        for fingerprint in request.fingerprints
    )


def _coverage_asset_id(targets: Sequence[QuickPlannerTarget]) -> str:
    if not targets:
        return _SCAN_LEVEL_ASSET_ID
    return min(target.asset_id for target in targets)


def _skipped_class_records(asset_id: str) -> tuple[QuickCoverageRecord, ...]:
    records = [
        QuickCoverageRecord(
            asset_id=asset_id,
            capability_id=capability_id,
            state=QuickCoverageState.NOT_SCHEDULED,
            reason_code=reason,
        )
        for capability_id, reason in SKIPPED_COVERAGE_CLASSES
    ]
    return tuple(sorted(records, key=lambda item: item.capability_id))


class QuickPlanner:
    """Deterministic capability × fingerprint planner for execution_mode=quick."""

    def __init__(
        self,
        graph: CapabilityGraph | None = None,
        registry: NucleiTemplateRegistry | None = None,
        selector: QuickTemplateSelector | None = None,
        scoring: ScoringWeights | None = None,
    ) -> None:
        self._graph = graph or default_capability_graph()
        self._registry = registry or NucleiTemplateRegistry()
        self._selector = selector or QuickTemplateSelector(registry=self._registry)
        self._scoring = scoring or DEFAULT_SCORING_WEIGHTS

    def select_candidates(self, request: QuickPlannerRequest) -> tuple[QuickPlanCandidate, ...]:
        """Public typed candidate list for later rerank. Fully deterministic."""
        targets = _in_scope_targets(request)
        if not targets:
            return ()
        built: list[QuickPlanCandidate] = []
        for target in sorted(targets, key=lambda item: (item.asset_id, item.target_ref)):
            fingerprint = _fingerprint_for_asset(request.fingerprints, target.asset_id)
            if fingerprint is None:
                fingerprint = AssetFingerprint(asset_id=target.asset_id)
            built.extend(self._candidates_for_target(request, target, fingerprint))
        built.sort(
            key=lambda item: tie_break_key(
                priority_score=item.priority_score,
                capability_id=item.capability_id,
                tool_id=item.tool_id,
                template_id=(item.template_ids[0] if item.template_ids else ""),
            )
        )
        return tuple(built)

    def plan(self, request: QuickPlannerRequest) -> QuickScanPlan:
        """Build an immutable QuickScanPlan. Identical inputs → identical plan."""
        targets = _in_scope_targets(request)
        coverage_asset = _coverage_asset_id(targets)
        coverage: list[QuickCoverageRecord] = list(_skipped_class_records(coverage_asset))
        assumptions = _assumptions(request, targets)

        if not targets:
            coverage.sort(key=lambda item: (item.asset_id, item.capability_id))
            plan = self._materialize(request, (), tuple(coverage), assumptions)
            _emit_plan_observability(request, plan, targets)
            return plan

        candidates = self.select_candidates(request)
        coverage.extend(self._gap_records(request, targets, candidates))
        tasks = _tasks_from_candidates(request, candidates)
        coverage.sort(key=lambda item: (item.asset_id, item.capability_id))
        plan = self._materialize(request, tasks, tuple(coverage), assumptions)
        _emit_plan_observability(request, plan, targets)
        return plan

    def _candidates_for_target(
        self,
        request: QuickPlannerRequest,
        target: QuickPlannerTarget,
        fingerprint: AssetFingerprint,
    ) -> list[QuickPlanCandidate]:
        nuclei_nodes: list[CapabilityNode] = []
        other: list[QuickPlanCandidate] = []
        for node in sorted(self._graph.nodes, key=lambda item: item.id):
            if not is_applicable(fingerprint, node):
                continue
            if node_excluded_from_quick(node):
                continue
            tools = allowed_tools_for_quick(node)
            if not tools:
                continue
            nuclei_only = tuple(tool_id for tool_id in tools if tool_id == "nuclei")
            other_tools = tuple(tool_id for tool_id in tools if tool_id != "nuclei")
            if nuclei_only:
                nuclei_nodes.append(node)
            for tool_id in other_tools:
                other.append(
                    self._candidate(
                        request,
                        target,
                        node,
                        tool_id,
                        template_ids=(),
                        template_digest=None,
                    )
                )
        if nuclei_nodes:
            manifest = self._selector.select(
                fingerprint,
                request.config,
                oast_available=request.oast_available,
                headless_signal=request.headless_signal,
                budget_allows_oast=request.budget.request_budget > 0,
                budget_allows_headless=request.budget.request_budget > 0,
            )
            if manifest.template_ids:
                for node in nuclei_nodes:
                    other.append(
                        self._candidate(
                            request,
                            target,
                            node,
                            "nuclei",
                            template_ids=manifest.template_ids,
                            template_digest=manifest.digest_sha256,
                        )
                    )
        return other

    def _candidate(
        self,
        request: QuickPlannerRequest,
        target: QuickPlannerTarget,
        node: CapabilityNode,
        tool_id: str,
        *,
        template_ids: tuple[str, ...],
        template_digest: str | None,
    ) -> QuickPlanCandidate:
        fingerprint = _fingerprint_for_asset(request.fingerprints, target.asset_id)
        confidence = mean_evidence_confidence(fingerprint) if fingerprint else 0.4
        components = ScoringComponents(
            exploitability_probability=exploitability_for_node(node),
            expected_impact=expected_impact_for_node(node),
            evidence_confidence=confidence,
            asset_criticality=request.asset_criticality,
            coverage_value=1.0,
            estimated_cost=float(max(node.estimated_cost_seconds, 1)),
        )
        score = compute_priority(components, self._scoring)
        requests_est = max(1, node.estimated_cost_seconds)
        return QuickPlanCandidate(
            capability_id=node.id,
            tool_id=tool_id,
            target_ref=target.target_ref,
            asset_id=target.asset_id,
            template_ids=template_ids,
            template_digest=template_digest,
            priority_score=score,
            estimated_seconds=node.estimated_cost_seconds,
            estimated_requests=requests_est,
        )

    def _gap_records(
        self,
        request: QuickPlannerRequest,
        targets: Sequence[QuickPlannerTarget],
        candidates: Sequence[QuickPlanCandidate],
    ) -> list[QuickCoverageRecord]:
        scheduled = {(item.capability_id, item.asset_id) for item in candidates}
        records: list[QuickCoverageRecord] = []
        seen: set[tuple[str, str]] = set()
        for target in targets:
            fingerprint = _fingerprint_for_asset(request.fingerprints, target.asset_id)
            if fingerprint is None:
                fingerprint = AssetFingerprint(asset_id=target.asset_id)
            for node in sorted(self._graph.nodes, key=lambda item: item.id):
                key = (node.id, target.asset_id)
                if key in scheduled or key in seen:
                    continue
                if not is_applicable(fingerprint, node):
                    continue
                seen.add(key)
                records.append(
                    QuickCoverageRecord(
                        asset_id=target.asset_id,
                        capability_id=node.id,
                        state=QuickCoverageState.NOT_SCHEDULED,
                        reason_code=NOT_SCHEDULED_BY_QUICK_PROFILE,
                    )
                )
        return records

    def _materialize(
        self,
        request: QuickPlannerRequest,
        tasks: tuple[QuickTask, ...],
        coverage: tuple[QuickCoverageRecord, ...],
        assumptions: tuple[str, ...],
    ) -> QuickScanPlan:
        return QuickScanPlan(
            scan_id=request.scan_id,
            profile=request.config.profile,
            deadline_at=request.deadline_at,
            budget=request.budget,
            assumptions=assumptions,
            stages=_PLAN_STAGES,
            tasks=tasks,
            fallbacks=("deterministic_planner", "ai_rerank_optional"),
            coverage_intent=coverage,
            plan_version=request.plan_version,
            prompt_version=request.prompt_version,
            model_route=request.model_route,
        )


def _tasks_from_candidates(
    request: QuickPlannerRequest,
    candidates: Sequence[QuickPlanCandidate],
) -> tuple[QuickTask, ...]:
    merged: dict[tuple[str, str], QuickPlanCandidate] = {}
    for candidate in candidates:
        key = (candidate.tool_id, candidate.target_ref)
        current = merged.get(key)
        if current is None:
            merged[key] = candidate
            continue
        better = tie_break_key(
            priority_score=candidate.priority_score,
            capability_id=candidate.capability_id,
            tool_id=candidate.tool_id,
            template_id=candidate.template_ids[0] if candidate.template_ids else "",
        ) < tie_break_key(
            priority_score=current.priority_score,
            capability_id=current.capability_id,
            tool_id=current.tool_id,
            template_id=current.template_ids[0] if current.template_ids else "",
        )
        if better:
            merged[key] = candidate
    tasks: list[QuickTask] = []
    ordered = sorted(
        merged.values(),
        key=lambda item: tie_break_key(
            priority_score=item.priority_score,
            capability_id=item.capability_id,
            tool_id=item.tool_id,
            template_id=item.template_ids[0] if item.template_ids else "",
        ),
    )
    for candidate in ordered:
        digest = candidate.template_digest or "none"
        idempotency = (
            f"{request.scan_id}:{candidate.tool_id}:{candidate.target_ref}:"
            f"{digest}:{request.plan_version}"
        )[:256]
        tasks.append(
            QuickTask(
                task_id=_stable_uuid(
                    request.scan_id,
                    candidate.capability_id,
                    candidate.tool_id,
                    candidate.target_ref,
                    str(request.plan_version),
                ),
                stage=QuickTaskStage.TEST,
                target_ref=candidate.target_ref,
                tool_id=candidate.tool_id,
                capability_id=candidate.capability_id,
                estimated_seconds=candidate.estimated_seconds,
                estimated_requests=candidate.estimated_requests,
                priority_score=candidate.priority_score,
                depends_on=(),
                success_signal=candidate.template_ids[:8],
                stop_conditions=("deadline_reached", "budget_exhausted"),
                idempotency_key=idempotency,
                status=QuickTaskStatus.QUEUED,
            )
        )
    return tuple(tasks)


def _assumptions(
    request: QuickPlannerRequest,
    targets: Sequence[QuickPlannerTarget],
) -> tuple[str, ...]:
    versions = tuple(f"{key}={value}" for key, value in request.catalog_versions)
    items = [
        "planner=deterministic-v1",
        f"profile={request.config.profile.value}",
        f"in_scope_targets={len(targets)}",
        f"oast_available={str(request.oast_available).lower()}",
        f"headless_signal={str(request.headless_signal).lower()}",
        "ai_rerank=disabled",
    ]
    items.extend(versions)
    if request.scope_allowed is False or not targets:
        items.append(f"scope={QuickDisallowedReason.OUT_OF_SCOPE.value}")
    return tuple(items)


def _emit_plan_observability(
    request: QuickPlannerRequest,
    plan: QuickScanPlan,
    targets: Sequence[QuickPlannerTarget],
) -> None:
    """Thin metrics/audit emit. Must never affect plan contents."""
    if targets:
        record_assets_discovered(amount=len(targets))
    template_ids: set[str] = set()
    for task in plan.tasks:
        record_task(stage=task.stage.value, status=task.status.value, tool=task.tool_id)
        template_ids.update(str(item) for item in task.success_signal if item)
    if template_ids:
        record_templates_selected(amount=len(template_ids))
    if request.plan_version > 1:
        record_plan_revision()
        emit_quick_audit_event(
            "quick.revision",
            scan_id=request.scan_id,
            payload={"plan_version": request.plan_version, "task_count": len(plan.tasks)},
        )
    emit_quick_audit_event(
        "quick.plan",
        scan_id=request.scan_id,
        payload={
            "plan_version": plan.plan_version,
            "prompt_version": plan.prompt_version,
            "model_route": plan.model_route,
            "task_count": len(plan.tasks),
            "in_scope_targets": len(targets),
        },
    )


def default_balanced_budget() -> QuickBudget:
    """Conservative budget used by the VA adapter until QuickBudgetManager exists."""
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


def plan_for_va_target(
    *,
    target_url: str,
    scan_options: Mapping[str, Any] | None = None,
    planner: QuickPlanner | None = None,
    now: datetime | None = None,
) -> QuickScanPlan:
    """Thin entry used by the VA scan-mode planner when execution_mode=quick."""
    options = dict(scan_options or {})
    in_scope = bool(options.get("in_scope", options.get("scope_allowed", True)))
    scan_id_raw = str(options.get("scan_id") or "").strip()
    scan_id = scan_id_raw[:36] if scan_id_raw else _stable_uuid("va-quick", target_url)
    asset_id = str(options.get("asset_id") or "").strip()[:36] or _stable_uuid(
        "va-quick-asset", target_url
    )
    config = coerce_quick_config(options.get("quick_config"))
    if config is None:
        config = QuickScanConfig(
            profile=QuickProfileName.BALANCED,
            wall_clock_budget_seconds=900,
            ai_budget_seconds=90,
            reserve_for_validation_percent=20,
            max_targets=10,
            max_urls_per_host=50,
            crawl_depth=2,
            severity_floor=SeverityFloor.MEDIUM,
        )
    budget = options.get("quick_budget")
    if not isinstance(budget, QuickBudget):
        budget = default_balanced_budget()
    deadline = options.get("deadline_at")
    if not isinstance(deadline, datetime):
        origin = now or datetime.now(tz=UTC)
        deadline = origin + timedelta(seconds=int(config.wall_clock_budget_seconds))
    protocol = "https" if target_url.lower().startswith("https://") else "http"
    fingerprint = AssetFingerprint(
        asset_id=asset_id,
        protocol=FingerprintFact(value=protocol, confidence=1.0),
        service=FingerprintFact(value="http", confidence=0.8),
    )
    request = QuickPlannerRequest(
        scan_id=scan_id,
        config=config,
        budget=budget,
        deadline_at=deadline,
        fingerprints=(fingerprint,),
        targets=(
            QuickPlannerTarget(
                target_ref=target_url,
                asset_id=asset_id,
                in_scope=in_scope,
            ),
        ),
        scope_allowed=in_scope,
        oast_available=bool(options.get("oast_available", False)),
        headless_signal=bool(options.get("headless_signal", False)),
    )
    registry = options.get("nuclei_registry")
    resolved_planner = planner or QuickPlanner(
        registry=registry if isinstance(registry, NucleiTemplateRegistry) else None,
    )
    return resolved_planner.plan(request)
