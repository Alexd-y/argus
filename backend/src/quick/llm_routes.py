"""Typed Quick LLM calls through ``call_llm_unified`` only (QUICK-006).

Fallbacks: Qwythos down → deterministic planner; WRB down → needs_verification;
small model down → rules; schema fail → discard AI; ``enable_ai=false`` →
full deterministic path. Timeouts never block report generation.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import yaml

from src.capabilities.graph import CapabilityGraph, default_capability_graph
from src.execution_mode.mode import ExecutionMode
from src.llm.facade import call_llm_unified
from src.llm.schemas import ContentClass
from src.llm.task_router import LLMTask
from src.orchestration.prompt_registry import sanitize_kwargs_for_prompt
from src.quick.audit import emit_quick_audit_event
from src.quick.disallowed import allowed_tools_for_quick
from src.quick.llm_schemas import (
    ASSET_FINGERPRINT_SCHEMA_ID,
    FINDING_TRIAGE_SCHEMA_ID,
    QUICK_REPORT_SCHEMA_ID,
    QUICK_SCAN_PLAN_SCHEMA_ID,
    SECURITY_CRITIQUE_SCHEMA_ID,
    LlmSchemaError,
    apply_llm_tasks_to_plan,
    parse_llm_critique,
    parse_llm_fingerprint,
    parse_llm_plan,
    parse_llm_report,
    parse_llm_triage,
)
from src.quick.metrics import (
    record_findings_from_rows,
    record_llm_call,
    record_scan_duration,
)
from src.quick.planner import QuickPlanner, QuickPlannerRequest
from src.quick.rag_profile import (
    QuickRagProfile,
    format_quick_rag_for_prompt,
)
from src.quick.schemas import (
    AssetFingerprint,
    FindingTriage,
    FindingTriageVerdict,
    FingerprintFact,
    QuickCoverageRecord,
    QuickProfileName,
    QuickReport,
    QuickScanConfig,
    QuickScanPlan,
    SecurityCritique,
    SeverityFloor,
)
from src.rag.ingestion import redact_secrets
from src.rag.schemas import RagEvidencePack

logger = logging.getLogger(__name__)

PROMPT_PLANNER: Final[str] = "quick_planner_v1"
PROMPT_FINGERPRINT: Final[str] = "quick_fingerprint_classifier_v1"
PROMPT_TRIAGE: Final[str] = "quick_finding_triage_v1"
PROMPT_CRITIC: Final[str] = "quick_security_critic_v1"
PROMPT_REPORTER: Final[str] = "quick_reporter_v1"

_PROMPTS_DIR: Final[Path] = (
    Path(__file__).resolve().parents[2] / "config" / "prompts"
)
_DEFAULT_AI_TIMEOUT_SECONDS: Final[float] = 20.0
_MAX_CONTEXT_CHARS: Final[int] = 12_000
_CACHE_MAX: Final[int] = 128

_PROMPT_CACHE: dict[str, dict[str, Any]] = {}
_RESPONSE_CACHE: dict[str, str] = {}


@dataclass(frozen=True)
class QuickLlmResult[T]:
    """Typed AI result plus degrade metadata for handlers (QUICK-004/005)."""

    value: T
    used_ai: bool
    model_route: str
    prompt_version: str
    fallback_reason: str | None = None
    degraded: tuple[str, ...] = ()


def catalog_tool_ids(graph: CapabilityGraph | None = None) -> frozenset[str]:
    """Tool ids Quick may schedule — capability catalog minus the denylist."""
    active = graph or default_capability_graph()
    ids: set[str] = set()
    for node in active.nodes:
        ids.update(allowed_tools_for_quick(node))
    return frozenset(ids)


def _load_prompt_yaml(prompt_id: str) -> dict[str, Any]:
    cached = _PROMPT_CACHE.get(prompt_id)
    if cached is not None:
        return cached
    path = _PROMPTS_DIR / f"{prompt_id}.yaml"
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"quick_prompt_invalid:{prompt_id}")
    _PROMPT_CACHE[prompt_id] = payload
    return payload


def render_quick_prompt(prompt_id: str, **kwargs: Any) -> tuple[str, str, str]:
    """Return (system, user, schema_id) from the signed YAML catalog."""
    definition = _load_prompt_yaml(prompt_id)
    system = str(definition.get("system_prompt") or "")
    template = str(definition.get("user_prompt_template") or "")
    schema_id = str(
        definition.get("response_schema_id")
        or definition.get("expected_schema_ref")
        or ""
    )
    sanitized = sanitize_kwargs_for_prompt(kwargs)
    user = template.format(**sanitized)
    return system, user, schema_id


def _bounded_json(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)
    redacted = redact_secrets(raw)
    if len(redacted) > _MAX_CONTEXT_CHARS:
        return redacted[:_MAX_CONTEXT_CHARS] + "…"
    return redacted


def _cache_key(prompt_id: str, user: str) -> str:
    blob = f"{prompt_id}\n{user}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _remember_response(key: str, text: str) -> None:
    if len(_RESPONSE_CACHE) >= _CACHE_MAX:
        oldest = next(iter(_RESPONSE_CACHE))
        _RESPONSE_CACHE.pop(oldest, None)
    _RESPONSE_CACHE[key] = text


async def _call_quick_llm(
    *,
    prompt_id: str,
    task: LLMTask,
    phase: str,
    schema_id: str,
    system: str,
    user: str,
    scan_id: str | None,
    tenant_id: str | None,
    engagement_id: str | None,
    cloud_llm_allowed: bool,
    timeout_seconds: float,
) -> str:
    key = _cache_key(prompt_id, user)
    cached = _RESPONSE_CACHE.get(key)
    if cached is not None:
        record_llm_call(model="deterministic", prompt=prompt_id, status="cached", latency_seconds=0.0)
        return cached
    timeout = max(1.0, min(float(timeout_seconds), 60.0))
    started = time.monotonic()
    status = "ok"
    model = "qwythos"
    try:
        text = await asyncio.wait_for(
            call_llm_unified(
                system,
                user,
                task=task,
                scan_id=scan_id,
                phase=phase,
                response_schema_id=schema_id,
                prompt_id=prompt_id,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                execution_mode=ExecutionMode.QUICK,
                content_class=ContentClass.INTERNAL,
                scan_options={"cloud_llm_allowed": bool(cloud_llm_allowed)},
            ),
            timeout=timeout,
        )
    except TimeoutError:
        status = "timeout"
        record_llm_call(
            model=model,
            prompt=prompt_id,
            status=status,
            latency_seconds=time.monotonic() - started,
        )
        emit_quick_audit_event(
            "quick.ai_route",
            scan_id=scan_id or "",
            tenant_id=tenant_id or "",
            payload={"prompt": prompt_id, "status": status, "task": str(task)},
        )
        raise
    except Exception:
        status = "error"
        record_llm_call(
            model=model,
            prompt=prompt_id,
            status=status,
            latency_seconds=time.monotonic() - started,
        )
        raise
    record_llm_call(
        model=model,
        prompt=prompt_id,
        status=status,
        latency_seconds=time.monotonic() - started,
    )
    emit_quick_audit_event(
        "quick.ai_route",
        scan_id=scan_id or "",
        tenant_id=tenant_id or "",
        payload={"prompt": prompt_id, "status": status, "task": str(task)},
    )
    emit_quick_audit_event(
        "quick.prompt_model_version",
        scan_id=scan_id or "",
        tenant_id=tenant_id or "",
        payload={"prompt": prompt_id, "model": model, "phase": phase},
    )
    _remember_response(key, text)
    return text


def _rag_json(pack: RagEvidencePack | None, _profile: QuickRagProfile | None = None) -> str:
    if pack is None:
        return json.dumps({"citations": [], "degraded": True}, ensure_ascii=False)
    return format_quick_rag_for_prompt(pack)


def _rules_fingerprint(observations: Mapping[str, Any], asset_id: str) -> AssetFingerprint:
    def _fact(key: str) -> FingerprintFact | None:
        value = observations.get(key)
        if value is None or value == "":
            return None
        evidence = observations.get("evidence_ids") or observations.get("evidence") or []
        evidence_ids = tuple(str(item) for item in evidence) if isinstance(evidence, list) else ()
        return FingerprintFact(value=str(value)[:512], confidence=0.5, evidence_ids=evidence_ids)

    evidence_raw = observations.get("evidence_ids") or ()
    evidence_ids = tuple(str(item) for item in evidence_raw) if isinstance(evidence_raw, (list, tuple)) else ()
    return AssetFingerprint(
        asset_id=asset_id,
        protocol=_fact("protocol"),
        service=_fact("service"),
        product=_fact("product"),
        version=_fact("version"),
        web_server=_fact("web_server"),
        framework=_fact("framework"),
        cms=_fact("cms"),
        language=_fact("language"),
        runtime=_fact("runtime"),
        evidence_ids=evidence_ids,
    )


def _rules_triage(candidate: Mapping[str, Any]) -> FindingTriage:
    finding_id = str(candidate.get("finding_id") or candidate.get("id") or "unknown")[:36]
    severity_raw = str(candidate.get("severity") or "medium").lower()
    try:
        severity = SeverityFloor(severity_raw)
    except ValueError:
        severity = SeverityFloor.MEDIUM
    evidence = candidate.get("evidence_ids") or candidate.get("citations") or ()
    citations = tuple(str(item) for item in evidence) if isinstance(evidence, (list, tuple)) else ()
    verdict = (
        FindingTriageVerdict.NEEDS_VERIFICATION
        if citations
        else FindingTriageVerdict.HYPOTHESIS
    )
    summary = str(candidate.get("title") or candidate.get("summary") or "unverified candidate")[:4096]
    return FindingTriage(
        finding_id=finding_id or "unknown",
        verdict=verdict,
        severity=severity,
        confidence=0.4 if citations else 0.2,
        fact_summary=summary or "unverified candidate",
        suggested_verification="repeat_high_signal_check",
        estimated_verification_seconds=15,
        citations=citations,
    )


def _needs_verification_critique(triage: FindingTriage | Mapping[str, Any]) -> SecurityCritique:
    if isinstance(triage, FindingTriage):
        triage_id = triage.finding_id
        citations = triage.citations
    else:
        triage_id = str(triage.get("finding_id") or triage.get("triage_id") or "unknown")[:36]
        raw = triage.get("citations") or ()
        citations = tuple(str(item) for item in raw) if isinstance(raw, (list, tuple)) else ()
    return SecurityCritique(
        triage_id=triage_id or "unknown",
        evidence_to_weakness_valid=False,
        alternative_explanations=("wrb_unavailable",),
        false_positive_indicators=(),
        suggested_verification="needs_verification",
        estimated_cost_seconds=15,
        citations=citations,
    )


def _emit_report_observability(
    *,
    scan_id: str,
    tenant_id: str | None,
    profile: str,
    used_ai: bool,
    budget_usage: Mapping[str, Any] | None,
) -> None:
    usage = dict(budget_usage or {})
    elapsed = usage.get("elapsed_seconds") or usage.get("wall_clock_used_seconds")
    if elapsed is not None:
        try:
            record_scan_duration(float(elapsed))
        except (TypeError, ValueError):
            pass
    emit_quick_audit_event(
        "quick.report",
        scan_id=scan_id,
        tenant_id=tenant_id or "",
        payload={"used_ai": used_ai, "profile": profile},
    )


def _template_report(
    *,
    scan_id: str,
    profile: QuickProfileName,
    findings: Sequence[Mapping[str, Any]],
    coverage: Sequence[QuickCoverageRecord] | Sequence[Mapping[str, Any]],
    budget_usage: Mapping[str, Any],
    failures: Sequence[str],
    versions: Mapping[str, str],
    assets: Sequence[str],
) -> QuickReport:
    verified: list[str] = []
    other: list[str] = []
    for item in findings:
        finding_id = str(item.get("finding_id") or item.get("id") or "")
        verdict = str(item.get("verdict") or "").lower()
        if not finding_id:
            continue
        if verdict in {"confirmed", "likely"}:
            verified.append(finding_id)
        else:
            other.append(finding_id)
    summary = [
        f"Quick scan {scan_id} profile={profile.value}.",
        f"Verified findings: {len(verified)}; other: {len(other)}.",
        "Absence of a finding is not proof of safety.",
    ]
    coverage_records: list[QuickCoverageRecord] = []
    for item in coverage:
        if isinstance(item, QuickCoverageRecord):
            coverage_records.append(item)
    return QuickReport(
        scan_id=scan_id,
        profile=profile,
        executive_summary=tuple(summary[:10]),
        verified_finding_ids=tuple(verified),
        other_finding_ids=tuple(other),
        assets_summary=tuple(str(item) for item in assets),
        coverage=tuple(coverage_records),
        skipped_timeouts_failures=tuple(str(item) for item in failures),
        budget_usage=dict(budget_usage),
        versions={str(key): str(value) for key, value in versions.items()},
        recommended_next_mode="production",
        follow_up_actions=("review coverage gaps", "consider standard or deep follow-up"),
    )


async def plan_with_ai(
    request: QuickPlannerRequest,
    *,
    scan_context: Mapping[str, Any] | None = None,
    scope: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
    assets: Sequence[Any] | None = None,
    tool_health: Mapping[str, Any] | None = None,
    rag_pack: RagEvidencePack | None = None,
    rag_profile: QuickRagProfile | None = None,
    previous_plan: QuickScanPlan | None = None,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    timeout_seconds: float = _DEFAULT_AI_TIMEOUT_SECONDS,
    allowed_tool_ids: frozenset[str] | None = None,
    planner: QuickPlanner | None = None,
) -> QuickLlmResult[QuickScanPlan]:
    """Deterministic plan, optionally reranked by Qwythos. Never emits CLI."""
    engine = planner or QuickPlanner()
    baseline = engine.plan(request)
    catalog = allowed_tool_ids if allowed_tool_ids is not None else catalog_tool_ids()
    enable_ai = request.config.enable_ai
    if not enable_ai:
        return QuickLlmResult(
            value=baseline,
            used_ai=False,
            model_route="deterministic",
            prompt_version="deterministic-v1",
            fallback_reason="enable_ai_false",
        )
    system, user, schema_id = render_quick_prompt(
        PROMPT_PLANNER,
        scan_context_json=_bounded_json(scan_context or {"scan_id": request.scan_id}),
        scope_json=_bounded_json(scope or {}),
        policy_json=_bounded_json(policy or {}),
        budget_json=_bounded_json(request.budget.model_dump(mode="json")),
        asset_summary_json=_bounded_json(list(assets or ())),
        fingerprints_json=_bounded_json(
            [item.model_dump(mode="json") for item in request.fingerprints]
        ),
        allowed_capabilities_json=_bounded_json(sorted(catalog)),
        tool_health_json=_bounded_json(tool_health or {}),
        rag_context_with_citations_json=_rag_json(rag_pack, rag_profile),
        previous_plan_or_null=_bounded_json(
            previous_plan.model_dump(mode="json") if previous_plan is not None else None
        ),
    )
    try:
        text = await _call_quick_llm(
            prompt_id=PROMPT_PLANNER,
            task=LLMTask.QUICK_PLANNER,
            phase="quick_planner",
            schema_id=schema_id or QUICK_SCAN_PLAN_SCHEMA_ID,
            system=system,
            user=user,
            scan_id=request.scan_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            cloud_llm_allowed=request.config.cloud_llm_allowed,
            timeout_seconds=timeout_seconds,
        )
        llm_plan = parse_llm_plan(text, catalog_tool_ids=catalog)
        merged = apply_llm_tasks_to_plan(baseline, llm_plan, catalog_tool_ids=catalog)
        return QuickLlmResult(
            value=merged,
            used_ai=True,
            model_route="qwythos-primary",
            prompt_version=PROMPT_PLANNER,
        )
    except TimeoutError:
        logger.warning(
            "quick_planner_timeout_deterministic",
            extra={"event": "quick_planner_timeout_deterministic", "scan_id": request.scan_id},
        )
        return QuickLlmResult(
            value=baseline,
            used_ai=False,
            model_route="deterministic",
            prompt_version="deterministic-v1",
            fallback_reason="ai_timeout",
            degraded=("ai_timeout",),
        )
    except (LlmSchemaError, RuntimeError, OSError, ValueError, TypeError) as exc:
        logger.warning(
            "quick_planner_fallback_deterministic",
            extra={
                "event": "quick_planner_fallback_deterministic",
                "scan_id": request.scan_id,
                "reason": type(exc).__name__,
            },
        )
        reason = "schema_invalid" if isinstance(exc, LlmSchemaError) else "qwythos_unavailable"
        return QuickLlmResult(
            value=baseline,
            used_ai=False,
            model_route="deterministic",
            prompt_version="deterministic-v1",
            fallback_reason=reason,
            degraded=(reason,),
        )


async def classify_fingerprint(
    observations: Mapping[str, Any],
    *,
    asset_id: str,
    rag_pack: RagEvidencePack | None = None,
    enable_ai: bool = True,
    cloud_llm_allowed: bool = False,
    scan_id: str | None = None,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    timeout_seconds: float = _DEFAULT_AI_TIMEOUT_SECONDS,
) -> QuickLlmResult[AssetFingerprint]:
    """Small-model fingerprint. Rules fallback when the model is down."""
    rules = _rules_fingerprint(observations, asset_id)
    if not enable_ai:
        return QuickLlmResult(
            value=rules,
            used_ai=False,
            model_route="rules",
            prompt_version="rules-v1",
            fallback_reason="enable_ai_false",
        )
    system, user, schema_id = render_quick_prompt(
        PROMPT_FINGERPRINT,
        normalized_observations_json=_bounded_json(observations),
        rag_context_json=_rag_json(rag_pack, None),
    )
    try:
        text = await _call_quick_llm(
            prompt_id=PROMPT_FINGERPRINT,
            task=LLMTask.QUICK_FINGERPRINT,
            phase="quick_fingerprint",
            schema_id=schema_id or ASSET_FINGERPRINT_SCHEMA_ID,
            system=system,
            user=user,
            scan_id=scan_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            cloud_llm_allowed=cloud_llm_allowed,
            timeout_seconds=timeout_seconds,
        )
        parsed = parse_llm_fingerprint(text)
        return QuickLlmResult(
            value=parsed,
            used_ai=True,
            model_route="small-model",
            prompt_version=PROMPT_FINGERPRINT,
        )
    except (TimeoutError, LlmSchemaError, RuntimeError, OSError, ValueError, TypeError):
        return QuickLlmResult(
            value=rules,
            used_ai=False,
            model_route="rules",
            prompt_version="rules-v1",
            fallback_reason="small_model_unavailable",
            degraded=("small_model_unavailable",),
        )


async def classify_fingerprints_batch(
    items: Sequence[Mapping[str, Any]],
    *,
    enable_ai: bool = True,
    cloud_llm_allowed: bool = False,
    scan_id: str | None = None,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    timeout_seconds: float = _DEFAULT_AI_TIMEOUT_SECONDS,
) -> tuple[QuickLlmResult[AssetFingerprint], ...]:
    """Bounded batch fingerprint classification (AI budget)."""
    results: list[QuickLlmResult[AssetFingerprint]] = []
    for item in items[:16]:
        asset_id = str(item.get("asset_id") or "unknown")[:36]
        results.append(
            await classify_fingerprint(
                item,
                asset_id=asset_id,
                enable_ai=enable_ai,
                cloud_llm_allowed=cloud_llm_allowed,
                scan_id=scan_id,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                timeout_seconds=timeout_seconds,
            )
        )
    return tuple(results)


async def triage_finding(
    candidate: Mapping[str, Any],
    *,
    asset_context: Mapping[str, Any] | None = None,
    evidence: Sequence[Any] | None = None,
    correlated: Sequence[Any] | None = None,
    policy: Mapping[str, Any] | None = None,
    remaining_budget: Mapping[str, Any] | None = None,
    rag_pack: RagEvidencePack | None = None,
    enable_ai: bool = True,
    cloud_llm_allowed: bool = False,
    scan_id: str | None = None,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    timeout_seconds: float = _DEFAULT_AI_TIMEOUT_SECONDS,
) -> QuickLlmResult[FindingTriage]:
    """Small-model triage. Rules fallback; citations required for non-hypothesis."""
    rules = _rules_triage(candidate)
    if not enable_ai:
        return QuickLlmResult(
            value=rules,
            used_ai=False,
            model_route="rules",
            prompt_version="rules-v1",
            fallback_reason="enable_ai_false",
        )
    system, user, schema_id = render_quick_prompt(
        PROMPT_TRIAGE,
        candidate_json=_bounded_json(candidate),
        asset_context_json=_bounded_json(asset_context or {}),
        evidence_json=_bounded_json(list(evidence or ())),
        correlated_results_json=_bounded_json(list(correlated or ())),
        policy_json=_bounded_json(policy or {}),
        budget_json=_bounded_json(remaining_budget or {}),
        rag_context_with_citations_json=_rag_json(rag_pack, None),
    )
    try:
        text = await _call_quick_llm(
            prompt_id=PROMPT_TRIAGE,
            task=LLMTask.QUICK_TRIAGE,
            phase="quick_triage",
            schema_id=schema_id or FINDING_TRIAGE_SCHEMA_ID,
            system=system,
            user=user,
            scan_id=scan_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            cloud_llm_allowed=cloud_llm_allowed,
            timeout_seconds=timeout_seconds,
        )
        parsed = parse_llm_triage(text)
        return QuickLlmResult(
            value=parsed,
            used_ai=True,
            model_route="small-model",
            prompt_version=PROMPT_TRIAGE,
        )
    except (TimeoutError, LlmSchemaError, RuntimeError, OSError, ValueError, TypeError):
        return QuickLlmResult(
            value=rules,
            used_ai=False,
            model_route="rules",
            prompt_version="rules-v1",
            fallback_reason="small_model_unavailable",
            degraded=("small_model_unavailable",),
        )


async def critique_finding(
    triage: FindingTriage | Mapping[str, Any],
    *,
    evidence: Sequence[Any] | None = None,
    asset: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
    budget: Mapping[str, Any] | None = None,
    rag_pack: RagEvidencePack | None = None,
    enable_ai: bool = True,
    cloud_llm_allowed: bool = False,
    scan_id: str | None = None,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    timeout_seconds: float = _DEFAULT_AI_TIMEOUT_SECONDS,
) -> QuickLlmResult[SecurityCritique]:
    """WRB critic for disputed high/critical. WRB down → needs_verification."""
    fallback = _needs_verification_critique(triage)
    if not enable_ai:
        return QuickLlmResult(
            value=fallback,
            used_ai=False,
            model_route="needs_verification",
            prompt_version="rules-v1",
            fallback_reason="enable_ai_false",
        )
    triage_payload = triage.model_dump(mode="json") if isinstance(triage, FindingTriage) else dict(triage)
    system, user, schema_id = render_quick_prompt(
        PROMPT_CRITIC,
        triage_json=_bounded_json(triage_payload),
        evidence_json=_bounded_json(list(evidence or ())),
        asset_json=_bounded_json(asset or {}),
        policy_json=_bounded_json(policy or {}),
        budget_json=_bounded_json(budget or {}),
        rag_context_json=_rag_json(rag_pack, None),
    )
    try:
        text = await _call_quick_llm(
            prompt_id=PROMPT_CRITIC,
            task=LLMTask.QUICK_CRITIC,
            phase="quick_critic",
            schema_id=schema_id or SECURITY_CRITIQUE_SCHEMA_ID,
            system=system,
            user=user,
            scan_id=scan_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            cloud_llm_allowed=cloud_llm_allowed,
            timeout_seconds=timeout_seconds,
        )
        parsed = parse_llm_critique(text)
        return QuickLlmResult(
            value=parsed,
            used_ai=True,
            model_route="wrb-primary",
            prompt_version=PROMPT_CRITIC,
        )
    except (TimeoutError, LlmSchemaError, RuntimeError, OSError, ValueError, TypeError):
        return QuickLlmResult(
            value=fallback,
            used_ai=False,
            model_route="needs_verification",
            prompt_version="rules-v1",
            fallback_reason="wrb_unavailable",
            degraded=("wrb_unavailable",),
        )


async def generate_report(
    *,
    scan_id: str,
    config: QuickScanConfig,
    assets: Sequence[Any] | None = None,
    findings: Sequence[Mapping[str, Any]] | None = None,
    coverage: Sequence[QuickCoverageRecord] | Sequence[Mapping[str, Any]] | None = None,
    budget_usage: Mapping[str, Any] | None = None,
    failures: Sequence[str] | None = None,
    versions: Mapping[str, str] | None = None,
    scan_meta: Mapping[str, Any] | None = None,
    enable_ai: bool | None = None,
    scan_tenant_id: str | None = None,
    engagement_id: str | None = None,
    timeout_seconds: float = _DEFAULT_AI_TIMEOUT_SECONDS,
) -> QuickLlmResult[QuickReport]:
    """Qwythos report. Timeout/failure → local template renderer (never blocks)."""
    use_ai = config.enable_ai if enable_ai is None else enable_ai
    template = _template_report(
        scan_id=scan_id,
        profile=config.profile,
        findings=findings or (),
        coverage=coverage or (),
        budget_usage=budget_usage or {},
        failures=failures or (),
        versions=versions or {},
        assets=[str(item) for item in (assets or ())],
    )
    if not use_ai:
        record_findings_from_rows(list(findings or ()))
        _emit_report_observability(
            scan_id=scan_id,
            tenant_id=scan_tenant_id,
            profile=config.profile.value,
            used_ai=False,
            budget_usage=budget_usage,
        )
        return QuickLlmResult(
            value=template,
            used_ai=False,
            model_route="template_renderer",
            prompt_version="template-v1",
            fallback_reason="enable_ai_false",
        )
    system, user, schema_id = render_quick_prompt(
        PROMPT_REPORTER,
        scan_json=_bounded_json(scan_meta or {"scan_id": scan_id, "profile": config.profile.value}),
        assets_json=_bounded_json(list(assets or ())),
        findings_json=_bounded_json(list(findings or ())),
        coverage_json=_bounded_json(
            [
                item.model_dump(mode="json") if isinstance(item, QuickCoverageRecord) else item
                for item in (coverage or ())
            ]
        ),
        budget_usage_json=_bounded_json(budget_usage or {}),
        failures_json=_bounded_json(list(failures or ())),
        versions_json=_bounded_json(versions or {}),
    )
    try:
        text = await _call_quick_llm(
            prompt_id=PROMPT_REPORTER,
            task=LLMTask.QUICK_REPORTER,
            phase="quick_reporter",
            schema_id=schema_id or QUICK_REPORT_SCHEMA_ID,
            system=system,
            user=user,
            scan_id=scan_id,
            tenant_id=scan_tenant_id,
            engagement_id=engagement_id,
            cloud_llm_allowed=config.cloud_llm_allowed,
            timeout_seconds=timeout_seconds,
        )
        parsed = parse_llm_report(text)
        record_findings_from_rows(list(findings or ()))
        _emit_report_observability(
            scan_id=scan_id,
            tenant_id=scan_tenant_id,
            profile=config.profile.value,
            used_ai=True,
            budget_usage=budget_usage,
        )
        return QuickLlmResult(
            value=parsed,
            used_ai=True,
            model_route="qwythos-primary",
            prompt_version=PROMPT_REPORTER,
        )
    except (TimeoutError, LlmSchemaError, RuntimeError, OSError, ValueError, TypeError):
        logger.warning(
            "quick_reporter_template_fallback",
            extra={"event": "quick_reporter_template_fallback", "scan_id": scan_id},
        )
        record_findings_from_rows(list(findings or ()))
        _emit_report_observability(
            scan_id=scan_id,
            tenant_id=scan_tenant_id,
            profile=config.profile.value,
            used_ai=False,
            budget_usage=budget_usage,
        )
        return QuickLlmResult(
            value=template,
            used_ai=False,
            model_route="template_renderer",
            prompt_version="template-v1",
            fallback_reason="qwythos_unavailable",
            degraded=("qwythos_unavailable",),
        )
