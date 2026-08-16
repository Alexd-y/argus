"""Pydantic validators for Quick-mode LLM JSON output (QUICK-006).

Domain objects in ``src.quick.schemas`` are frozen and extra-forbid. LLM
payloads are parsed here first: schema failure discards the AI output and
callers fall back to the deterministic path. Shell/CLI fields are rejected.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    ValidationError,
)

from src.core.unified_ai_metrics import record_llm_schema_failure
from src.quick.disallowed import is_disallowed_tool
from src.quick.schemas import (
    AssetFingerprint,
    FindingTriage,
    FindingTriageVerdict,
    FingerprintFact,
    QuickCoverageRecord,
    QuickCoverageState,
    QuickProfileName,
    QuickReport,
    QuickScanPlan,
    QuickTask,
    QuickTaskStage,
    QuickTaskStatus,
    SecurityCritique,
    SeverityFloor,
)

QUICK_SCAN_PLAN_SCHEMA_ID: Final[str] = "quick_scan_plan_v1"
ASSET_FINGERPRINT_SCHEMA_ID: Final[str] = "asset_fingerprint_v1"
FINDING_TRIAGE_SCHEMA_ID: Final[str] = "finding_triage_v1"
SECURITY_CRITIQUE_SCHEMA_ID: Final[str] = "security_critique_v1"
QUICK_REPORT_SCHEMA_ID: Final[str] = "quick_report_v1"

SCHEMA_ID_BY_MODEL: Final[dict[str, str]] = {
    "LlmQuickScanPlan": QUICK_SCAN_PLAN_SCHEMA_ID,
    "LlmAssetFingerprint": ASSET_FINGERPRINT_SCHEMA_ID,
    "LlmFindingTriage": FINDING_TRIAGE_SCHEMA_ID,
    "LlmSecurityCritique": SECURITY_CRITIQUE_SCHEMA_ID,
    "LlmQuickReport": QUICK_REPORT_SCHEMA_ID,
}

_JSON_FENCE_RE: Final[re.Pattern[str]] = re.compile(
    r"```(?:json)?\s*([\s\S]*?)\s*```",
    re.IGNORECASE,
)
_SHELL_RE: Final[re.Pattern[str]] = re.compile(
    r"(?is)(\b(bash|zsh|powershell|pwsh|cmd\.exe|docker\s+exec|kubectl\s+exec)\b"
    r"|[;&|`$]|rm\s+-rf|\bcurl\s+|\bwget\s+|\bnc\s+-|/bin/sh\b|/bin/bash\b)",
)
_PATH_OR_FLAG_RE: Final[re.Pattern[str]] = re.compile(r"[\\/]|^\s*-{1,2}[a-z]")
_CITATION_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"(finding|evidence|citation|cite)[_:-]?\s*[a-z0-9-]{4,}",
    re.IGNORECASE,
)


class LlmSchemaError(ValueError):
    """Raised when LLM JSON cannot be validated or contains disallowed fields."""

    def __init__(self, reason: str, *, schema_id: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.schema_id = schema_id


class _LlmLoose(BaseModel):
    """LLM payloads may omit optional domain fields; unknown keys are dropped."""

    model_config = ConfigDict(extra="ignore")


class LlmQuickTask(_LlmLoose):
    task_id: StrictStr | None = Field(default=None, max_length=36)
    stage: StrictStr = Field(min_length=1, max_length=32)
    target_ref: StrictStr = Field(min_length=1, max_length=256)
    tool_id: StrictStr = Field(min_length=1, max_length=128)
    capability_id: StrictStr = Field(min_length=1, max_length=256)
    estimated_seconds: StrictInt = Field(default=10, ge=0, le=86_400)
    estimated_requests: StrictInt = Field(default=1, ge=0)
    priority_score: StrictFloat = Field(default=0.5, ge=0.0, le=1.0)
    depends_on: list[StrictStr] = Field(default_factory=list)
    success_signal: list[StrictStr] = Field(default_factory=list)
    stop_conditions: list[StrictStr] = Field(default_factory=list)


class LlmCoverageIntent(_LlmLoose):
    asset_id: StrictStr = Field(min_length=1, max_length=36)
    capability_id: StrictStr = Field(min_length=1, max_length=256)
    state: StrictStr = Field(default="not_scheduled", min_length=1, max_length=64)
    reason_code: StrictStr = Field(default="not_scheduled_by_quick_profile", max_length=128)
    tools: list[StrictStr] = Field(default_factory=list)
    template_ids: list[StrictStr] = Field(default_factory=list)
    evidence_ids: list[StrictStr] = Field(default_factory=list)


class LlmQuickScanPlan(_LlmLoose):
    tasks: list[LlmQuickTask] = Field(default_factory=list)
    assumptions: list[StrictStr] = Field(default_factory=list)
    fallbacks: list[StrictStr] = Field(default_factory=list)
    coverage_intent: list[LlmCoverageIntent] = Field(default_factory=list)
    prompt_version: StrictStr | None = Field(default=None, max_length=128)
    model_route: StrictStr | None = Field(default=None, max_length=128)


class LlmFingerprintFact(_LlmLoose):
    value: StrictStr | None = Field(default=None, max_length=512)
    confidence: StrictFloat = Field(default=0.0, ge=0.0, le=1.0)
    evidence_ids: list[StrictStr] = Field(default_factory=list)


class LlmAssetFingerprint(_LlmLoose):
    asset_id: StrictStr = Field(min_length=1, max_length=36)
    protocol: LlmFingerprintFact | None = None
    service: LlmFingerprintFact | None = None
    product: LlmFingerprintFact | None = None
    version: LlmFingerprintFact | None = None
    web_server: LlmFingerprintFact | None = None
    framework: LlmFingerprintFact | None = None
    cms: LlmFingerprintFact | None = None
    language: LlmFingerprintFact | None = None
    runtime: LlmFingerprintFact | None = None
    waf_cdn_hints: LlmFingerprintFact | None = None
    authentication_surface: LlmFingerprintFact | None = None
    api_hints: LlmFingerprintFact | None = None
    cloud_storage_admin_debug: LlmFingerprintFact | None = None
    tls_security_header_posture: LlmFingerprintFact | None = None
    network_os_hints: LlmFingerprintFact | None = None
    evidence_ids: list[StrictStr] = Field(default_factory=list)


class LlmFindingTriage(_LlmLoose):
    finding_id: StrictStr = Field(min_length=1, max_length=36)
    verdict: StrictStr = Field(min_length=1, max_length=64)
    severity: StrictStr = Field(min_length=1, max_length=32)
    confidence: StrictFloat = Field(ge=0.0, le=1.0)
    cwe_ids: list[StrictStr] = Field(default_factory=list)
    cve_ids: list[StrictStr] = Field(default_factory=list)
    owasp: StrictStr | None = Field(default=None, max_length=64)
    fact_summary: StrictStr = Field(min_length=1, max_length=4096)
    hypothesis_summary: StrictStr | None = Field(default=None, max_length=4096)
    suggested_verification: StrictStr | None = Field(default=None, max_length=512)
    estimated_verification_seconds: StrictInt | None = Field(default=None, ge=0, le=86_400)
    citations: list[StrictStr] = Field(default_factory=list)


class LlmSecurityCritique(_LlmLoose):
    triage_id: StrictStr = Field(min_length=1, max_length=36)
    evidence_to_weakness_valid: StrictBool
    alternative_explanations: list[StrictStr] = Field(default_factory=list)
    false_positive_indicators: list[StrictStr] = Field(default_factory=list)
    suggested_verification: StrictStr | None = Field(default=None, max_length=512)
    estimated_cost_seconds: StrictInt | None = Field(default=None, ge=0, le=86_400)
    citations: list[StrictStr] = Field(default_factory=list)


class LlmQuickReport(_LlmLoose):
    scan_id: StrictStr = Field(min_length=1, max_length=36)
    profile: StrictStr = Field(min_length=1, max_length=32)
    executive_summary: list[StrictStr] = Field(min_length=1, max_length=10)
    verified_finding_ids: list[StrictStr] = Field(default_factory=list)
    other_finding_ids: list[StrictStr] = Field(default_factory=list)
    assets_summary: list[StrictStr] = Field(default_factory=list)
    coverage: list[LlmCoverageIntent] = Field(default_factory=list)
    skipped_timeouts_failures: list[StrictStr] = Field(default_factory=list)
    budget_usage: dict[str, Any] = Field(default_factory=dict)
    versions: dict[str, StrictStr] = Field(default_factory=dict)
    recommended_next_mode: StrictStr = Field(default="production", max_length=32)
    follow_up_actions: list[StrictStr] = Field(default_factory=list)
    incompleteness_warning: StrictStr | None = Field(default=None, max_length=1024)


def extract_json_object(text: str) -> dict[str, Any]:
    """Parse a JSON object from model text. Markdown fences are stripped."""
    raw = (text or "").strip()
    if not raw:
        raise LlmSchemaError("empty_llm_output")
    fenced = _JSON_FENCE_RE.search(raw)
    if fenced:
        raw = fenced.group(1).strip()
    start = raw.find("{")
    end = raw.rfind("}")
    if start < 0 or end <= start:
        raise LlmSchemaError("llm_output_not_json_object")
    try:
        parsed = json.loads(raw[start : end + 1])
    except json.JSONDecodeError as exc:
        raise LlmSchemaError("llm_output_json_decode") from exc
    if not isinstance(parsed, dict):
        raise LlmSchemaError("llm_output_not_object")
    return parsed


def contains_shell_command(payload: object) -> bool:
    """True when the payload looks like a shell/CLI string rather than a tool id."""
    if isinstance(payload, str):
        if _SHELL_RE.search(payload):
            return True
        return bool(_PATH_OR_FLAG_RE.search(payload) and (" " in payload or len(payload) > 64))
    if isinstance(payload, Mapping):
        banned_keys = {"command", "argv", "shell", "cmdline", "cli", "payload", "script"}
        for key, value in payload.items():
            if str(key).lower() in banned_keys:
                return True
            if contains_shell_command(value):
                return True
        return False
    if isinstance(payload, Sequence) and not isinstance(payload, (str, bytes)):
        return any(contains_shell_command(item) for item in payload)
    return False


def tool_id_is_catalog_safe(tool_id: str, catalog: frozenset[str]) -> bool:
    """Reject unknown, disallowed, or shell-like tool identifiers."""
    normalized = str(tool_id or "").strip().lower()
    if not normalized:
        return False
    if " " in normalized or "/" in normalized or "\\" in normalized:
        return False
    if contains_shell_command(normalized):
        return False
    if is_disallowed_tool(normalized):
        return False
    allowed = {item.strip().lower() for item in catalog}
    return normalized in allowed


def _record_failure(schema_id: str, task: str) -> None:
    record_llm_schema_failure(
        alias="quick",
        provider="quick_llm",
        model="schema",
        task=task,
        mode="quick",
    )


def _to_fact(raw: LlmFingerprintFact | None) -> FingerprintFact | None:
    if raw is None:
        return None
    return FingerprintFact(
        value=raw.value,
        confidence=raw.confidence,
        evidence_ids=tuple(raw.evidence_ids),
    )


def parse_llm_plan(text: str, *, catalog_tool_ids: frozenset[str]) -> LlmQuickScanPlan:
    """Validate planner JSON. Unknown tool_id or shell content → schema failure."""
    try:
        payload = extract_json_object(text)
    except LlmSchemaError:
        _record_failure(QUICK_SCAN_PLAN_SCHEMA_ID, "quick_planner")
        raise
    if contains_shell_command(payload):
        _record_failure(QUICK_SCAN_PLAN_SCHEMA_ID, "quick_planner")
        raise LlmSchemaError("planner_shell_command_rejected", schema_id=QUICK_SCAN_PLAN_SCHEMA_ID)
    try:
        plan = LlmQuickScanPlan.model_validate(payload)
    except ValidationError as exc:
        _record_failure(QUICK_SCAN_PLAN_SCHEMA_ID, "quick_planner")
        raise LlmSchemaError("planner_schema_invalid", schema_id=QUICK_SCAN_PLAN_SCHEMA_ID) from exc
    for task in plan.tasks:
        if not tool_id_is_catalog_safe(task.tool_id, catalog_tool_ids):
            _record_failure(QUICK_SCAN_PLAN_SCHEMA_ID, "quick_planner")
            raise LlmSchemaError(
                f"planner_unknown_tool_id:{task.tool_id}",
                schema_id=QUICK_SCAN_PLAN_SCHEMA_ID,
            )
    return plan


def parse_llm_fingerprint(text: str) -> AssetFingerprint:
    try:
        payload = extract_json_object(text)
        parsed = LlmAssetFingerprint.model_validate(payload)
    except (LlmSchemaError, ValidationError) as exc:
        _record_failure(ASSET_FINGERPRINT_SCHEMA_ID, "quick_fingerprint")
        raise LlmSchemaError(
            "fingerprint_schema_invalid",
            schema_id=ASSET_FINGERPRINT_SCHEMA_ID,
        ) from exc
    return AssetFingerprint(
        asset_id=parsed.asset_id,
        protocol=_to_fact(parsed.protocol),
        service=_to_fact(parsed.service),
        product=_to_fact(parsed.product),
        version=_to_fact(parsed.version),
        web_server=_to_fact(parsed.web_server),
        framework=_to_fact(parsed.framework),
        cms=_to_fact(parsed.cms),
        language=_to_fact(parsed.language),
        runtime=_to_fact(parsed.runtime),
        waf_cdn_hints=_to_fact(parsed.waf_cdn_hints),
        authentication_surface=_to_fact(parsed.authentication_surface),
        api_hints=_to_fact(parsed.api_hints),
        cloud_storage_admin_debug=_to_fact(parsed.cloud_storage_admin_debug),
        tls_security_header_posture=_to_fact(parsed.tls_security_header_posture),
        network_os_hints=_to_fact(parsed.network_os_hints),
        evidence_ids=tuple(parsed.evidence_ids),
    )


def _coerce_hypothesis(triage: FindingTriage) -> FindingTriage:
    """Non-hypothesis claims without citations become hypothesis."""
    if triage.verdict is FindingTriageVerdict.HYPOTHESIS:
        return triage
    if triage.citations:
        return triage
    return FindingTriage(
        finding_id=triage.finding_id,
        verdict=FindingTriageVerdict.HYPOTHESIS,
        severity=triage.severity,
        confidence=min(triage.confidence, 0.4),
        cwe_ids=triage.cwe_ids,
        cve_ids=triage.cve_ids,
        owasp=triage.owasp,
        fact_summary=triage.fact_summary,
        hypothesis_summary=triage.hypothesis_summary or triage.fact_summary,
        suggested_verification=triage.suggested_verification,
        estimated_verification_seconds=triage.estimated_verification_seconds,
        citations=triage.citations,
    )


def parse_llm_triage(text: str) -> FindingTriage:
    try:
        payload = extract_json_object(text)
        parsed = LlmFindingTriage.model_validate(payload)
        verdict = FindingTriageVerdict(parsed.verdict)
        severity = SeverityFloor(parsed.severity)
    except (LlmSchemaError, ValidationError, ValueError) as exc:
        _record_failure(FINDING_TRIAGE_SCHEMA_ID, "quick_triage")
        raise LlmSchemaError(
            "triage_schema_invalid",
            schema_id=FINDING_TRIAGE_SCHEMA_ID,
        ) from exc
    triage = FindingTriage(
        finding_id=parsed.finding_id,
        verdict=verdict,
        severity=severity,
        confidence=parsed.confidence,
        cwe_ids=tuple(parsed.cwe_ids),
        cve_ids=tuple(parsed.cve_ids),
        owasp=parsed.owasp,
        fact_summary=parsed.fact_summary,
        hypothesis_summary=parsed.hypothesis_summary,
        suggested_verification=parsed.suggested_verification,
        estimated_verification_seconds=parsed.estimated_verification_seconds,
        citations=tuple(parsed.citations),
    )
    return _coerce_hypothesis(triage)


def parse_llm_critique(text: str) -> SecurityCritique:
    try:
        payload = extract_json_object(text)
        parsed = LlmSecurityCritique.model_validate(payload)
    except (LlmSchemaError, ValidationError) as exc:
        _record_failure(SECURITY_CRITIQUE_SCHEMA_ID, "quick_critic")
        raise LlmSchemaError(
            "critique_schema_invalid",
            schema_id=SECURITY_CRITIQUE_SCHEMA_ID,
        ) from exc
    critique = SecurityCritique(
        triage_id=parsed.triage_id,
        evidence_to_weakness_valid=parsed.evidence_to_weakness_valid,
        alternative_explanations=tuple(parsed.alternative_explanations),
        false_positive_indicators=tuple(parsed.false_positive_indicators),
        suggested_verification=parsed.suggested_verification,
        estimated_cost_seconds=parsed.estimated_cost_seconds,
        citations=tuple(parsed.citations),
    )
    if critique.evidence_to_weakness_valid and not critique.citations:
        return SecurityCritique(
            triage_id=critique.triage_id,
            evidence_to_weakness_valid=False,
            alternative_explanations=critique.alternative_explanations,
            false_positive_indicators=critique.false_positive_indicators
            + ("missing_citations",),
            suggested_verification=critique.suggested_verification,
            estimated_cost_seconds=critique.estimated_cost_seconds,
            citations=critique.citations,
        )
    return critique


def _coverage_from_llm(items: Sequence[LlmCoverageIntent]) -> tuple[QuickCoverageRecord, ...]:
    records: list[QuickCoverageRecord] = []
    for item in items:
        try:
            state = QuickCoverageState(item.state)
        except ValueError:
            state = QuickCoverageState.NOT_SCHEDULED
        records.append(
            QuickCoverageRecord(
                asset_id=item.asset_id,
                capability_id=item.capability_id,
                state=state,
                reason_code=item.reason_code,
                tools=tuple(item.tools),
                template_ids=tuple(item.template_ids),
                evidence_ids=tuple(item.evidence_ids),
            )
        )
    return tuple(records)


def parse_llm_report(text: str) -> QuickReport:
    try:
        payload = extract_json_object(text)
        parsed = LlmQuickReport.model_validate(payload)
        profile = QuickProfileName(parsed.profile)
    except (LlmSchemaError, ValidationError, ValueError) as exc:
        _record_failure(QUICK_REPORT_SCHEMA_ID, "quick_reporter")
        raise LlmSchemaError(
            "report_schema_invalid",
            schema_id=QUICK_REPORT_SCHEMA_ID,
        ) from exc
    allowed_modes = {"production", "lab_unrestricted", "standard", "deep"}
    next_mode = parsed.recommended_next_mode if parsed.recommended_next_mode in allowed_modes else "production"
    warning = parsed.incompleteness_warning or (
        "This quick scan does not prove the absence of vulnerabilities. "
        "Uncovered capabilities are gaps, not a clean bill of health."
    )
    cited_summaries = tuple(
        item
        for item in parsed.executive_summary
        if _CITATION_TOKEN_RE.search(item)
        or item in parsed.verified_finding_ids
        or item in parsed.other_finding_ids
    )
    if not cited_summaries:
        cited_summaries = tuple(parsed.executive_summary[:10])
    return QuickReport(
        scan_id=parsed.scan_id,
        profile=profile,
        executive_summary=cited_summaries[:10],
        verified_finding_ids=tuple(parsed.verified_finding_ids),
        other_finding_ids=tuple(parsed.other_finding_ids),
        assets_summary=tuple(parsed.assets_summary),
        coverage=_coverage_from_llm(parsed.coverage),
        skipped_timeouts_failures=tuple(parsed.skipped_timeouts_failures),
        budget_usage=dict(parsed.budget_usage),
        versions=dict(parsed.versions),
        recommended_next_mode=next_mode,  # type: ignore[arg-type]
        follow_up_actions=tuple(parsed.follow_up_actions),
        incompleteness_warning=warning,
    )


def apply_llm_tasks_to_plan(
    baseline: QuickScanPlan,
    llm_plan: LlmQuickScanPlan,
    *,
    catalog_tool_ids: frozenset[str],
) -> QuickScanPlan:
    """Rerank baseline tasks from validated LLM output. Never invents tool ids."""
    by_key = {
        (task.tool_id.lower(), task.target_ref, task.capability_id): task
        for task in baseline.tasks
    }
    reranked: list[QuickTask] = []
    seen: set[tuple[str, str, str]] = set()
    for item in llm_plan.tasks:
        if not tool_id_is_catalog_safe(item.tool_id, catalog_tool_ids):
            raise LlmSchemaError(
                f"planner_unknown_tool_id:{item.tool_id}",
                schema_id=QUICK_SCAN_PLAN_SCHEMA_ID,
            )
        key = (item.tool_id.lower(), item.target_ref, item.capability_id)
        existing = by_key.get(key)
        if existing is None:
            continue
        try:
            stage = QuickTaskStage(item.stage)
        except ValueError:
            stage = existing.stage
        reranked.append(
            QuickTask(
                task_id=existing.task_id,
                stage=stage,
                target_ref=existing.target_ref,
                tool_id=existing.tool_id,
                capability_id=existing.capability_id,
                estimated_seconds=item.estimated_seconds,
                estimated_requests=item.estimated_requests,
                priority_score=item.priority_score,
                depends_on=tuple(item.depends_on) or existing.depends_on,
                success_signal=tuple(item.success_signal) or existing.success_signal,
                stop_conditions=tuple(item.stop_conditions) or existing.stop_conditions,
                policy_decision_id=existing.policy_decision_id,
                budget_lease_id=existing.budget_lease_id,
                idempotency_key=existing.idempotency_key,
                status=QuickTaskStatus.QUEUED,
            )
        )
        seen.add(key)
    if not reranked:
        raise LlmSchemaError("planner_no_catalog_overlap", schema_id=QUICK_SCAN_PLAN_SCHEMA_ID)
    leftovers = [task for task in baseline.tasks if (task.tool_id.lower(), task.target_ref, task.capability_id) not in seen]
    merged = tuple(reranked + leftovers)
    assumptions = tuple(llm_plan.assumptions) if llm_plan.assumptions else baseline.assumptions
    fallbacks = tuple(llm_plan.fallbacks) if llm_plan.fallbacks else baseline.fallbacks
    return QuickScanPlan(
        scan_id=baseline.scan_id,
        profile=baseline.profile,
        deadline_at=baseline.deadline_at,
        budget=baseline.budget,
        assumptions=assumptions,
        stages=baseline.stages,
        tasks=merged,
        fallbacks=fallbacks,
        coverage_intent=baseline.coverage_intent,
        plan_version=baseline.plan_version,
        prompt_version=llm_plan.prompt_version or "quick_planner_v1",
        model_route=llm_plan.model_route or "qwythos-primary",
    )
