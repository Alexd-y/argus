"""ScanStateMachine — transitions between phases, DB recording."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import String, cast, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas import DEFAULT_GENERATE_ALL_FORMATS, ReportSummary
from src.core.config import settings
from src.core.observability import (
    record_phase_duration,
    record_tool_run,
    trace_phase,
)
from src.db.models import (
    Finding,
    PhaseInput,
    PhaseOutput,
    Policy,
    Report,
    Scan,
    ScanEvent,
    ScanStep,
    ScanTimeline,
)
from src.findings.cvss_auto_score import CVSSAutoScorer
from src.mcp.services.notifications import (
    DiscordNotifier,
    GitHubIssuesNotifier,
    NotificationDispatcher,
    NotificationEvent,
    NotificationSeverity,
)
from src.orchestration.aggressive_exploit_tools import (
    maybe_run_aggressive_exploit_tools,
)
from src.orchestration.auth_config import TargetConfig
from src.orchestration.binary_analysis import (
    BinaryAnalysisRequest,
    detect_binary_type,
    run_binary_analysis,
)
from src.orchestration.cost_aware_reasoning import (
    BudgetEnforcer,
    CostTracker,
    register_cost_tracker,
    unregister_cost_tracker,
)
from src.orchestration.ephemeral_worker import EphemeralWorkerPool
from src.orchestration.episodic_memory import EpisodicEntry, EpisodicMemory
from src.orchestration.evidence_chain import EvidenceChain
from src.orchestration.execution_mode_context import (
    attach_execution_mode_to_input,
    extract_execution_mode,
    is_lab_lease_active_from_options,
)
from src.orchestration.exploit_verification_microvm import (
    ExploitVerificationMicroVM,
    VerificationRequest,
)
from src.orchestration.exploit_verify import verify_exploit_poc_async
from src.orchestration.exploitation_queue import ExploitationQueue, ExploitHypothesis
from src.orchestration.handlers import (
    run_exploit_attempt,
    run_exploit_verify,
    run_post_exploitation,
    run_quick_fuzz,
    run_recon,
    run_reporting,
    run_source_analysis,
    run_threat_modeling,
    run_vuln_analysis,
)
from src.orchestration.phase_resume import (
    ResumeDecision,
    compute_resume_plan,
    freeze_scan_scope,
    get_completed_phases,
    restore_phase_context,
)
from src.orchestration.phases import (
    PHASE_ORDER,
    PHASE_PROGRESS,
    ExploitationOutput,
    ExploitationSubPhase,
    PostExploitationOutput,
    QuickFuzzOutput,
    ReconOutput,
    ReportingOutput,
    ScanPhase,
    SourceAnalysisOutput,
    ThreatModelOutput,
    VulnAnalysisOutput,
)
from src.orchestration.poc_watermarking import stamp_payload
from src.orchestration.raw_phase_artifacts import RawPhaseSink
from src.orchestration.re_verification import (
    ReVerificationRequest,
    ReVerificationTracker,
)
from src.orchestration.scan_events import ScanEvent as _ScanEvent
from src.orchestration.scan_events import ScanEventBus
from src.orchestration.scope_integration import rules_of_engagement_to_prompt_context
from src.orchestration.self_pentest import SelfPentestRunner
from src.orchestration.tenant_isolation import TenantIsolationGuard
from src.owasp_top10_2025 import parse_owasp_category
from src.policy.scan_queue import notify_scan_finished
from src.quick.budget import QuickBudgetError
from src.quick.cancellation import (
    ScanCancelledError,
    propagate_scan_cancellation,
    scan_row_is_cancelled,
)
from src.quick.resolver import QuickProfileResolver, UnknownQuickProfileError
from src.quick.scheduler import (
    get_quick_budget_manager,
    quick_deadline_reached,
    quick_should_stop_discovery,
)
from src.quick.schemas import QuickScanConfig
from src.quick.workflow import (
    DISCOVERY_PHASES,
    SKIPPED_BY_QUICK_PROFILE,
    VERIFICATION_AND_REPORT_PHASES,
    is_quick_execution,
    skip_reason_for_phase,
    skipped_phase_payload,
    skipped_phases_for_options,
)
from src.recon.recon_runtime import build_recon_runtime_config
from src.recon.sandbox_tool_runner import clear_tool_availability_cache
from src.recon.step_registry import plan_recon_steps
from src.recon.vulnerability_analysis.finding_stable_id import (
    assign_stable_finding_ids,
    compute_stable_finding_id,
)
from src.reports.bundle_enqueue import (
    enqueue_generate_all_bundle,
    schedule_generate_all_reports_task_safe,
)
from src.reports.finding_metadata import (
    clip_optional_text,
    normalize_confidence,
    normalize_evidence_refs,
    normalize_evidence_type,
)
from src.storage.s3 import upload_finding_poc_json

logger = logging.getLogger(__name__)

_SCAN_HEARTBEAT_SEC = 30


# ---------------------------------------------------------------------------
# Heartbeat / raw snapshot helpers
# ---------------------------------------------------------------------------


async def _heartbeat_loop(
    session: AsyncSession,
    scan_id: str,
    interval_sec: int,
) -> None:
    """Периодически обновляет Scan.last_heartbeat. Выходит если скан cancelled."""
    while True:
        await asyncio.sleep(interval_sec)
        try:
            result = await session.execute(
                select(Scan.status).where(cast(Scan.id, String) == scan_id)
            )
            current_status = result.scalar_one_or_none()
            if current_status == "cancelled":
                logger.warning(
                    "Скан отменён — heartbeat остановлен",
                    extra={"scan_id": scan_id},
                )
                return
            await session.execute(
                update(Scan)
                .where(cast(Scan.id, String) == scan_id)
                .values(last_heartbeat=func.now())
            )
            await session.commit()
        except Exception:
            logger.exception("Heartbeat update failed", extra={"scan_id": scan_id})


async def _upload_raw_phase_snapshot(
    tenant_id: str,
    scan_id: str,
    phase_key: str,
    artifact_type: str,
    payload: dict,
) -> None:
    """Best-effort MinIO raw artifact; failures are logged inside upload_raw_artifact."""
    sink = RawPhaseSink(tenant_id, scan_id, phase_key)
    await asyncio.to_thread(sink.upload_json, artifact_type, payload)


# ---------------------------------------------------------------------------
# Exceptions / stable-ID helpers / approval flags
# ---------------------------------------------------------------------------


class ExploitationApprovalRequiredError(Exception):
    """Raised when exploitation phase requires approval and scan is not approved."""


class LabLeaseRequiredError(Exception):
    """Raised when LAB mode is requested without a usable execution lease."""


def _ensure_quick_budget(scan_id: str, tenant_id: str, options: dict) -> None:
    """Open wall-clock leases for Quick. Idempotent if the scan is already registered."""
    manager = get_quick_budget_manager()
    if manager.is_open(scan_id):
        return
    config = options.get("quick_config")
    if not isinstance(config, QuickScanConfig):
        profile_raw = str(options.get("quick_profile") or "balanced")
        resolver = QuickProfileResolver()
        try:
            config = resolver.resolve(tenant_id, profile_raw)
        except UnknownQuickProfileError:
            config = resolver.resolve(tenant_id, "balanced")
    started = options.get("started_at")
    if not isinstance(started, datetime):
        started = datetime.now(tz=UTC)
    try:
        snapshot = manager.open_scan(
            tenant_id=tenant_id,
            scan_id=scan_id,
            config=config,
            started_at=started,
        )
        options["deadline_at"] = snapshot.deadline_at.isoformat()
        options["quick_config"] = config
    except QuickBudgetError as exc:
        if getattr(exc, "code", "") != "scan_budget_already_open":
            logger.warning(
                "quick_budget_open_failed",
                extra={
                    "event": "quick_budget_open_failed",
                    "scan_id": scan_id,
                    "code": getattr(exc, "code", ""),
                },
            )


def _apply_skipped_phase_to_ctx(
    phase: ScanPhase,
    ctx: ScanContext,
    payload: dict[str, Any],
    target: str,
) -> None:
    reason = str(payload.get("skip_reason") or "")
    if phase == ScanPhase.SOURCE_ANALYSIS:
        ctx.source_out = SourceAnalysisOutput(skipped=True, summary=reason)
    elif phase == ScanPhase.RECON:
        assets = [target] if target else []
        ctx.recon_out = ReconOutput(assets=assets)
    elif phase == ScanPhase.QUICK_FUZZ:
        ctx.quick_fuzz_out = QuickFuzzOutput()
    elif phase == ScanPhase.THREAT_MODELING:
        ctx.threat_out = ThreatModelOutput(threat_model={"skipped": True, "reason": reason})
    elif phase == ScanPhase.VULN_ANALYSIS:
        ctx.vuln_out = VulnAnalysisOutput(findings=[])
    elif phase == ScanPhase.EXPLOITATION:
        ctx.exploit_out = ExploitationOutput(exploits=[], evidence=[])
    elif phase == ScanPhase.POST_EXPLOITATION:
        ctx.post_out = PostExploitationOutput()


async def _persist_quick_phase_skip(
    *,
    session: AsyncSession,
    tenant_id: str,
    scan_id: str,
    phase: ScanPhase,
    ctx: ScanContext,
    target: str,
    reason: str,
    order_index: int,
    progress: int,
) -> None:
    payload = skipped_phase_payload(phase, reason)
    _apply_skipped_phase_to_ctx(phase, ctx, payload, target)
    step = await _record_step(session, tenant_id, scan_id, phase, "skipped", order_index)
    await _persist_phase_output(session, tenant_id, scan_id, phase.value, payload)
    await _record_event(
        session,
        tenant_id,
        scan_id,
        "phase_skipped",
        phase.value,
        progress,
        message=f"Skipped {phase.value}",
        data=payload,
    )
    logger.info(
        "quick_phase_skipped",
        extra={
            "event": "quick_phase_skipped",
            "scan_id": scan_id,
            "phase": phase.value,
            "skip_reason": reason,
            "step_id": step.id,
        },
    )
    await session.commit()


def _quick_phase_skip_reason(
    phase: ScanPhase,
    *,
    scan_id: str,
    options: dict,
    resume_decision: ResumeDecision | None,
) -> str | None:
    if resume_decision is ResumeDecision.SKIPPED_BY_PROFILE:
        return skip_reason_for_phase(phase)
    if not is_quick_execution(options):
        return None
    if phase in SKIPPED_BY_QUICK_PROFILE:
        return skip_reason_for_phase(phase)
    deadline = quick_deadline_reached(scan_id, options)
    stop_discovery = quick_should_stop_discovery(scan_id, options)
    if deadline and phase not in VERIFICATION_AND_REPORT_PHASES:
        return "deadline_reached"
    if stop_discovery and phase in DISCOVERY_PHASES and phase is not ScanPhase.REPORTING:
        if phase in VERIFICATION_AND_REPORT_PHASES:
            return None
        if phase is ScanPhase.RECON or phase is ScanPhase.QUICK_FUZZ or phase is ScanPhase.SOURCE_ANALYSIS:
            return "deadline_reached"
    return None


_FID_PK_COLLISION_NS = uuid.UUID("018f4a2e-7c8b-7b4d-8e0e-6b6579317431")


def _unique_finding_dicts(findings: list[dict]) -> list[dict]:
    """Drop duplicate references to the same dict (avoids one row overwriting finding_id twice)."""
    seen: set[int] = set()
    out: list[dict] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        oid = id(f)
        if oid in seen:
            continue
        seen.add(oid)
        out.append(f)
    return out


def _dedupe_finding_ids_after_assign(
    findings: list[dict],
    *,
    scan_id: str | None = None,
) -> None:
    """Guarantee unique ``finding_id`` strings in-memory (avoids IntegrityError on bulk insert)."""
    seen: set[str] = set()
    for idx, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        raw = str(f.get("finding_id") or "").strip()
        try:
            pk = str(uuid.UUID(raw)) if raw else compute_stable_finding_id(f, scan_id=scan_id)
        except (ValueError, TypeError, AttributeError):
            pk = compute_stable_finding_id(f, scan_id=scan_id)
        if pk in seen:
            pk = str(
                uuid.uuid5(
                    _FID_PK_COLLISION_NS,
                    f"finding-pk-list-dedup:{pk}:{idx}:v1",
                )
            )
        f["finding_id"] = pk
        seen.add(pk)


def _resolve_unique_finding_pk(
    proposed: str,
    used: set[str],
    *,
    scan_id: str,
    row_index: int,
) -> str:
    """Ensure primary key is unique within this persist batch (duplicate dicts / ID collisions)."""
    pk = proposed
    n = 0
    while pk in used:
        n += 1
        pk = str(
            uuid.uuid5(
                _FID_PK_COLLISION_NS,
                f"finding-pk-collision:{proposed}:{scan_id}:{row_index}:{n}",
            )
        )
    if n:
        logger.warning(
            json.dumps(
                {
                    "event": "finding_pk_collision_resolved",
                    "scan_id": scan_id,
                    "row_index": row_index,
                    "attempts": n,
                },
                ensure_ascii=False,
            )
        )
    used.add(pk)
    return pk


def _scan_approval_flags_from_options(options: dict | None) -> dict[str, bool] | None:
    """Parse ``scan_approval_flags`` from scan options (WEB-006); None if absent or invalid."""
    if not options or not isinstance(options, dict):
        return None
    raw = options.get("scan_approval_flags")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        return None
    return {str(k).strip().lower(): bool(v) for k, v in raw.items()}


def _phase_to_progress(phase: ScanPhase) -> int:
    """Map phase to progress 0..100 (source_analysis 5, recon 15, quick_fuzz 35, threat_modeling 45, vuln_analysis 55, exploitation 70, post_exploitation 85, reporting 100)."""
    return PHASE_PROGRESS.get(phase.value, 0)


# ---------------------------------------------------------------------------
# DB persistence helpers
# ---------------------------------------------------------------------------


async def _record_step(
    session: AsyncSession,
    tenant_id: str,
    scan_id: str,
    phase: ScanPhase,
    status: str,
    order_index: int,
) -> ScanStep:
    """Create scan_step record. Returns the step for later status update."""
    step = ScanStep(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        scan_id=scan_id,
        step_name=phase.value,
        status=status,
        order_index=order_index,
    )
    session.add(step)
    return step


async def _record_event(
    session: AsyncSession,
    tenant_id: str,
    scan_id: str,
    event: str,
    phase: str,
    progress: int | None,
    message: str | None = None,
    data: dict | None = None,
) -> None:
    """Create scan_event record."""
    ev = ScanEvent(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        scan_id=scan_id,
        event=event,
        phase=phase,
        progress=progress,
        message=message,
        data=data,
    )
    session.add(ev)


async def _update_scan_phase_status(
    session: AsyncSession,
    scan_id: str,
    phase: str,
    status: str,
    progress: int,
) -> None:
    """Update scan.phase and scan.status."""
    await session.execute(
        update(Scan)
        .where(cast(Scan.id, String) == scan_id)
        .values(phase=phase, status=status, progress=progress)
    )


async def _persist_phase_input(
    session: AsyncSession,
    tenant_id: str,
    scan_id: str,
    phase: str,
    input_data: dict,
) -> None:
    """Persist phase input to phase_inputs table."""
    pi = PhaseInput(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        scan_id=scan_id,
        phase=phase,
        input_data=input_data,
    )
    session.add(pi)


async def _persist_phase_output(
    session: AsyncSession,
    tenant_id: str,
    scan_id: str,
    phase: str,
    output_data: dict,
) -> None:
    """Persist phase output to phase_outputs table."""
    po = PhaseOutput(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        scan_id=scan_id,
        phase=phase,
        output_data=output_data,
    )
    session.add(po)


async def _record_timeline_entry(
    session: AsyncSession,
    tenant_id: str,
    scan_id: str,
    phase: str,
    order_index: int,
    entry: dict,
) -> None:
    """Add scan_timeline entry."""
    tl = ScanTimeline(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        scan_id=scan_id,
        phase=phase,
        order_index=order_index,
        entry=entry,
    )
    session.add(tl)


async def _check_exploitation_approval_required(
    session: AsyncSession,
    tenant_id: str,
    scan_id: str,
    options: dict[str, Any] | None = None,
) -> bool:
    """
    Check if exploitation phase requires approval per tenant policy.
    Returns True if approval is required and scan is not yet approved.
    Verified LAB lease bypasses tenant exploit_approval gate.
    """
    if is_lab_lease_active_from_options(options, tenant_id=tenant_id):
        return False
    result = await session.execute(
        select(Policy)
        .where(
            cast(Policy.tenant_id, String) == tenant_id,
            Policy.policy_type == "exploit_approval",
            Policy.enabled.is_(True),
        )
    )
    policy = result.scalar_one_or_none()
    if not policy or not policy.config:
        return False
    require = policy.config.get("require_approval")
    if not require:
        return False
    scan_result = await session.execute(select(Scan).where(cast(Scan.id, String) == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        return False
    return scan.status != "approved"


def _build_summary_from_findings(findings: list[dict]) -> ReportSummary:
    """Aggregate severity counts from findings."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["info"] += 1
    return ReportSummary(
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        technologies=[],
        sslIssues=0,
        headerIssues=0,
        leaksFound=False,
    )


async def _persist_report_and_findings(
    session: AsyncSession,
    tenant_id: str,
    scan_id: str,
    target: str,
    report_out: ReportingOutput,
    vuln_out: VulnAnalysisOutput | None,
    recon_out: ReconOutput | None,
) -> None:
    """Persist Report and Findings to DB after reporting phase."""
    report_id = str(uuid.uuid4())
    findings_raw = list(vuln_out.findings) if vuln_out and vuln_out.findings else []
    findings_raw = _unique_finding_dicts(findings_raw)

    try:
        _cvss_scorer = CVSSAutoScorer()
        _cvss_scorer.score_all_findings(findings_raw)
    except Exception as _cvss_exc:
        logger.warning("cvss_auto_score_failed", extra={"scan_id": scan_id, "error": str(_cvss_exc)})

    assign_stable_finding_ids(findings_raw, scan_id=scan_id)
    _dedupe_finding_ids_after_assign(findings_raw, scan_id=scan_id)
    report_dict = report_out.report or {}

    summary_dict = report_dict.get("summary") or {}
    if summary_dict and isinstance(summary_dict, dict):
        summary = ReportSummary(
            critical=int(summary_dict.get("critical", 0)),
            high=int(summary_dict.get("high", 0)),
            medium=int(summary_dict.get("medium", 0)),
            low=int(summary_dict.get("low", 0)),
            info=int(summary_dict.get("info", 0)),
            technologies=summary_dict.get("technologies", []) or [],
            sslIssues=int(summary_dict.get("sslIssues", 0)),
            headerIssues=int(summary_dict.get("headerIssues", 0)),
            leaksFound=bool(summary_dict.get("leaksFound", False)),
        )
    else:
        summary = _build_summary_from_findings(findings_raw)

    technologies = report_dict.get("technologies") or []
    if not technologies and recon_out:
        technologies = list(recon_out.assets)[:20]

    report = Report(
        id=report_id,
        tenant_id=tenant_id,
        scan_id=scan_id,
        target=target,
        summary={**summary.model_dump(), "ai_insights": report_dict.get("ai_insights") or []},
        technologies=technologies if technologies else None,
    )
    session.add(report)
    await session.flush()

    used_finding_pks: set[str] = set()
    for row_index, f in enumerate(findings_raw):
        poc_blob = f.get("proof_of_concept")
        poc_db = poc_blob if isinstance(poc_blob, dict) and poc_blob else None
        ow_raw = f.get("owasp_category")
        owasp_val = parse_owasp_category(ow_raw.strip()) if isinstance(ow_raw, str) and ow_raw.strip() else None
        conf = normalize_confidence(f.get("confidence"), default="likely")
        ev_type = normalize_evidence_type(f.get("evidence_type"))
        ev_refs = normalize_evidence_refs(f.get("evidence_refs"))
        rep_steps = clip_optional_text(f.get("reproducible_steps"), 16_000)
        app_notes = clip_optional_text(f.get("applicability_notes"), 8_000)
        fid_raw = str(f.get("finding_id") or "").strip()
        try:
            finding_pk = (
                str(uuid.UUID(fid_raw)) if fid_raw else compute_stable_finding_id(f, scan_id=scan_id)
            )
        except (ValueError, TypeError, AttributeError):
            finding_pk = compute_stable_finding_id(f, scan_id=scan_id)
        finding_pk = _resolve_unique_finding_pk(
            finding_pk,
            used_finding_pks,
            scan_id=scan_id,
            row_index=row_index,
        )
        f["finding_id"] = finding_pk
        _et_raw = f.get("evidence_tier")
        _et = int(_et_raw) if isinstance(_et_raw, (int, float)) and 1 <= int(_et_raw) <= 4 else None
        _pa = f.get("payload_attempted")
        _ps = f.get("payload_successful")
        _tp = f.get("taint_path")
        _cl = str(f.get("code_location", ""))[:500] if f.get("code_location") else None
        _adv = f.get("adversarial_score")
        _adv = float(_adv) if isinstance(_adv, (int, float)) else None
        _eds = f.get("exploit_demonstrated")
        _es = str(f.get("exploit_summary", ""))[:2000] if f.get("exploit_summary") else None
        _cvss_vec = str(f.get("cvss_vector", ""))[:100] if f.get("cvss_vector") else None
        _dedup = str(f.get("dedup_status", "unchecked"))[:20] if f.get("dedup_status") else None
        finding = Finding(
            id=finding_pk,
            tenant_id=tenant_id,
            scan_id=scan_id,
            report_id=report_id,
            severity=str(f.get("severity", "info"))[:20],
            title=str(f.get("title", "Unknown"))[:500],
            description=str(f.get("description", "")) if f.get("description") else None,
            cwe=str(f.get("cwe", ""))[:20] if f.get("cwe") else None,
            cvss=float(f["cvss"]) if isinstance(f.get("cvss"), (int, float)) else None,
            owasp_category=owasp_val,
            proof_of_concept=poc_db,
            confidence=conf,
            evidence_type=ev_type,
            evidence_refs=ev_refs,
            reproducible_steps=rep_steps,
            applicability_notes=app_notes,
            evidence_tier=_et,
            payload_attempted=_pa if isinstance(_pa, list) else None,
            payload_successful=_ps if isinstance(_ps, list) else None,
            taint_path=_tp if isinstance(_tp, list) else None,
            code_location=_cl,
            adversarial_score=_adv,
            exploit_demonstrated=bool(_eds) if _eds is not None else None,
            exploit_summary=_es,
            cvss_vector=_cvss_vec,
            dedup_status=_dedup,
        )
        session.add(finding)
        if poc_db:
            await asyncio.to_thread(
                upload_finding_poc_json,
                tenant_id,
                scan_id,
                finding.id,
                poc_db,
            )
        await _record_event(
            session,
            tenant_id,
            scan_id,
            "finding",
            "reporting",
            100,
            message=f"Finding: {finding.title[:80]}",
            data={
                "severity": finding.severity,
                "title": finding.title,
                "cwe": finding.cwe,
                "cvss": finding.cvss,
            },
        )


# ---------------------------------------------------------------------------
# ScanContext — mutable state flowing through the phase pipeline
# ---------------------------------------------------------------------------


@dataclass
class ScanContext:
    """Mutable state carrying all phase outputs across the scan pipeline."""
    source_out: SourceAnalysisOutput | None = None
    recon_out: ReconOutput | None = None
    quick_fuzz_out: QuickFuzzOutput | None = None
    threat_out: ThreatModelOutput | None = None
    vuln_out: VulnAnalysisOutput | None = None
    exploit_out: ExploitationOutput | None = None
    post_out: PostExploitationOutput | None = None
    report_out: ReportingOutput | None = None


# ---------------------------------------------------------------------------
# Extracted subsystem initialization
# ---------------------------------------------------------------------------


async def _init_scan_subsystems(
    scan_id: str,
    tenant_id: str,
    target: str,
    options: dict,
) -> dict[str, Any]:
    """Initialize optional scan subsystems (non-blocking on failure).

    Returns a dict with keys: evidence_chain, episodic_memory, cost_tracker, event_bus.
    Each value is the initialized subsystem or None.
    """
    subsystems: dict[str, Any] = {}

    evidence_chain = None
    try:
        evidence_chain = EvidenceChain(scan_id=scan_id, tenant_id=tenant_id)
        evidence_chain.add_scan_link(target_url=target)
    except Exception as _ec_exc:
        logger.warning(
            "evidence_chain_init_failed",
            extra={"scan_id": scan_id, "error": str(_ec_exc)},
        )
    subsystems["evidence_chain"] = evidence_chain

    episodic_memory = None
    try:
        episodic_memory = EpisodicMemory()
    except Exception as _em_exc:
        logger.warning(
            "episodic_memory_init_failed",
            extra={"scan_id": scan_id, "error": str(_em_exc)},
        )
    subsystems["episodic_memory"] = episodic_memory

    cost_tracker = None
    try:
        _max_cost = float(options.get("max_cost_usd", 50.0)) if options else 50.0
        _max_tokens = int(options.get("max_tokens", 2000000)) if options else 2000000
        cost_tracker = CostTracker(
            scan_id=scan_id, max_cost_usd=_max_cost, max_total_tokens=_max_tokens
        )
    except Exception as _cr_exc:
        logger.warning(
            "cost_tracker_init_failed",
            extra={"scan_id": scan_id, "error": str(_cr_exc)},
        )
    subsystems["cost_tracker"] = cost_tracker

    if cost_tracker is not None:
        try:
            register_cost_tracker(cost_tracker)
        except Exception as _reg_exc:
            logger.warning(
                "register_cost_tracker_failed",
                extra={"scan_id": scan_id, "error": str(_reg_exc)},
            )

    try:
        _guard = TenantIsolationGuard()
        if not _guard.can_start_scan(tenant_id):
            logger.warning("tenant_scan_limit_reached", extra={"tenant_id": tenant_id})
        else:
            _guard.register_scan_start(tenant_id)
    except Exception as _ti_exc:
        logger.warning(
            "tenant_isolation_init_failed",
            extra={"tenant_id": tenant_id, "error": str(_ti_exc)},
        )

    event_bus = None
    try:
        event_bus = ScanEventBus()
    except Exception as _se_exc:
        logger.warning(
            "scan_events_init_failed",
            extra={"scan_id": scan_id, "error": str(_se_exc)},
        )
    subsystems["event_bus"] = event_bus

    return subsystems


# ---------------------------------------------------------------------------
# Extracted resume-plan detection and context restoration
# ---------------------------------------------------------------------------


async def _detect_resume_plan(
    session: AsyncSession,
    scan_id: str,
    options: dict | None,
    target: str,
) -> tuple[dict[ScanPhase, ResumeDecision], ScanContext]:
    """Detect completed phases, compute resume plan, restore prior outputs.

    Returns (resume_plan: dict, ctx: ScanContext with restored outputs).
    """
    ctx = ScanContext()

    completed_phases = await get_completed_phases(session, scan_id)
    skipped_by_profile = skipped_phases_for_options(options)
    resume_plan = compute_resume_plan(
        completed_phases,
        skipped_by_profile=skipped_by_profile,
    )

    if completed_phases:
        logger.info(
            "Resuming scan %s: completed phases=%s",
            scan_id,
            [p.value for p in completed_phases],
        )
        for restored_phase in completed_phases:
            restored = await restore_phase_context(session, scan_id, restored_phase)
            if restored is None:
                continue
            if restored_phase == ScanPhase.SOURCE_ANALYSIS:
                try:
                    ctx.source_out = SourceAnalysisOutput.model_validate(restored)
                except Exception as _val_exc:
                    logger.warning(
                        "restore_source_analysis_failed",
                        extra={"scan_id": scan_id, "error": str(_val_exc)},
                    )
            elif restored_phase == ScanPhase.RECON:
                try:
                    ctx.recon_out = ReconOutput.model_validate(restored)
                except Exception as _val_exc:
                    logger.warning(
                        "restore_recon_failed",
                        extra={"scan_id": scan_id, "error": str(_val_exc)},
                    )
            elif restored_phase == ScanPhase.QUICK_FUZZ:
                try:
                    ctx.quick_fuzz_out = QuickFuzzOutput.model_validate(restored)
                except Exception as _val_exc:
                    logger.warning(
                        "restore_quick_fuzz_failed",
                        extra={"scan_id": scan_id, "error": str(_val_exc)},
                    )
            elif restored_phase == ScanPhase.THREAT_MODELING:
                try:
                    ctx.threat_out = ThreatModelOutput.model_validate(restored)
                except Exception as _val_exc:
                    logger.warning(
                        "restore_threat_modeling_failed",
                        extra={"scan_id": scan_id, "error": str(_val_exc)},
                    )
            elif restored_phase == ScanPhase.VULN_ANALYSIS:
                try:
                    ctx.vuln_out = VulnAnalysisOutput.model_validate(restored)
                except Exception as _val_exc:
                    logger.warning(
                        "restore_vuln_analysis_failed",
                        extra={"scan_id": scan_id, "error": str(_val_exc)},
                    )
            elif restored_phase == ScanPhase.EXPLOITATION:
                try:
                    ctx.exploit_out = ExploitationOutput.model_validate(restored)
                except Exception as _val_exc:
                    logger.warning(
                        "restore_exploitation_failed",
                        extra={"scan_id": scan_id, "error": str(_val_exc)},
                    )
            elif restored_phase == ScanPhase.POST_EXPLOITATION:
                try:
                    ctx.post_out = PostExploitationOutput.model_validate(restored)
                except Exception as _val_exc:
                    logger.warning(
                        "restore_post_exploitation_failed",
                        extra={"scan_id": scan_id, "error": str(_val_exc)},
                    )

    freeze_scan_scope_kwargs: dict[str, Any] = {}
    if options:
        freeze_scan_scope_kwargs["vuln_classes"] = options.get("vuln_classes")
        freeze_scan_scope_kwargs["exploit_enabled"] = options.get("exploit_enabled", True)
    try:
        await freeze_scan_scope(
            session, scan_id,
            target_url=target,
            **{k: v for k, v in freeze_scan_scope_kwargs.items() if v is not None},
        )
    except Exception as _scope_exc:
        # Non-fatal: scope may already be frozen or the row may be absent on
        # resume. Kept non-blocking to preserve resume behaviour, but logged
        # with the exception type so a genuine scope-freeze regression is
        # visible instead of being swallowed silently.
        logger.warning(
            "freeze_scan_scope_failed",
            extra={
                "scan_id": scan_id,
                "exception_type": type(_scope_exc).__name__,
                "error": str(_scope_exc),
            },
        )

    return resume_plan, ctx


# ---------------------------------------------------------------------------
# Extracted phase input builder
# ---------------------------------------------------------------------------


async def _build_phase_input(
    phase: ScanPhase,
    ctx: ScanContext,
    options: dict | None,
    target: str,
    session: AsyncSession,
    tenant_id: str,
    scan_id: str,
    episodic_memory: Any | None,
) -> dict:
    """Build input_data for a phase from prior outputs, persist to DB, upload snapshots."""
    input_data: dict[str, Any] = {}

    if phase == ScanPhase.SOURCE_ANALYSIS:
        repo_path = options.get("repo_path") if options else None
        repo_url = options.get("repo_url") if options else None
        input_data = {
            "target": target,
            "repo_path": repo_path,
            "repo_url": repo_url,
            "options": options,
        }
    elif phase == ScanPhase.RECON:
        input_data = {
            "target": target,
            "options": options,
            "source_analysis": ctx.source_out.model_dump() if ctx.source_out and not ctx.source_out.skipped else None,
        }
    elif phase == ScanPhase.QUICK_FUZZ:
        input_data = {
            "target": target,
            "recon_output": ctx.recon_out.model_dump() if ctx.recon_out else None,
            "options": options,
        }
    elif phase == ScanPhase.THREAT_MODELING:
        input_data = {
            "assets": ctx.recon_out.assets if ctx.recon_out else [],
            "source_analysis": ctx.source_out.model_dump() if ctx.source_out and not ctx.source_out.skipped else None,
            "quick_fuzz_findings": ctx.quick_fuzz_out.findings if ctx.quick_fuzz_out else [],
            "quick_fuzz_candidates": ctx.quick_fuzz_out.candidates if ctx.quick_fuzz_out else [],
        }
    elif phase == ScanPhase.VULN_ANALYSIS:
        input_data = {
            "threat_model": ctx.threat_out.threat_model if ctx.threat_out else {},
            "assets": ctx.recon_out.assets if ctx.recon_out else [],
        }
        if ctx.quick_fuzz_out and ctx.quick_fuzz_out.candidates:
            input_data["quick_fuzz_candidates"] = ctx.quick_fuzz_out.candidates
        if ctx.source_out and not ctx.source_out.skipped:
            try:
                input_data["source_analysis"] = ctx.source_out.model_dump()
            except Exception as _sa_exc:
                logger.warning(
                    "source_analysis_data_failed",
                    extra={"scan_id": scan_id, "error": str(_sa_exc)},
                )
        if episodic_memory is not None:
            try:
                _mem_ctx = episodic_memory.build_context_prompt(
                    f"vuln_analysis {target}", max_entries=3
                )
                input_data["memory_context"] = _mem_ctx
            except Exception as _mem_exc:
                logger.warning(
                    "episodic_memory_recall_failed",
                    extra={"scan_id": scan_id, "error": str(_mem_exc)},
                )
    elif phase == ScanPhase.EXPLOITATION:
        input_data = {
            "findings": ctx.vuln_out.findings if ctx.vuln_out else [],
            "auth_config": None,
        }
    elif phase == ScanPhase.POST_EXPLOITATION:
        input_data = {
            "exploits": ctx.exploit_out.exploits if ctx.exploit_out else [],
            "evidence": ctx.exploit_out.evidence if ctx.exploit_out else [],
            "evidence_tiers": {
                k: int(v) if hasattr(v, '__int__') else v
                for k, v in (ctx.exploit_out.evidence_tiers or {}).items()
            } if ctx.exploit_out else {},
        }
    elif phase == ScanPhase.REPORTING:
        input_data = {
            "target": target,
            "recon": ctx.recon_out.model_dump() if ctx.recon_out else None,
            "threat_model": ctx.threat_out.model_dump() if ctx.threat_out else None,
            "vuln_analysis": ctx.vuln_out.model_dump() if ctx.vuln_out else None,
            "exploitation": ctx.exploit_out.model_dump() if ctx.exploit_out else None,
            "post_exploitation": ctx.post_out.model_dump() if ctx.post_out else None,
            "scope_config": None,
            "source_analysis": ctx.source_out.model_dump() if ctx.source_out else None,
            "quick_fuzz": ctx.quick_fuzz_out.model_dump() if ctx.quick_fuzz_out else None,
        }

    phase_str = phase.value
    await _persist_phase_input(session, tenant_id, scan_id, phase_str, input_data)

    if phase == ScanPhase.RECON:
        await _upload_raw_phase_snapshot(tenant_id, scan_id, "recon", "phase_input", input_data)
    elif phase == ScanPhase.QUICK_FUZZ:
        await _upload_raw_phase_snapshot(tenant_id, scan_id, "quick_fuzz", "phase_input", input_data)
    elif phase == ScanPhase.VULN_ANALYSIS:
        await _upload_raw_phase_snapshot(tenant_id, scan_id, "vuln_analysis", "phase_input", input_data)
    elif phase == ScanPhase.POST_EXPLOITATION:
        await _upload_raw_phase_snapshot(tenant_id, scan_id, "post_exploitation", "phase_input", input_data)

    return input_data


# ---------------------------------------------------------------------------
# Extracted single-phase execution + dispatch
# ---------------------------------------------------------------------------


async def _execute_phase(
    phase: ScanPhase,
    ctx: ScanContext,
    input_data: dict,
    subsystems: dict[str, Any],
    session: AsyncSession,
    scan_id: str,
    tenant_id: str,
    target: str,
    options: dict,
    step: ScanStep,
    progress: int,
    heartbeat_task: asyncio.Task,
    order_index: int,
    cost_tracker: Any | None,
    event_bus: Any | None,
    auth_config_obj: Any | None,
    scope_context: dict[str, Any] | None,
) -> dict:
    """Execute a single scan phase handler. Returns output_data dict. Updates ctx in-place."""
    phase_str = phase.value

    # Pre-phase: record step, events, update status
    await _record_step(session, tenant_id, scan_id, phase, "running", order_index)
    await _record_event(
        session, tenant_id, scan_id, "phase_start", phase_str, progress,
        message=f"Starting {phase_str}",
    )
    if event_bus is not None:
        try:
            event_bus.publish(_ScanEvent(
                event_type="phase_start", scan_id=scan_id, tenant_id=tenant_id,
                phase=phase_str, progress=progress, message=f"Starting {phase_str}",
            ))
        except Exception as _eb_exc:
            logger.warning(
                "event_bus_publish_phase_start_failed",
                extra={"scan_id": scan_id, "error": str(_eb_exc)},
            )
    await _record_event(
        session, tenant_id, scan_id, "progress", phase_str, progress,
        message=f"Progress {progress}%",
    )
    await _update_scan_phase_status(session, scan_id, phase_str, "running", progress)
    await session.commit()

    logger.info(
        "Phase started",
        extra={"event_type": "phase_start", "phase": phase_str, "scan_id": scan_id},
    )

    # --- Phase dispatch ---
    try:
        with trace_phase(scan_id, phase_str):
            output_data = await _dispatch_phase_handler(
                phase=phase,
                ctx=ctx,
                input_data=input_data,
                scan_id=scan_id,
                tenant_id=tenant_id,
                target=target,
                options=options,
                session=session,
                progress=progress,
                phase_str=phase_str,
                cost_tracker=cost_tracker,
                auth_config_obj=auth_config_obj,
                scope_context=scope_context,
            )
    except Exception as exc:
        heartbeat_task.cancel()
        with suppress(asyncio.CancelledError):
            await heartbeat_task
        await session.execute(
            update(ScanStep)
            .where(cast(ScanStep.id, String) == step.id)
            .values(status="failed")
        )
        logger.error(
            "Phase handler failed",
            extra={
                "event_type": "phase_error",
                "phase": phase_str,
                "scan_id": scan_id,
                "exception_type": type(exc).__name__,
            },
            exc_info=True,
        )
        err_message = "Phase failed"
        err_data: dict[str, str] = {"code": "phase_error"}
        if isinstance(exc, RuntimeError):
            etext = str(exc)
            if etext.startswith("LLM provider required"):
                err_message = etext
                err_data = {"code": "llm_required"}
        await _record_event(
            session, tenant_id, scan_id, "error", phase_str, progress,
            message=err_message, data=err_data,
        )
        await _update_scan_phase_status(session, scan_id, phase_str, "failed", progress)
        await session.commit()
        raise

    return output_data


async def _dispatch_phase_handler(
    phase: ScanPhase,
    ctx: ScanContext,
    input_data: dict,
    scan_id: str,
    tenant_id: str,
    target: str,
    options: dict,
    session: AsyncSession,
    progress: int,
    phase_str: str,
    cost_tracker: Any | None,
    auth_config_obj: Any | None,
    scope_context: dict[str, Any] | None,
) -> dict:
    """Dispatch to the appropriate phase handler. Returns output_data dict."""
    output_data: dict

    if phase == ScanPhase.SOURCE_ANALYSIS:
        try:
            source_out = await run_source_analysis(
                target=target,
                options=options or {},
                tenant_id=tenant_id,
                scan_id=scan_id,
            )
        except ImportError:
            logger.warning("source_analysis handler unavailable, skipping")
            source_out = SourceAnalysisOutput(
                skipped=True, summary="Source analysis handler not available"
            )
        except Exception as sa_exc:
            logger.warning("source_analysis failed: %s", sa_exc)
            source_out = SourceAnalysisOutput(
                skipped=True, summary=f"Source analysis error: {sa_exc}"
            )
        ctx.source_out = source_out

        if source_out and not source_out.skipped:
            try:
                _sa_dict = source_out.model_dump() if hasattr(source_out, "model_dump") else {}
                _code_files = _sa_dict.get("code_files", []) or []
                _binary_types = []
                for _cf in _code_files:
                    _path = str(_cf.get("path", _cf)) if isinstance(_cf, dict) else str(_cf)
                    _btype = detect_binary_type(_path)
                    if _btype != "unknown":
                        _binary_types.append({"file": _path, "type": _btype})
                if _binary_types:
                    logger.info(
                        "binary_analysis_detected",
                        extra={"scan_id": scan_id, "binaries": len(_binary_types)},
                    )
                if _binary_types and options.get("binary_analysis_enabled", True):
                    _ba_max = min(len(_binary_types), 3)
                    for _bi in _binary_types[:_ba_max]:
                        try:
                            _ba_req = BinaryAnalysisRequest(
                                binary_path=_bi["file"],
                                analysis_type="full",
                                architecture=_bi["type"],
                                scan_id=scan_id or "",
                            )
                            _ba_result = await run_binary_analysis(
                                _ba_req, use_sandbox=bool(settings.sandbox_enabled)
                            )
                            if _ba_result and _ba_result.vulnerabilities:
                                for _bv in _ba_result.vulnerabilities:
                                    _sa_dict.setdefault("binary_findings", []).append({
                                        "title": f"Binary: {_bv.vuln_type} in {_bi['file']}",
                                        "severity": _bv.severity,
                                        "description": _bv.description,
                                        "source": "binary_analysis",
                                        "cwe": "",
                                        "evidence_tier": 2,
                                    })
                                logger.info(
                                    "binary_analysis_vulns_found",
                                    extra={"scan_id": scan_id, "file": _bi["file"], "vulns": len(_ba_result.vulnerabilities)},
                                )
                            elif _ba_result and _ba_result.strings:
                                logger.info(
                                    "binary_analysis_strings_extracted",
                                    extra={"scan_id": scan_id, "file": _bi["file"], "strings": len(_ba_result.strings)},
                                )
                            else:
                                logger.info(
                                    "binary_analysis_no_results",
                                    extra={"scan_id": scan_id, "file": _bi["file"]},
                                )
                        except Exception as _ba_run_exc:
                            logger.warning(
                                "binary_analysis_run_failed",
                                extra={"scan_id": scan_id, "file": _bi["file"], "error": str(_ba_run_exc)},
                            )
            except Exception as _ba_exc:
                logger.warning(
                    "binary_analysis_failed",
                    extra={"scan_id": scan_id, "error": str(_ba_exc)},
                )
        output_data = source_out.model_dump()

    elif phase == ScanPhase.RECON:
        record_tool_run("recon")
        _recon_cfg = build_recon_runtime_config(options)
        logger.debug(
            "recon_step_registry_preview",
            extra={
                "event": "recon_step_registry_preview",
                "scan_id": scan_id,
                "mode": _recon_cfg.mode,
                "steps": [s.value for s in plan_recon_steps(_recon_cfg)],
            },
        )
        recon_out = await run_recon(
            target, options, tenant_id=tenant_id, scan_id=scan_id,
            source_analysis=ctx.source_out,
        )
        ctx.recon_out = recon_out
        output_data = recon_out.model_dump()

    elif phase == ScanPhase.QUICK_FUZZ:
        record_tool_run("quick_fuzz")
        quick_fuzz_out = await run_quick_fuzz(
            target,
            recon_output=ctx.recon_out.model_dump() if ctx.recon_out else None,
            options=options,
            tenant_id=tenant_id,
            scan_id=scan_id,
        )
        ctx.quick_fuzz_out = quick_fuzz_out
        output_data = quick_fuzz_out.model_dump()

    elif phase == ScanPhase.THREAT_MODELING:
        record_tool_run("threat_modeling")
        assets = ctx.recon_out.assets if ctx.recon_out else []
        threat_out = await run_threat_modeling(
            assets,
            subdomains=ctx.recon_out.subdomains if ctx.recon_out else None,
            ports=ctx.recon_out.ports if ctx.recon_out else None,
            target=target,
            scan_id=scan_id,
            tenant_id=tenant_id,
            scan_options=options,
            source_analysis=ctx.source_out,
            quick_fuzz_findings=ctx.quick_fuzz_out.findings if ctx.quick_fuzz_out else None,
        )
        ctx.threat_out = threat_out
        output_data = threat_out.model_dump()

    elif phase == ScanPhase.VULN_ANALYSIS:
        record_tool_run("vuln_analysis")
        tm = ctx.threat_out.threat_model if ctx.threat_out else {}
        assets = ctx.recon_out.assets if ctx.recon_out else []
        vuln_out = await run_vuln_analysis(
            tm,
            assets,
            target=target,
            tenant_id=tenant_id,
            scan_id=scan_id,
            scan_options=options,
            recon_context=ctx.recon_out.tool_results if ctx.recon_out else None,
            source_analysis=ctx.source_out,
            quick_fuzz_candidates=ctx.quick_fuzz_out.candidates if ctx.quick_fuzz_out else None,
        )
        ctx.vuln_out = vuln_out
        output_data = vuln_out.model_dump()

    elif phase == ScanPhase.EXPLOITATION:
        if is_quick_execution(options):
            payload = skipped_phase_payload(phase)
            ctx.exploit_out = ExploitationOutput(exploits=[], evidence=[])
            return payload
        findings = ctx.vuln_out.findings if ctx.vuln_out else []

        try:
            exploitation_queue = ExploitationQueue.from_vuln_analysis_output(
                target=target or "",
                findings=findings,
                scan_id=scan_id or "",
            )
            for _hyp_dict in (ctx.vuln_out.hypotheses or []):
                try:
                    _hyp = ExploitHypothesis(
                        finding_id=str(_hyp_dict.get("finding_id") or _hyp_dict.get("id") or ""),
                        vuln_type=_hyp_dict.get("vuln_type", "unknown"),
                        location=_hyp_dict.get("location", "unknown"),
                        method=_hyp_dict.get("method", "GET"),
                        parameter=_hyp_dict.get("parameter", ""),
                        evidence=_hyp_dict.get("evidence", ""),
                        suggested_payload=_hyp_dict.get("suggested_payload", ""),
                        confidence=float(_hyp_dict.get("confidence", 0.5)),
                        source_phase=f"vuln_agent_{_hyp_dict.get('source_domain', 'unknown')}",
                    )
                    exploitation_queue.hypotheses.append(_hyp)
                except Exception as _hyp_exc:
                    logger.warning(
                        "exploit_hypothesis_append_failed",
                        extra={"scan_id": scan_id, "error": str(_hyp_exc)},
                    )
            structured_findings = exploitation_queue.to_exploitation_input()
            logger.info(
                "ExploitationQueue: %d hypotheses for %s",
                len(exploitation_queue.hypotheses),
                scan_id,
            )
        except Exception as eq_exc:
            logger.warning(
                "ExploitationQueue build failed, using raw findings: %s", eq_exc,
                extra={"scan_id": scan_id},
            )
            structured_findings = None

        try:
            auth_cfg = TargetConfig.from_scan_options(options) if options else None
        except Exception as _auth_exc:
            logger.warning(
                "exploit_auth_config_load_failed",
                extra={"scan_id": scan_id, "error": str(_auth_exc)},
            )
            auth_cfg = None

        if not is_quick_execution(options):
            maybe_run_aggressive_exploit_tools(
                findings,
                tenant_id,
                scan_id,
                target,
                scan_approval_flags=_scan_approval_flags_from_options(options),
                scan_options=options,
            )
        await _record_event(
            session, tenant_id, scan_id, "tool_run", phase_str, progress,
            message=f"Running {ExploitationSubPhase.EXPLOIT_ATTEMPT.value}",
            data={"tool": ExploitationSubPhase.EXPLOIT_ATTEMPT.value},
        )
        record_tool_run(ExploitationSubPhase.EXPLOIT_ATTEMPT.value)
        await session.commit()

        _ewp = None
        if options and options.get("ephemeral_workers"):
            try:
                _ewp = EphemeralWorkerPool(max_containers=options.get("max_ephemeral_containers", 5))
                logger.info(
                    "ephemeral_worker_pool_active",
                    extra={"scan_id": scan_id, "max": _ewp._max_containers},
                )
            except Exception as _ewp_exc:
                logger.warning(
                    "ephemeral_worker_pool_init_failed: %s", _ewp_exc,
                    extra={"scan_id": scan_id},
                )

        _auth_config_dict = None
        try:
            if auth_cfg and hasattr(auth_cfg, "model_dump"):
                _auth_config_dict = auth_cfg.model_dump()
            elif auth_cfg and isinstance(auth_cfg, dict):
                _auth_config_dict = auth_cfg
        except Exception as _ad_exc:
            logger.warning(
                "exploit_auth_config_dump_failed",
                extra={"scan_id": scan_id, "error": str(_ad_exc)},
            )

        _exploitation_findings = findings
        try:
            if structured_findings and isinstance(structured_findings, dict):
                _exploitation_findings = structured_findings.get("findings", findings)
                logger.info(
                    "Using structured_findings from ExploitationQueue (%d hypotheses)",
                    len(_exploitation_findings),
                    extra={"scan_id": scan_id},
                )
        except Exception as _sf_exc:
            logger.warning(
                "structured_findings_extract_failed",
                extra={"scan_id": scan_id, "error": str(_sf_exc)},
            )

        attempt_out = await run_exploit_attempt(
            _exploitation_findings, scan_id=scan_id, target=target, tenant_id=tenant_id,
            auth_config=_auth_config_dict,
            execution_mode=extract_execution_mode(
                options if isinstance(options, dict) else None
            ).value,
            scan_options=options if isinstance(options, dict) else None,
        )
        await _record_event(
            session, tenant_id, scan_id, "progress", phase_str, progress,
            message=f"Completed {ExploitationSubPhase.EXPLOIT_ATTEMPT.value}",
            data={"tool": ExploitationSubPhase.EXPLOIT_ATTEMPT.value},
        )
        await _record_event(
            session, tenant_id, scan_id, "tool_run", phase_str, progress,
            message=f"Running {ExploitationSubPhase.EXPLOIT_VERIFY.value}",
            data={"tool": ExploitationSubPhase.EXPLOIT_VERIFY.value},
        )
        record_tool_run(ExploitationSubPhase.EXPLOIT_VERIFY.value)
        await session.commit()
        exploit_out = await run_exploit_verify(attempt_out)

        try:
            _microvm = ExploitVerificationMicroVM()
            for _cand in (exploit_out.exploits or []):
                if str(_cand.get("severity", "")).lower() in ("critical", "high"):
                    try:
                        _vr = VerificationRequest(
                            exploit_payload=str(_cand.get("poc_curl", _cand.get("exploit_payload", ""))),
                            exploit_type=str(_cand.get("vuln_type", "general")),
                            finding_id=str(_cand.get("finding_id", "")),
                            scan_id=scan_id,
                        )
                        _vresult = await _microvm.verify(_vr)
                        if _vresult.verified:
                            _cand["microvm_verified"] = True
                            _cand["microvm_artifact"] = _vresult.artifact_content[:2000]
                    except Exception as _vm_cand_exc:
                        logger.warning(
                            "microvm_verify_cand_failed",
                            extra={"scan_id": scan_id, "error": str(_vm_cand_exc)},
                        )
        except Exception as _vm_exc:
            logger.warning(
                "microvm_verification_failed",
                extra={"scan_id": scan_id, "error": str(_vm_exc)},
            )

        if _ewp is not None:
            try:
                for _ecand in (exploit_out.exploits or [])[:3]:
                    if str(_ecand.get("severity", "")).lower() in ("critical", "high"):
                        _container_id = await _ewp.acquire(
                            f"exploit-{scan_id[:12]}-{_ecand.get('finding_id', 'unk')[:8]}",
                        )
                        if _container_id:
                            logger.info(
                                "ephemeral_worker_acquired",
                                extra={"scan_id": scan_id, "container": _container_id, "finding": str(_ecand.get("finding_id", ""))},
                            )
                            try:
                                _artifacts = await _ewp.collect_artifacts(_container_id, scan_id, "exploit_verify", str(_ecand.get("finding_id", "")))
                                if _artifacts:
                                    _ecand["ephemeral_artifacts"] = _artifacts
                            except Exception as _ewp_coll_exc:
                                logger.warning(
                                    "ephemeral_collect_artifacts_failed",
                                    extra={"scan_id": scan_id, "error": str(_ewp_coll_exc)},
                                )
                            finally:
                                await _ewp.release(_container_id)
            except Exception as _ewp_dispatch_exc:
                logger.warning(
                    "ephemeral_worker_dispatch_failed: %s", _ewp_dispatch_exc,
                    extra={"scan_id": scan_id},
                )
            try:
                await _ewp.prune_stale()
                logger.info(
                    "ephemeral_worker_pool_cleanup",
                    extra={"scan_id": scan_id, "active": _ewp.active_count},
                )
            except Exception as _ewp_clean_exc:
                logger.warning(
                    "ephemeral_cleanup_failed: %s", _ewp_clean_exc,
                    extra={"scan_id": scan_id},
                )

        try:
            _wm_secret = options.get("watermark_secret", "argus-default-wm-key") if options else "argus-default-wm-key"
            for _exploit in (exploit_out.exploits or []):
                _poc = _exploit.get("poc_curl", _exploit.get("poc", ""))
                if _poc and not _poc.startswith("# ARGUS-WM"):
                    _exploit["poc_curl"] = stamp_payload(
                        _poc, scan_id=scan_id, tenant_id=tenant_id, secret_key=_wm_secret
                    )
        except Exception as _wm_exc:
            logger.warning(
                "poc_watermarking_failed",
                extra={"scan_id": scan_id, "error": str(_wm_exc)},
            )

        await _record_event(
            session, tenant_id, scan_id, "progress", phase_str, progress,
            message=f"Completed {ExploitationSubPhase.EXPLOIT_VERIFY.value}",
            data={"tool": ExploitationSubPhase.EXPLOIT_VERIFY.value},
        )
        ctx.exploit_out = exploit_out
        output_data = exploit_out.model_dump()

    elif phase == ScanPhase.POST_EXPLOITATION:
        if is_quick_execution(options):
            payload = skipped_phase_payload(phase)
            ctx.post_out = PostExploitationOutput()
            return payload
        exploits = ctx.exploit_out.exploits if ctx.exploit_out else []
        post_out = await run_post_exploitation(
            exploits,
            tenant_id=tenant_id,
            scan_id=scan_id,
            scan_options=options,
        )
        ctx.post_out = post_out
        output_data = post_out.model_dump()

    elif phase == ScanPhase.REPORTING:
        record_tool_run("reporting")
        report_out = await run_reporting(
            target,
            ctx.recon_out,
            ctx.threat_out,
            ctx.vuln_out,
            ctx.exploit_out,
            ctx.post_out,
            scan_id=scan_id,
            tenant_id=tenant_id,
            scan_options=options,
            scope_config=scope_context,
            source_analysis=ctx.source_out,
            quick_fuzz=ctx.quick_fuzz_out,
        )
        ctx.report_out = report_out
        output_data = report_out.model_dump()

    else:
        output_data = {}

    return output_data


# ---------------------------------------------------------------------------
# Extracted post-scan finalization
# ---------------------------------------------------------------------------


async def _finalize_scan(
    session: AsyncSession,
    scan_id: str,
    tenant_id: str,
    target: str,
    options: dict,
    ctx: ScanContext,
    subsystems: dict[str, Any],
) -> None:
    """Post-scan: episodic memory, evidence chain, re-verification, notifications, report persist."""
    evidence_chain = subsystems.get("evidence_chain")
    episodic_memory = subsystems.get("episodic_memory")
    cost_tracker = subsystems.get("cost_tracker")

    if episodic_memory is not None:
        try:
            for _f in (ctx.vuln_out.findings or []) if ctx.vuln_out else []:
                _eid = f"ep-{scan_id}-{_f.get('finding_id', _f.get('id', ''))}"
                episodic_memory.store(EpisodicEntry(
                    entry_id=_eid, scan_id=scan_id, tenant_id=tenant_id,
                    finding_type=str(_f.get("vuln_type", _f.get("type", ""))),
                    cwe=str(_f.get("cwe", _f.get("cwe_id", ""))),
                    title=str(_f.get("title", _f.get("name", ""))),
                    description=str(_f.get("description", "")),
                    framework="",
                ))
        except Exception as _em_store_exc:
            logger.warning(
                "episodic_memory_store_failed",
                extra={"scan_id": scan_id, "error": str(_em_store_exc)},
            )

    if evidence_chain is not None:
        try:
            _chain_valid = evidence_chain.verify_chain()
            if not _chain_valid:
                logger.warning("evidence_chain_tamper_detected", extra={"scan_id": scan_id})
        except Exception as _ec_verify_exc:
            logger.warning(
                "evidence_chain_verify_failed",
                extra={"scan_id": scan_id, "error": str(_ec_verify_exc)},
            )

    try:
        _rv_tracker = ReVerificationTracker()
        if options and options.get("auto_reverify") and ctx.exploit_out and (ctx.exploit_out.exploits or []):
            async def _scanner_func(req):
                try:
                    poc_data = {
                        "poc_curl": req.original_payload,
                        "vuln_type": req.original_cwe,
                        "target_url": req.original_endpoint,
                    }
                    verified = await verify_exploit_poc_async(poc_data)
                    return {
                        "vulnerable": verified,
                        "details": f"PoC verification: {'still vulnerable' if verified else 'patched'}",
                    }
                except Exception as _sf_exc:
                    logger.warning(
                        "reverify_scanner_func_failed",
                        extra={
                            "scan_id": scan_id,
                            "exception_type": type(_sf_exc).__name__,
                            "error": str(_sf_exc),
                        },
                    )
                    # Fail safe: an unverifiable PoC is treated as still
                    # vulnerable so a real issue is never silently dropped.
                    # The raw exception is logged above, not returned, to avoid
                    # leaking internals into re-verification details.
                    return {"vulnerable": True, "details": "Verification error"}

            for _rv_exp in (ctx.exploit_out.exploits or [])[:5]:
                if str(_rv_exp.get("severity", "")).lower() in ("critical", "high"):
                    try:
                        _rv_req = ReVerificationRequest(
                            finding_id=str(_rv_exp.get("finding_id", "")),
                            scan_id=scan_id,
                            original_cwe=str(_rv_exp.get("vuln_type", _rv_exp.get("cwe", ""))),
                            original_endpoint=str(_rv_exp.get("target_url", target)),
                            original_payload=str(_rv_exp.get("poc_curl", _rv_exp.get("poc", ""))),
                        )
                        _rv_res = await _rv_tracker.re_verify(_rv_req, scanner_func=_scanner_func)
                        if not _rv_res.still_vulnerable:
                            _rv_exp["re_verified_fixed"] = True
                            logger.info(
                                "re_verification_fixed",
                                extra={"scan_id": scan_id, "finding_id": _rv_req.finding_id},
                            )
                    except Exception as _rv_cand_exc:
                        logger.warning(
                            "re_verification_cand_failed",
                            extra={"scan_id": scan_id, "error": str(_rv_cand_exc)},
                        )
        logger.info("re_verification_tracker_initialized", extra={"scan_id": scan_id})
        if _rv_tracker and _rv_tracker._history:
            try:
                _rv_data = {
                    fid: [
                        {
                            "status": r.status,
                            "still_vulnerable": r.still_vulnerable,
                            "verified_fixed_at": r.verified_fixed_at,
                        }
                        for r in results
                    ]
                    for fid, results in _rv_tracker._history.items()
                }
                if tenant_id and scan_id:
                    _rv_sink = RawPhaseSink(tenant_id, scan_id, "re_verification")
                    await asyncio.to_thread(_rv_sink.upload_text, "re_verification_history", json.dumps(_rv_data, default=str))
            except Exception as _rv_persist_exc:
                logger.warning(
                    "re_verification_persist_failed",
                    extra={"scan_id": scan_id, "error": str(_rv_persist_exc)},
                )
    except Exception as _rv_exc:
        logger.warning(
            "re_verification_init_failed",
            extra={"scan_id": scan_id, "error": str(_rv_exc)},
        )

    if options and options.get("self_pentest_enabled"):
        try:
            _sp_runner = SelfPentestRunner()
            _sp_result = await _sp_runner.run(scan_id=scan_id)
            if _sp_result.findings:
                logger.warning(
                    "self_pentest_findings",
                    extra={"scan_id": scan_id, "count": len(_sp_result.findings)},
                )
                if evidence_chain is not None:
                    for _spf in _sp_result.findings[:10]:
                        try:
                            evidence_chain.add_finding_link(
                                finding_id=f"self-pentest-{_spf.target}",
                                title=_spf.vulnerability,
                                severity=_spf.severity,
                                evidence_tier=2,
                            )
                        except Exception as _sp_ev_exc:
                            logger.warning(
                                "self_pentest_evidence_link_failed",
                                extra={"scan_id": scan_id, "error": str(_sp_ev_exc)},
                            )
            else:
                logger.info(
                    "self_pentest_clean",
                    extra={"scan_id": scan_id, "targets_scanned": _sp_result.targets_scanned},
                )
        except Exception as _sp_exc:
            logger.warning(
                "self_pentest_run_failed",
                extra={"scan_id": scan_id, "error": str(_sp_exc)},
            )

    try:
        _ti_guard = TenantIsolationGuard()
        _ti_guard.register_scan_end(tenant_id)
    except Exception as _ti_end_exc:
        logger.warning(
            "tenant_isolation_end_failed",
            extra={"tenant_id": tenant_id, "error": str(_ti_end_exc)},
        )

    if evidence_chain is not None:
        try:
            _chain_data = evidence_chain.to_dict()
            _chain_json = json.dumps(_chain_data, default=str)
            logger.info(
                "evidence_chain_persisted",
                extra={
                    "scan_id": scan_id,
                    "tenant_id": tenant_id,
                    "link_count": evidence_chain.link_count,
                    "chain_intact": _chain_data.get("chain_intact", False),
                },
            )
            if tenant_id and scan_id:
                try:
                    _sink = RawPhaseSink(tenant_id, scan_id, "evidence_chain")
                    await asyncio.to_thread(_sink.upload_text, "evidence_chain", _chain_json)
                except Exception as _chain_sink_exc:
                    logger.warning(
                        "evidence_chain_minio_upload_failed",
                        extra={"scan_id": scan_id, "error": str(_chain_sink_exc)},
                    )
        except Exception as _chain_persist_exc:
            logger.warning(
                "evidence_chain_persist_failed",
                extra={"scan_id": scan_id, "error": str(_chain_persist_exc)},
            )

    if cost_tracker is not None:
        try:
            _cost_summary = cost_tracker.summary()
            logger.info(
                "cost_tracker_summary",
                extra={
                    "scan_id": scan_id,
                    "total_tokens": _cost_summary.get("total_tokens", 0),
                    "total_cost_usd": _cost_summary.get("total_cost_usd", 0),
                    "budget_remaining_usd": _cost_summary.get("budget_remaining_usd", 0),
                    "phases": list(_cost_summary.get("by_phase", {}).keys()),
                },
            )
        except Exception as _cost_log_exc:
            logger.warning(
                "cost_tracker_summary_failed",
                extra={"scan_id": scan_id, "error": str(_cost_log_exc)},
            )

    try:
        unregister_cost_tracker(scan_id)
    except Exception as _unreg_exc:
        logger.warning(
            "unregister_cost_tracker_failed",
            extra={"scan_id": scan_id, "error": str(_unreg_exc)},
        )

    await _persist_report_and_findings(
        session, tenant_id, scan_id, target,
        ctx.report_out, ctx.vuln_out, ctx.recon_out,
    )

    # Notification dispatch
    try:
        findings_for_notify = list(ctx.vuln_out.findings) if ctx.vuln_out and ctx.vuln_out.findings else []
        _top_sev = "info"
        for _f in findings_for_notify:
            _s = str(_f.get("severity", "")).lower()
            if _s in ("critical", "high", "medium", "low", "info"):
                if (
                    (_s == "critical")
                    or (_s == "high" and _top_sev != "critical")
                    or (_s == "medium" and _top_sev not in ("critical", "high"))
                    or (_s == "low" and _top_sev not in ("critical", "high", "medium"))
                    or (_s == "info" and _top_sev not in ("critical", "high", "medium", "low"))
                ):
                    _top_sev = _s
        _sev_map = {
            "critical": NotificationSeverity.CRITICAL,
            "high": NotificationSeverity.HIGH,
            "medium": NotificationSeverity.MEDIUM,
            "low": NotificationSeverity.LOW,
            "info": NotificationSeverity.INFO,
        }
        _event = NotificationEvent(
            event_type="scan_completed",
            tenant_id=tenant_id,
            scan_id=scan_id,
            target=target,
            severity=_sev_map.get(_top_sev, NotificationSeverity.INFO),
            title=f"Scan completed for {target}",
            message=f"Scan {scan_id} completed. Top severity: {_top_sev}. Findings: {len(findings_for_notify)}.",
            metadata={"findings_count": len(findings_for_notify), "top_severity": _top_sev},
        )
        _notify_dispatcher = NotificationDispatcher(
            adapters=[DiscordNotifier(), GitHubIssuesNotifier()],
            enabled=True,
        )
        await _notify_dispatcher.dispatch(_event)
    except Exception as _notify_exc:
        logger.warning(
            "scan_notification_dispatch_failed",
            extra={"scan_id": scan_id, "error": str(_notify_exc)},
        )

    await _update_scan_phase_status(session, scan_id, "complete", "completed", 100)
    await _record_event(
        session, tenant_id, scan_id, "complete", "complete", 100,
        message="Scan completed",
    )
    post_scan_bundle = await enqueue_generate_all_bundle(
        session,
        tenant_id,
        scan_id,
        list(DEFAULT_GENERATE_ALL_FORMATS),
        set_post_scan_idempotency_flag=True,
    )
    await session.commit()
    if post_scan_bundle:
        b_id, r_ids = post_scan_bundle
        schedule_generate_all_reports_task_safe(tenant_id, scan_id, b_id, r_ids)

    await notify_scan_finished(tenant_id)


# ---------------------------------------------------------------------------
# Refactored main state machine — thin orchestrator
# ---------------------------------------------------------------------------


async def run_scan_state_machine(
    session: AsyncSession,
    scan_id: str,
    tenant_id: str,
    target: str,
    options: dict,
) -> None:
    """
    Execute the full scan pipeline in ``PHASE_ORDER``: source_analysis -> recon ->
    quick_fuzz -> threat_modeling -> vuln_analysis -> exploitation ->
    post_exploitation -> reporting.
    Records scan_steps, scan_events, updates scan.phase/status.
    """
    # 1. Initialize subsystems (non-blocking on failure)
    subsystems = await _init_scan_subsystems(scan_id, tenant_id, target, options)

    clear_tool_availability_cache()

    # 2. Detect resume plan, restore prior outputs
    resume_plan, ctx = await _detect_resume_plan(session, scan_id, options, target)

    # 3. Start heartbeat
    heartbeat_task = asyncio.create_task(
        _heartbeat_loop(session, scan_id, _SCAN_HEARTBEAT_SEC)
    )

    cost_tracker = subsystems.get("cost_tracker")
    evidence_chain = subsystems.get("evidence_chain")
    episodic_memory = subsystems.get("episodic_memory")
    event_bus = subsystems.get("event_bus")

    if is_quick_execution(options):
        _ensure_quick_budget(scan_id, tenant_id, options)

    cancelled = False
    # 4. Phase loop
    for order_index, phase in enumerate(PHASE_ORDER):
        if await scan_row_is_cancelled(session, scan_id):
            await propagate_scan_cancellation(
                scan_id=scan_id,
                tenant_id=tenant_id,
                reason="status_cancelled",
                session=session,
                revoke_workers=False,
            )
            cancelled = True
            break

        if phase in resume_plan and resume_plan.get(phase) == ResumeDecision.SKIP:
            logger.info("Skipping completed phase %s (resume)", phase.value)
            continue

        progress = _phase_to_progress(phase)
        skip_reason = _quick_phase_skip_reason(
            phase,
            scan_id=scan_id,
            options=options,
            resume_decision=resume_plan.get(phase),
        )
        if skip_reason:
            await _persist_quick_phase_skip(
                session=session,
                tenant_id=tenant_id,
                scan_id=scan_id,
                phase=phase,
                ctx=ctx,
                target=target,
                reason=skip_reason,
                order_index=order_index,
                progress=progress,
            )
            continue

        if cost_tracker is not None:
            try:
                _budget_enforcer = BudgetEnforcer(cost_tracker)
                _budget_enforcer.check()
            except Exception as _budget_exc:
                if "BudgetExceeded" in type(_budget_exc).__name__ or "BudgetExceeded" in str(type(_budget_exc)):
                    logger.warning(
                        "scan_budget_exceeded",
                        extra={"scan_id": scan_id, "phase": phase.value, "cost_usd": cost_tracker.total_cost_usd},
                    )
                    break
                logger.warning(
                    "budget_check_non_fatal",
                    extra={"scan_id": scan_id, "phase": phase.value, "error": str(_budget_exc)},
                )

        progress = _phase_to_progress(phase)
        phase_str = phase.value
        phase_start_time = time.monotonic()

        # --- Build auth config & scope context ---
        auth_config_obj = None
        if options:
            try:
                auth_config_obj = TargetConfig.from_scan_options(options)
            except Exception as _ac_exc:
                logger.warning(
                    "auth_config_load_failed",
                    extra={"scan_id": scan_id, "phase": phase_str, "error": str(_ac_exc)},
                )

        scope_context: dict[str, Any] | None = None
        if options and phase in (
            ScanPhase.SOURCE_ANALYSIS, ScanPhase.RECON, ScanPhase.QUICK_FUZZ,
            ScanPhase.THREAT_MODELING, ScanPhase.VULN_ANALYSIS, ScanPhase.EXPLOITATION,
            ScanPhase.POST_EXPLOITATION, ScanPhase.REPORTING,
        ):
            try:
                if auth_config_obj is not None:
                    scope_context = rules_of_engagement_to_prompt_context(auth_config_obj)
            except Exception as _sc_exc:
                logger.warning(
                    "scope_context_failed",
                    extra={"scan_id": scan_id, "error": str(_sc_exc)},
                )

        # --- Build phase input ---
        input_data = await _build_phase_input(
            phase=phase,
            ctx=ctx,
            options=options,
            target=target,
            session=session,
            tenant_id=tenant_id,
            scan_id=scan_id,
            episodic_memory=episodic_memory,
        )

        exec_preflight = attach_execution_mode_to_input(
            input_data,
            options if isinstance(options, dict) else {},
            tenant_id=tenant_id,
            scan_id=scan_id,
            engagement_id=str(options.get("engagement_id")) if options else None,
        )
        logger.info(
            "phase_execution_mode_preflight",
            extra={
                "event": "phase_execution_mode_preflight",
                "scan_id": scan_id,
                "phase": phase_str,
                "mode": exec_preflight.mode,
                "lab_lease_active": exec_preflight.lab_lease_active,
                "reason": exec_preflight.reason,
                "deny_code": exec_preflight.deny_code,
            },
        )

        # LAB without usable lease (missing / kill-switched / expired) — fail closed.
        if exec_preflight.deny_code and not exec_preflight.lab_lease_active:
            await _update_scan_phase_status(session, scan_id, phase_str, "failed", progress)
            await _record_event(
                session, tenant_id, scan_id, "progress", phase_str, progress,
                message="LAB mode requires a usable execution lease",
                data={
                    "code": "lab_lease_required",
                    "deny_code": exec_preflight.deny_code,
                    "reason": exec_preflight.reason,
                },
            )
            await session.commit()
            raise LabLeaseRequiredError(
                exec_preflight.reason or "lab_lease_required"
            )

        # Inject dynamic auth_config & scope_context into input_data
        if auth_config_obj:
            if phase == ScanPhase.EXPLOITATION:
                input_data["auth_config"] = auth_config_obj.model_dump() if hasattr(auth_config_obj, "model_dump") else None
        if phase == ScanPhase.REPORTING:
            input_data["scope_config"] = scope_context

        # --- Policy gate: exploitation approval ---
        if phase == ScanPhase.EXPLOITATION:
            needs_approval = await _check_exploitation_approval_required(
                session, tenant_id, scan_id, options
            )
            if needs_approval:
                await _update_scan_phase_status(session, scan_id, phase_str, "awaiting_approval", progress)
                await _record_event(
                    session, tenant_id, scan_id, "progress", phase_str, progress,
                    message="Exploitation requires approval",
                    data={"code": "approval_required"},
                )
                await session.commit()
                raise ExploitationApprovalRequiredError(
                    "Exploitation phase requires approval per policy"
                )

        # --- Record scan step ---
        step = await _record_step(session, tenant_id, scan_id, phase, "running", order_index)

        # --- Execute the phase ---
        output_data = await _execute_phase(
            phase=phase,
            ctx=ctx,
            input_data=input_data,
            subsystems=subsystems,
            session=session,
            scan_id=scan_id,
            tenant_id=tenant_id,
            target=target,
            options=options,
            step=step,
            progress=progress,
            heartbeat_task=heartbeat_task,
            order_index=order_index,
            cost_tracker=cost_tracker,
            event_bus=event_bus,
            auth_config_obj=auth_config_obj,
            scope_context=scope_context,
        )

        # --- Post-phase: duration, evidence chain, persistence ---
        phase_duration = time.monotonic() - phase_start_time
        record_phase_duration(phase_str, phase_duration)

        if evidence_chain is not None:
            try:
                if phase == ScanPhase.VULN_ANALYSIS and ctx.vuln_out:
                    for _f in (ctx.vuln_out.findings or [])[:20]:
                        fid = str(_f.get("finding_id", _f.get("id", "")))
                        evidence_chain.add_finding_link(
                            finding_id=fid,
                            title=str(_f.get("title", _f.get("name", ""))),
                            severity=str(_f.get("severity", "info")),
                            evidence_tier=int(_f.get("evidence_tier", 0)),
                        )
                elif phase == ScanPhase.EXPLOITATION and ctx.exploit_out:
                    for _e in (ctx.exploit_out.exploits or [])[:20]:
                        fid = str(_e.get("finding_id", _e.get("id", "")))
                        poc = str(_e.get("poc_curl", _e.get("poc", "")))
                        if poc:
                            evidence_chain.add_poc_link(
                                finding_id=fid,
                                poc_type="curl",
                                poc_hash=evidence_chain._hash_content(poc),
                            )
                elif phase == ScanPhase.REPORTING and ctx.report_out:
                    evidence_chain.add_remediation_link(
                        scan_id=scan_id, description="Report generated"
                    )
            except Exception as _ec_link_exc:
                logger.warning(
                    "evidence_chain_link_failed",
                    extra={"scan_id": scan_id, "phase": phase_str, "error": str(_ec_link_exc)},
                )

        await _persist_phase_output(session, tenant_id, scan_id, phase_str, output_data)
        if phase in (ScanPhase.RECON, ScanPhase.QUICK_FUZZ, ScanPhase.VULN_ANALYSIS, ScanPhase.POST_EXPLOITATION):
            await _upload_raw_phase_snapshot(tenant_id, scan_id, phase_str, "phase_output_final", output_data)
            await _upload_raw_phase_snapshot(
                tenant_id, scan_id, phase_str, "phase_execution_summary",
                {"phase": phase_str, "order_index": order_index, "duration_seconds": round(phase_duration, 2)},
            )
        await _record_timeline_entry(
            session, tenant_id, scan_id, phase_str, order_index,
            {"phase": phase_str, "output": output_data, "duration_seconds": round(phase_duration, 2)},
        )
        await _record_event(
            session, tenant_id, scan_id, "phase_complete", phase_str, progress,
            message=f"Completed {phase_str}", data=output_data,
        )
        logger.info(
            "Phase completed",
            extra={
                "event_type": "phase_complete",
                "phase": phase_str,
                "scan_id": scan_id,
                "duration_seconds": round(phase_duration, 2),
            },
        )
        await session.execute(
            update(ScanStep)
            .where(cast(ScanStep.id, String) == step.id)
            .values(status="completed")
        )
        await session.commit()

    # 5. Heartbeat cleanup
    heartbeat_task.cancel()
    with suppress(asyncio.CancelledError):
        await heartbeat_task

    if cancelled or await scan_row_is_cancelled(session, scan_id):
        raise ScanCancelledError(scan_id)

    # 6. Finalize scan (deadline still publishes the report)
    await _finalize_scan(session, scan_id, tenant_id, target, options, ctx, subsystems)
