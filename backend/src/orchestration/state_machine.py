"""ScanStateMachine — transitions between phases, DB recording."""

import asyncio
import json
import logging
import time
import uuid
from contextlib import suppress

from sqlalchemy import String, cast, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas import DEFAULT_GENERATE_ALL_FORMATS, ReportSummary
from src.owasp_top10_2025 import parse_owasp_category
from src.reports.finding_metadata import (
    clip_optional_text,
    normalize_confidence,
    normalize_evidence_refs,
    normalize_evidence_type,
)
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
from src.recon.recon_runtime import build_recon_runtime_config
from src.recon.step_registry import plan_recon_steps
from src.recon.vulnerability_analysis.finding_stable_id import (
    assign_stable_finding_ids,
    compute_stable_finding_id,
)
from src.orchestration.aggressive_exploit_tools import maybe_run_aggressive_exploit_tools
from src.storage.s3 import upload_finding_poc_json
from src.orchestration.handlers import (
    run_exploit_attempt,
    run_exploit_verify,
    run_post_exploitation,
    run_quick_fuzz,
    run_recon,
    run_reporting,
    run_threat_modeling,
    run_vuln_analysis,
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
from src.orchestration.exploitation_queue import ExploitationQueue
from src.orchestration.phase_resume import (
    ResumeDecision,
    compute_resume_plan,
    get_completed_phases,
    restore_phase_context,
)
from src.orchestration.raw_phase_artifacts import RawPhaseSink
from src.reports.bundle_enqueue import (
    enqueue_generate_all_bundle,
    schedule_generate_all_reports_task_safe,
)

logger = logging.getLogger(__name__)

_SCAN_HEARTBEAT_SEC = 30


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


class ExploitationApprovalRequiredError(Exception):
    """Raised when exploitation phase requires approval and scan is not approved."""


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
) -> bool:
    """
    Check if exploitation phase requires approval per tenant policy.
    Returns True if approval is required and scan is not yet approved.
    """
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
        from src.findings.cvss_auto_score import CVSSAutoScorer
        _cvss_scorer = CVSSAutoScorer()
        _cvss_scorer.score_all_findings(findings_raw)
    except Exception as _cvss_exc:
        logger.debug("cvss_auto_score_failed", extra={"scan_id": scan_id, "error": str(_cvss_exc)})

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


async def run_scan_state_machine(
    session: AsyncSession,
    scan_id: str,
    tenant_id: str,
    target: str,
    options: dict,
) -> None:
    """
    Execute full scan pipeline: recon -> threat_modeling -> vuln_analysis ->
    exploitation -> post_exploitation -> reporting.
    Records scan_steps, scan_events, updates scan.phase/status.
    """
    source_out: SourceAnalysisOutput | None = None
    recon_out: ReconOutput | None = None
    quick_fuzz_out: QuickFuzzOutput | None = None
    threat_out: ThreatModelOutput | None = None
    vuln_out: VulnAnalysisOutput | None = None
    exploit_out: ExploitationOutput | None = None
    post_out: PostExploitationOutput | None = None

    report_out: ReportingOutput | None = None

    evidence_chain = None
    try:
        from src.orchestration.evidence_chain import EvidenceChain as _EC
        evidence_chain = _EC(scan_id=scan_id, tenant_id=tenant_id)
        evidence_chain.add_scan_link(target_url=target)
    except Exception as _ec_exc:
        logger.warning("evidence_chain_init_failed", extra={"scan_id": scan_id, "error": str(_ec_exc)})

    episodic_memory = None
    try:
        from src.orchestration.episodic_memory import EpisodicMemory as _EM
        episodic_memory = _EM()
    except Exception as _em_exc:
        logger.warning("episodic_memory_init_failed", extra={"scan_id": scan_id, "error": str(_em_exc)})

    cost_tracker = None
    try:
        from src.orchestration.cost_aware_reasoning import CostTracker, BudgetEnforcer
        _max_cost = float(options.get("max_cost_usd", 50.0)) if options else 50.0
        _max_tokens = int(options.get("max_tokens", 2000000)) if options else 2000000
        cost_tracker = CostTracker(scan_id=scan_id, max_cost_usd=_max_cost, max_total_tokens=_max_tokens)
    except Exception as _cr_exc:
        logger.warning("cost_tracker_init_failed", extra={"scan_id": scan_id, "error": str(_cr_exc)})

    if cost_tracker is not None:
        try:
            from src.orchestration.cost_aware_reasoning import register_cost_tracker
            register_cost_tracker(cost_tracker)
        except Exception:
            pass

    try:
        from src.orchestration.tenant_isolation import TenantIsolationGuard
        _guard = TenantIsolationGuard()
        if not _guard.can_start_scan(tenant_id):
            logger.warning("tenant_scan_limit_reached", extra={"tenant_id": tenant_id})
        else:
            _guard.register_scan_start(tenant_id)
    except Exception as _ti_exc:
        logger.warning("tenant_isolation_init_failed", extra={"tenant_id": tenant_id, "error": str(_ti_exc)})

    event_bus = None
    try:
        from src.orchestration.scan_events import ScanEventBus, ScanEvent
        event_bus = ScanEventBus()
    except Exception as _se_exc:
        logger.warning("scan_events_init_failed", extra={"scan_id": scan_id, "error": str(_se_exc)})

    from src.recon.sandbox_tool_runner import clear_tool_availability_cache

    clear_tool_availability_cache()

    from src.orchestration.phase_resume import freeze_scan_scope
    with suppress(Exception):
        await freeze_scan_scope(
            session, scan_id,
            vuln_classes=options.get("vuln_classes") if options else None,
            exploit_enabled=options.get("exploit_enabled", True) if options else True,
            target_url=target,
        )

    completed_phases = await get_completed_phases(session, scan_id)
    resume_plan = compute_resume_plan(completed_phases)

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
                    source_out = SourceAnalysisOutput.model_validate(restored)
                except Exception:
                    pass
            elif restored_phase == ScanPhase.RECON:
                try:
                    recon_out = ReconOutput.model_validate(restored)
                except Exception:
                    pass
            elif restored_phase == ScanPhase.QUICK_FUZZ:
                try:
                    quick_fuzz_out = QuickFuzzOutput.model_validate(restored)
                except Exception:
                    pass
            elif restored_phase == ScanPhase.THREAT_MODELING:
                try:
                    threat_out = ThreatModelOutput.model_validate(restored)
                except Exception:
                    pass
            elif restored_phase == ScanPhase.VULN_ANALYSIS:
                try:
                    vuln_out = VulnAnalysisOutput.model_validate(restored)
                except Exception:
                    pass
            elif restored_phase == ScanPhase.EXPLOITATION:
                try:
                    exploit_out = ExploitationOutput.model_validate(restored)
                except Exception:
                    pass
            elif restored_phase == ScanPhase.POST_EXPLOITATION:
                try:
                    post_out = PostExploitationOutput.model_validate(restored)
                except Exception:
                    pass

    heartbeat_task = asyncio.create_task(
        _heartbeat_loop(session, scan_id, _SCAN_HEARTBEAT_SEC)
    )

    for order_index, phase in enumerate(PHASE_ORDER):
        if phase in completed_phases and resume_plan.get(phase) == ResumeDecision.SKIP:
            logger.info("Skipping completed phase %s (resume)", phase.value)
            continue

        if cost_tracker is not None:
            try:
                from src.orchestration.cost_aware_reasoning import BudgetEnforcer
                _budget_enforcer = BudgetEnforcer(cost_tracker)
                _budget_enforcer.check()
            except Exception as _budget_exc:
                if "BudgetExceededError" in type(_budget_exc).__name__ or "BudgetExceeded" in str(type(_budget_exc)):
                    logger.warning("scan_budget_exceeded", extra={"scan_id": scan_id, "phase": phase.value, "cost_usd": cost_tracker.total_cost_usd})
                    break
                logger.debug("budget_check_non_fatal", extra={"error": str(_budget_exc)})

        progress = _phase_to_progress(phase)
        phase_str = phase.value
        phase_start_time = time.monotonic()

        # Build phase input and persist
        _auth_config_obj = None
        if options:
            try:
                from src.orchestration.auth_config import TargetConfig as _TC
                _auth_config_obj = _TC.from_scan_options(options)
            except Exception as _ac_exc:
                logger.debug("auth_config_load_failed", extra={"scan_id": scan_id, "phase": phase_str, "error": str(_ac_exc)})

        _scope_context = ""
        if options and phase in (
            ScanPhase.SOURCE_ANALYSIS,
            ScanPhase.RECON,
            ScanPhase.QUICK_FUZZ,
            ScanPhase.THREAT_MODELING,
            ScanPhase.VULN_ANALYSIS,
            ScanPhase.EXPLOITATION,
            ScanPhase.POST_EXPLOITATION,
            ScanPhase.REPORTING,
        ):
            try:
                from src.orchestration.scope_integration import rules_of_engagement_to_prompt_context
                if _auth_config_obj is not None:
                    _scope_context = rules_of_engagement_to_prompt_context(_auth_config_obj)
            except Exception as _sc_exc:
                logger.debug("scope_context_failed", extra={"scan_id": scan_id, "error": str(_sc_exc)})

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
                "source_analysis": source_out.model_dump() if source_out and not source_out.skipped else None,
            }
        elif phase == ScanPhase.QUICK_FUZZ:
            input_data = {
                "target": target,
                "recon_output": recon_out.model_dump() if recon_out else None,
                "options": options,
            }
        elif phase == ScanPhase.THREAT_MODELING:
            input_data = {
                "assets": recon_out.assets if recon_out else [],
                "source_analysis": source_out.model_dump() if source_out and not source_out.skipped else None,
                "quick_fuzz_findings": quick_fuzz_out.findings if quick_fuzz_out else [],
                "quick_fuzz_candidates": quick_fuzz_out.candidates if quick_fuzz_out else [],
            }
        elif phase == ScanPhase.VULN_ANALYSIS:
            input_data = {
                "threat_model": threat_out.threat_model if threat_out else {},
                "assets": recon_out.assets if recon_out else [],
            }
            if quick_fuzz_out and quick_fuzz_out.candidates:
                input_data["quick_fuzz_candidates"] = quick_fuzz_out.candidates
            if source_out and not source_out.skipped:
                try:
                    input_data["source_analysis"] = source_out.model_dump()
                except Exception as _sa_exc:
                    logger.debug("source_analysis_data_failed", extra={"scan_id": scan_id, "error": str(_sa_exc)})
            if episodic_memory is not None:
                try:
                    _mem_ctx = episodic_memory.build_context_prompt(
                        f"vuln_analysis {target}", max_entries=3
                    )
                    input_data["memory_context"] = _mem_ctx
                except Exception as _mem_exc:
                    logger.debug("episodic_memory_recall_failed", extra={"scan_id": scan_id, "error": str(_mem_exc)})
        elif phase == ScanPhase.EXPLOITATION:
            input_data = {
                "findings": vuln_out.findings if vuln_out else [],
                "auth_config": _auth_config_obj.model_dump() if _auth_config_obj else None,
            }
        elif phase == ScanPhase.POST_EXPLOITATION:
            input_data = {
                "exploits": exploit_out.exploits if exploit_out else [],
                "evidence": exploit_out.evidence if exploit_out else [],
                "evidence_tiers": {k: int(v) if hasattr(v, '__int__') else v for k, v in (exploit_out.evidence_tiers or {}).items()} if exploit_out else {},
            }
        elif phase == ScanPhase.REPORTING:
            input_data = {
                "target": target,
                "recon": recon_out.model_dump() if recon_out else None,
                "threat_model": threat_out.model_dump() if threat_out else None,
                "vuln_analysis": vuln_out.model_dump() if vuln_out else None,
                "exploitation": exploit_out.model_dump() if exploit_out else None,
                "post_exploitation": post_out.model_dump() if post_out else None,
                "scope_config": _scope_context,
                "source_analysis": source_out.model_dump() if source_out else None,
                "quick_fuzz": quick_fuzz_out.model_dump() if quick_fuzz_out else None,
            }
        else:
            input_data = {}
        await _persist_phase_input(session, tenant_id, scan_id, phase_str, input_data)
        if phase == ScanPhase.RECON:
            await _upload_raw_phase_snapshot(
                tenant_id, scan_id, "recon", "phase_input", input_data
            )
        elif phase == ScanPhase.QUICK_FUZZ:
            await _upload_raw_phase_snapshot(
                tenant_id, scan_id, "quick_fuzz", "phase_input", input_data
            )
        elif phase == ScanPhase.VULN_ANALYSIS:
            await _upload_raw_phase_snapshot(
                tenant_id, scan_id, "vuln_analysis", "phase_input", input_data
            )
        elif phase == ScanPhase.POST_EXPLOITATION:
            await _upload_raw_phase_snapshot(
                tenant_id, scan_id, "post_exploitation", "phase_input", input_data
            )

        # Policy gate: exploitation requires approval
        if phase == ScanPhase.EXPLOITATION:
            needs_approval = await _check_exploitation_approval_required(
                session, tenant_id, scan_id
            )
            if needs_approval:
                await _update_scan_phase_status(
                    session, scan_id, phase_str, "awaiting_approval", progress
                )
                await _record_event(
                    session,
                    tenant_id,
                    scan_id,
                    "progress",
                    phase_str,
                    progress,
                    message="Exploitation requires approval",
                    data={"code": "approval_required"},
                )
                await session.commit()
                raise ExploitationApprovalRequiredError(
                    "Exploitation phase requires approval per policy"
                )

        step = await _record_step(
            session, tenant_id, scan_id, phase, "running", order_index
        )
        await _record_event(
            session,
            tenant_id,
            scan_id,
            "phase_start",
            phase_str,
            progress,
            message=f"Starting {phase_str}",
        )
        if event_bus is not None:
            try:
                from src.orchestration.scan_events import ScanEvent as _SE
                event_bus.publish(_SE(event_type="phase_start", scan_id=scan_id, tenant_id=tenant_id, phase=phase_str, progress=progress, message=f"Starting {phase_str}"))
            except Exception:
                pass
        await _record_event(
            session,
            tenant_id,
            scan_id,
            "progress",
            phase_str,
            progress,
            message=f"Progress {progress}%",
        )
        await _update_scan_phase_status(
            session, scan_id, phase_str, "running", progress
        )
        await session.commit()

        logger.info(
            "Phase started",
            extra={"event_type": "phase_start", "phase": phase_str, "scan_id": scan_id},
        )

        try:
            with trace_phase(scan_id, phase_str):
                if phase == ScanPhase.SOURCE_ANALYSIS:
                    try:
                        from src.orchestration.handlers import run_source_analysis
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
                    if source_out and not source_out.skipped:
                        try:
                            from src.orchestration.binary_analysis import detect_binary_type, run_binary_analysis, BinaryAnalysisRequest
                            _sa_dict = source_out.model_dump() if hasattr(source_out, "model_dump") else {}
                            _code_files = _sa_dict.get("code_files", []) or []
                            _binary_types = []
                            for _cf in _code_files:
                                _path = str(_cf.get("path", _cf)) if isinstance(_cf, dict) else str(_cf)
                                _btype = detect_binary_type(_path)
                                if _btype != "unknown":
                                    _binary_types.append({"file": _path, "type": _btype})
                            if _binary_types:
                                logger.info("binary_analysis_detected", extra={"scan_id": scan_id, "binaries": len(_binary_types)})
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
                                        _ba_result = await run_binary_analysis(_ba_req, use_sandbox=bool(settings.sandbox_enabled))
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
                                            logger.info("binary_analysis_vulns_found", extra={"scan_id": scan_id, "file": _bi["file"], "vulns": len(_ba_result.vulnerabilities)})
                                        elif _ba_result and _ba_result.strings:
                                            logger.info("binary_analysis_strings_extracted", extra={"scan_id": scan_id, "file": _bi["file"], "strings": len(_ba_result.strings)})
                                        else:
                                            logger.info("binary_analysis_no_results", extra={"scan_id": scan_id, "file": _bi["file"]})
                                    except Exception as _ba_run_exc:
                                        logger.debug("binary_analysis_run_failed", extra={"scan_id": scan_id, "file": _bi["file"], "error": str(_ba_run_exc)})
                        except Exception as _ba_exc:
                            logger.debug("binary_analysis_failed", extra={"scan_id": scan_id, "error": str(_ba_exc)})
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
                        source_analysis=source_out,
                    )
                    output_data = recon_out.model_dump()
                elif phase == ScanPhase.QUICK_FUZZ:
                    record_tool_run("quick_fuzz")
                    quick_fuzz_out = await run_quick_fuzz(
                        target,
                        recon_output=recon_out.model_dump() if recon_out else None,
                        options=options,
                        tenant_id=tenant_id,
                        scan_id=scan_id,
                    )
                    output_data = quick_fuzz_out.model_dump()
                elif phase == ScanPhase.THREAT_MODELING:
                    record_tool_run("threat_modeling")
                    assets = recon_out.assets if recon_out else []
                    threat_out = await run_threat_modeling(
                        assets,
                        subdomains=recon_out.subdomains if recon_out else None,
                        ports=recon_out.ports if recon_out else None,
                        target=target,
                        scan_id=scan_id,
                        source_analysis=source_out,
                    )
                    output_data = threat_out.model_dump()
                elif phase == ScanPhase.VULN_ANALYSIS:
                    record_tool_run("vuln_analysis")
                    tm = threat_out.threat_model if threat_out else {}
                    assets = recon_out.assets if recon_out else []
                    # OWASP-003: pass target + tenant_id + scan_id so VA active scan and raw sinks work.
                    # Active scan runs inside handlers.run_vuln_analysis when SANDBOX_ENABLED=true (do not call
                    # run_va_active_scan_phase from state_machine).
                    vuln_out = await run_vuln_analysis(
                        tm,
                        assets,
                        target=target,
                        tenant_id=tenant_id,
                        scan_id=scan_id,
                        scan_options=options,
                        recon_context=recon_out.tool_results if recon_out else None,
                        source_analysis=source_out,
                        quick_fuzz_candidates=quick_fuzz_out.candidates if quick_fuzz_out else None,
                    )
                    output_data = vuln_out.model_dump()
                elif phase == ScanPhase.EXPLOITATION:
                    findings = vuln_out.findings if vuln_out else []

                    try:
                        from src.orchestration.exploitation_queue import ExploitationQueue as _EQ, ExploitHypothesis as _EH
                        exploitation_queue = _EQ.from_vuln_analysis_output(vuln_out)
                        # Merge CWE-agent hypotheses into the queue
                        for _hyp_dict in (vuln_out.hypotheses or []):
                            try:
                                _hyp = _EH(
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
                            except Exception:
                                pass
                        structured_findings = exploitation_queue.to_exploitation_input()
                        logger.info(
                            "ExploitationQueue: %d hypotheses for %s",
                            len(exploitation_queue.hypotheses),
                            scan_id,
                        )
                    except Exception as eq_exc:
                        logger.debug("ExploitationQueue build failed, using raw findings: %s", eq_exc)
                        structured_findings = None

                    try:
                        from src.orchestration.auth_config import TargetConfig as _TC
                        auth_config_obj = _TC.from_scan_options(options) if options else None
                    except Exception:
                        auth_config_obj = None

                    maybe_run_aggressive_exploit_tools(
                        findings,
                        tenant_id,
                        scan_id,
                        target,
                        scan_approval_flags=_scan_approval_flags_from_options(options),
                    )
                    await _record_event(
                        session,
                        tenant_id,
                        scan_id,
                        "tool_run",
                        phase_str,
                        progress,
                        message=f"Running {ExploitationSubPhase.EXPLOIT_ATTEMPT.value}",
                        data={"tool": ExploitationSubPhase.EXPLOIT_ATTEMPT.value},
                    )
                    record_tool_run(ExploitationSubPhase.EXPLOIT_ATTEMPT.value)
                    await session.commit()

                    _ewp = None
                    if options and options.get("ephemeral_workers"):
                        try:
                            from src.orchestration.ephemeral_worker import EphemeralWorkerPool, ContainerSpec
                            _ewp = EphemeralWorkerPool(max_containers=options.get("max_ephemeral_containers", 5))
                            logger.info("ephemeral_worker_pool_active", extra={"scan_id": scan_id, "max": _ewp._max_containers})
                        except Exception as _ewp_exc:
                            logger.warning("ephemeral_worker_pool_init_failed: %s", _ewp_exc)

                    _auth_config_dict = None
                    try:
                        if auth_config_obj and hasattr(auth_config_obj, "model_dump"):
                            _auth_config_dict = auth_config_obj.model_dump()
                        elif auth_config_obj and isinstance(auth_config_obj, dict):
                            _auth_config_dict = auth_config_obj
                    except Exception:
                        pass

                    _exploitation_findings = findings
                    try:
                        if structured_findings and isinstance(structured_findings, dict):
                            _exploitation_findings = structured_findings.get("findings", findings)
                            logger.info(
                                "Using structured_findings from ExploitationQueue (%d hypotheses)",
                                len(_exploitation_findings),
                                extra={"scan_id": scan_id},
                            )
                    except Exception:
                        pass

                    attempt_out = await run_exploit_attempt(
                        _exploitation_findings, scan_id=scan_id, target=target, tenant_id=tenant_id,
                        auth_config=_auth_config_dict,
                    )
                    await _record_event(
                        session,
                        tenant_id,
                        scan_id,
                        "progress",
                        phase_str,
                        progress,
                        message=f"Completed {ExploitationSubPhase.EXPLOIT_ATTEMPT.value}",
                        data={"tool": ExploitationSubPhase.EXPLOIT_ATTEMPT.value},
                    )
                    await _record_event(
                        session,
                        tenant_id,
                        scan_id,
                        "tool_run",
                        phase_str,
                        progress,
                        message=f"Running {ExploitationSubPhase.EXPLOIT_VERIFY.value}",
                        data={"tool": ExploitationSubPhase.EXPLOIT_VERIFY.value},
                    )
                    record_tool_run(ExploitationSubPhase.EXPLOIT_VERIFY.value)
                    await session.commit()
                    exploit_out = await run_exploit_verify(attempt_out)
                    try:
                        from src.orchestration.exploit_verification_microvm import ExploitVerificationMicroVM as _MicroVM, VerificationRequest as _VR
                        _microvm = _MicroVM()
                        for _cand in (exploit_out.exploits or []):
                            if str(_cand.get("severity", "")).lower() in ("critical", "high"):
                                try:
                                    _vr = _VR(
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
                                    logger.debug("microvm_verify_cand_failed", extra={"scan_id": scan_id, "error": str(_vm_cand_exc)})
                    except Exception as _vm_exc:
                        logger.warning("microvm_verification_failed", extra={"scan_id": scan_id, "error": str(_vm_exc)})
                    if _ewp is not None:
                        try:
                            for _ecand in (exploit_out.exploits or [])[:3]:
                                if str(_ecand.get("severity", "")).lower() in ("critical", "high"):
                                    _container_id = await _ewp.acquire(
                                        f"exploit-{scan_id[:12]}-{_ecand.get('finding_id', 'unk')[:8]}",
                                    )
                                    if _container_id:
                                        logger.info("ephemeral_worker_acquired", extra={"scan_id": scan_id, "container": _container_id, "finding": str(_ecand.get("finding_id", ""))})
                                        try:
                                            _artifacts = await _ewp.collect_artifacts(_container_id, scan_id, "exploit_verify", str(_ecand.get("finding_id", "")))
                                            if _artifacts:
                                                _ecand["ephemeral_artifacts"] = _artifacts
                                        except Exception:
                                            pass
                                        finally:
                                            await _ewp.release(_container_id)
                        except Exception as _ewp_dispatch_exc:
                            logger.debug("ephemeral_worker_dispatch_failed: %s", _ewp_dispatch_exc)
                        try:
                            await _ewp.prune_stale()
                            logger.info("ephemeral_worker_pool_cleanup", extra={"scan_id": scan_id, "active": _ewp.active_count})
                        except Exception as _ewp_clean_exc:
                            logger.debug("ephemeral_cleanup_failed: %s", _ewp_clean_exc)
                    try:
                        from src.orchestration.poc_watermarking import stamp_payload
                        _wm_secret = options.get("watermark_secret", "argus-default-wm-key") if options else "argus-default-wm-key"
                        for _exploit in (exploit_out.exploits or []):
                            _poc = _exploit.get("poc_curl", _exploit.get("poc", ""))
                            if _poc and not _poc.startswith("# ARGUS-WM"):
                                _exploit["poc_curl"] = stamp_payload(
                                    _poc, scan_id=scan_id, tenant_id=tenant_id, secret_key=_wm_secret
                                )
                    except Exception as _wm_exc:
                        logger.warning("poc_watermarking_failed", extra={"scan_id": scan_id, "error": str(_wm_exc)})
                    await _record_event(
                        session,
                        tenant_id,
                        scan_id,
                        "progress",
                        phase_str,
                        progress,
                        message=f"Completed {ExploitationSubPhase.EXPLOIT_VERIFY.value}",
                        data={"tool": ExploitationSubPhase.EXPLOIT_VERIFY.value},
                    )
                    output_data = exploit_out.model_dump()
                elif phase == ScanPhase.POST_EXPLOITATION:
                    exploits = exploit_out.exploits if exploit_out else []
                    post_out = await run_post_exploitation(
                        exploits, tenant_id=tenant_id, scan_id=scan_id
                    )
                    output_data = post_out.model_dump()
                elif phase == ScanPhase.REPORTING:
                    record_tool_run("reporting")
                    report_out = await run_reporting(
                        target,
                        recon_out,
                        threat_out,
                        vuln_out,
                        exploit_out,
                        post_out,
                        scan_id=scan_id,
                        scan_options=options,
                        scope_config=_scope_context,
                        source_analysis=source_out,
                        quick_fuzz=quick_fuzz_out,
                    )
                    output_data = report_out.model_dump()
                else:
                    output_data = {}
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
                extra={"event_type": "phase_error", "phase": phase_str, "scan_id": scan_id},
            )
            err_message = "Phase failed"
            err_data: dict[str, str] = {"code": "phase_error"}
            if isinstance(exc, RuntimeError):
                etext = str(exc)
                if etext.startswith("LLM provider required"):
                    err_message = etext
                    err_data = {"code": "llm_required"}
            await _record_event(
                session,
                tenant_id,
                scan_id,
                "error",
                phase_str,
                progress,
                message=err_message,
                data=err_data,
            )
            await _update_scan_phase_status(
                session, scan_id, phase_str, "failed", progress
            )
            await session.commit()
            raise

        phase_duration = time.monotonic() - phase_start_time
        record_phase_duration(phase_str, phase_duration)

        if evidence_chain is not None:
            try:
                if phase == ScanPhase.VULN_ANALYSIS and vuln_out:
                    for _f in (vuln_out.findings or [])[:20]:
                        fid = str(_f.get("finding_id", _f.get("id", "")))
                        evidence_chain.add_finding_link(
                            finding_id=fid,
                            title=str(_f.get("title", _f.get("name", ""))),
                            severity=str(_f.get("severity", "info")),
                            evidence_tier=int(_f.get("evidence_tier", 0)),
                        )
                elif phase == ScanPhase.EXPLOITATION and exploit_out:
                    for _e in (exploit_out.exploits or [])[:20]:
                        fid = str(_e.get("finding_id", _e.get("id", "")))
                        poc = str(_e.get("poc_curl", _e.get("poc", "")))
                        if poc:
                            evidence_chain.add_poc_link(
                                finding_id=fid,
                                poc_type="curl",
                                poc_hash=evidence_chain._hash_content(poc),
                            )
                elif phase == ScanPhase.REPORTING and report_out:
                    evidence_chain.add_remediation_link(
                        scan_id=scan_id, description="Report generated"
                    )
            except Exception:
                pass

        await _persist_phase_output(
            session, tenant_id, scan_id, phase_str, output_data
        )
        if phase in (ScanPhase.RECON, ScanPhase.QUICK_FUZZ, ScanPhase.VULN_ANALYSIS, ScanPhase.POST_EXPLOITATION):
            await _upload_raw_phase_snapshot(
                tenant_id, scan_id, phase_str, "phase_output_final", output_data
            )
            await _upload_raw_phase_snapshot(
                tenant_id,
                scan_id,
                phase_str,
                "phase_execution_summary",
                {
                    "phase": phase_str,
                    "order_index": order_index,
                    "duration_seconds": round(phase_duration, 2),
                },
            )
        await _record_timeline_entry(
            session,
            tenant_id,
            scan_id,
            phase_str,
            order_index,
            {"phase": phase_str, "output": output_data, "duration_seconds": round(phase_duration, 2)},
        )

        await _record_event(
            session,
            tenant_id,
            scan_id,
            "phase_complete",
            phase_str,
            progress,
            message=f"Completed {phase_str}",
            data=output_data,
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

    heartbeat_task.cancel()
    with suppress(asyncio.CancelledError):
        await heartbeat_task

    if episodic_memory is not None:
        try:
            from src.orchestration.episodic_memory import EpisodicEntry
            for _f in (vuln_out.findings or []) if vuln_out else []:
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
            logger.warning("episodic_memory_store_failed", extra={"scan_id": scan_id, "error": str(_em_store_exc)})

    if evidence_chain is not None:
        try:
            _chain_valid = evidence_chain.verify_chain()
            if not _chain_valid:
                logger.warning("evidence_chain_tamper_detected", extra={"scan_id": scan_id})
        except Exception as _ec_verify_exc:
            logger.warning("evidence_chain_verify_failed", extra={"scan_id": scan_id, "error": str(_ec_verify_exc)})

    try:
        from src.orchestration.re_verification import ReVerificationTracker, ReVerificationRequest
        _rv_tracker = ReVerificationTracker()
        if options and options.get("auto_reverify") and exploit_out and (exploit_out.exploits or []):
            async def _scanner_func(req):
                try:
                    from src.orchestration.exploit_verify import verify_exploit_poc_async
                    poc_data = {"poc_curl": req.original_payload, "vuln_type": req.original_cwe, "target_url": req.original_endpoint}
                    verified = await verify_exploit_poc_async(poc_data)
                    return {"vulnerable": verified, "details": f"PoC verification: {'still vulnerable' if verified else 'patched'}"}
                except Exception as _sf_exc:
                    return {"vulnerable": True, "details": f"Verification error: {_sf_exc}"}

            for _rv_exp in (exploit_out.exploits or [])[:5]:
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
                            logger.info("re_verification_fixed", extra={"scan_id": scan_id, "finding_id": _rv_req.finding_id})
                    except Exception as _rv_cand_exc:
                        logger.debug("re_verification_cand_failed", extra={"error": str(_rv_cand_exc)})
        logger.info("re_verification_tracker_initialized", extra={"scan_id": scan_id})
        if _rv_tracker and _rv_tracker._history:
            try:
                import json as _rv_json
                _rv_data = {fid: [{"status": r.status, "still_vulnerable": r.still_vulnerable, "verified_fixed_at": r.verified_fixed_at} for r in results] for fid, results in _rv_tracker._history.items()}
                if tenant_id and scan_id:
                    from src.orchestration.raw_phase_artifacts import RawPhaseSink as _RPS_rv
                    _rv_sink = _RPS_rv(tenant_id, scan_id, "re_verification")
                    await asyncio.to_thread(_rv_sink.upload_text, "re_verification_history", _rv_json.dumps(_rv_data, default=str))
            except Exception as _rv_persist_exc:
                logger.debug("re_verification_persist_failed", extra={"error": str(_rv_persist_exc)})
    except Exception as _rv_exc:
        logger.warning("re_verification_init_failed", extra={"scan_id": scan_id, "error": str(_rv_exc)})

    if options and options.get("self_pentest_enabled"):
        try:
            from src.orchestration.self_pentest import SelfPentestRunner, SELF_PENTEST_TARGETS
            _sp_runner = SelfPentestRunner()
            _sp_result = await _sp_runner.run(scan_id=scan_id)
            if _sp_result.findings:
                logger.warning("self_pentest_findings", extra={"scan_id": scan_id, "count": len(_sp_result.findings)})
                if evidence_chain is not None:
                    for _spf in _sp_result.findings[:10]:
                        try:
                            evidence_chain.add_finding_link(
                                finding_id=f"self-pentest-{_spf.target}",
                                title=_spf.vulnerability,
                                severity=_spf.severity,
                                evidence_tier=2,
                            )
                        except Exception:
                            pass
            else:
                logger.info("self_pentest_clean", extra={"scan_id": scan_id, "targets_scanned": _sp_result.targets_scanned})
        except Exception as _sp_exc:
            logger.warning("self_pentest_run_failed", extra={"scan_id": scan_id, "error": str(_sp_exc)})

    try:
        from src.orchestration.tenant_isolation import TenantIsolationGuard as _TIG
        _ti_guard = _TIG()
        _ti_guard.register_scan_end(tenant_id)
    except Exception as _ti_end_exc:
        logger.warning("tenant_isolation_end_failed", extra={"tenant_id": tenant_id, "error": str(_ti_end_exc)})

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
                    from src.orchestration.raw_phase_artifacts import RawPhaseSink
                    _sink = RawPhaseSink(tenant_id, scan_id, "evidence_chain")
                    await asyncio.to_thread(_sink.upload_text, "evidence_chain", _chain_json)
                except Exception as _chain_sink_exc:
                    logger.debug("evidence_chain_minio_upload_failed", extra={"error": str(_chain_sink_exc)})
        except Exception as _chain_persist_exc:
            logger.warning("evidence_chain_persist_failed", extra={"scan_id": scan_id, "error": str(_chain_persist_exc)})

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
            logger.debug("cost_tracker_summary_failed", extra={"error": str(_cost_log_exc)})

    try:
        from src.orchestration.cost_aware_reasoning import unregister_cost_tracker
        unregister_cost_tracker(scan_id)
    except Exception:
        pass

    await _persist_report_and_findings(
        session,
        tenant_id,
        scan_id,
        target,
        report_out,
        vuln_out,
        recon_out,
    )

    try:
        from src.mcp.services.notifications import (
            DiscordNotifier,
            GitHubIssuesNotifier,
            NotificationDispatcher,
            NotificationEvent,
            NotificationSeverity,
        )
        findings_for_notify = list(vuln_out.findings) if vuln_out and vuln_out.findings else []
        _top_sev = "info"
        for _f in findings_for_notify:
            _s = str(_f.get("severity", "")).lower()
            if _s in ("critical", "high", "medium", "low", "info"):
                if (_s == "critical") or (_s == "high" and _top_sev != "critical") or (
                    _s == "medium" and _top_sev not in ("critical", "high")
                ) or (_s == "low" and _top_sev not in ("critical", "high", "medium")) or (
                    _s == "info" and _top_sev not in ("critical", "high", "medium", "low")
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
        logger.debug("scan_notification_dispatch_failed", extra={"scan_id": scan_id, "error": str(_notify_exc)})

    await _update_scan_phase_status(
        session, scan_id, "complete", "completed", 100
    )
    await _record_event(
        session,
        tenant_id,
        scan_id,
        "complete",
        "complete",
        100,
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

    from src.policy.scan_queue import notify_scan_finished

    await notify_scan_finished(tenant_id)
