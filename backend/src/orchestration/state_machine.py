"""ScanStateMachine — transitions between phases, DB recording."""

import asyncio
import logging
import time
import uuid

from sqlalchemy import String, cast, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas import DEFAULT_GENERATE_ALL_FORMATS, ReportSummary
from src.owasp_top10_2025 import parse_owasp_category
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
from src.orchestration.aggressive_exploit_tools import maybe_run_aggressive_exploit_tools
from src.storage.s3 import upload_finding_poc_json
from src.orchestration.handlers import (
    run_exploit_attempt,
    run_exploit_verify,
    run_post_exploitation,
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
    ReconOutput,
    ReportingOutput,
    ScanPhase,
    ThreatModelOutput,
    VulnAnalysisOutput,
)
from src.orchestration.raw_phase_artifacts import RawPhaseSink
from src.reports.bundle_enqueue import (
    enqueue_generate_all_bundle,
    schedule_generate_all_reports_task_safe,
)

logger = logging.getLogger(__name__)


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
    """Map phase to progress 0..100 (recon 15, threat_modeling 25, vuln_analysis 45, exploitation 65, post_exploitation 85, reporting 100)."""
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
    findings_raw = vuln_out.findings if vuln_out else []
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

    for f in findings_raw:
        poc_blob = f.get("proof_of_concept")
        poc_db = poc_blob if isinstance(poc_blob, dict) and poc_blob else None
        ow_raw = f.get("owasp_category")
        owasp_val = parse_owasp_category(ow_raw.strip()) if isinstance(ow_raw, str) and ow_raw.strip() else None
        finding = Finding(
            id=str(uuid.uuid4()),
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
    recon_out: ReconOutput | None = None
    threat_out: ThreatModelOutput | None = None
    vuln_out: VulnAnalysisOutput | None = None
    exploit_out: ExploitationOutput | None = None
    post_out: PostExploitationOutput | None = None

    report_out: ReportingOutput | None = None

    for order_index, phase in enumerate(PHASE_ORDER):
        progress = _phase_to_progress(phase)
        phase_str = phase.value
        phase_start_time = time.monotonic()

        # Build phase input and persist
        if phase == ScanPhase.RECON:
            input_data = {"target": target, "options": options}
        elif phase == ScanPhase.THREAT_MODELING:
            input_data = {"assets": recon_out.assets if recon_out else []}
        elif phase == ScanPhase.VULN_ANALYSIS:
            input_data = {
                "threat_model": threat_out.threat_model if threat_out else {},
                "assets": recon_out.assets if recon_out else [],
            }
        elif phase == ScanPhase.EXPLOITATION:
            input_data = {"findings": vuln_out.findings if vuln_out else []}
        elif phase == ScanPhase.POST_EXPLOITATION:
            input_data = {"exploits": exploit_out.exploits if exploit_out else []}
        elif phase == ScanPhase.REPORTING:
            input_data = {
                "target": target,
                "recon": recon_out.model_dump() if recon_out else None,
                "threat_model": threat_out.model_dump() if threat_out else None,
                "vuln_analysis": vuln_out.model_dump() if vuln_out else None,
                "exploitation": exploit_out.model_dump() if exploit_out else None,
                "post_exploitation": post_out.model_dump() if post_out else None,
            }
        else:
            input_data = {}
        await _persist_phase_input(session, tenant_id, scan_id, phase_str, input_data)
        if phase == ScanPhase.RECON:
            await _upload_raw_phase_snapshot(
                tenant_id, scan_id, "recon", "phase_input", input_data
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
                if phase == ScanPhase.RECON:
                    record_tool_run("recon")
                    recon_out = await run_recon(
                        target, options, tenant_id=tenant_id, scan_id=scan_id
                    )
                    output_data = recon_out.model_dump()
                elif phase == ScanPhase.THREAT_MODELING:
                    record_tool_run("threat_modeling")
                    assets = recon_out.assets if recon_out else []
                    threat_out = await run_threat_modeling(assets)
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
                    )
                    output_data = vuln_out.model_dump()
                elif phase == ScanPhase.EXPLOITATION:
                    findings = vuln_out.findings if vuln_out else []
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
                    attempt_out = await run_exploit_attempt(findings)
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
                        target, recon_out, threat_out, vuln_out, exploit_out, post_out
                    )
                    output_data = report_out.model_dump()
                else:
                    output_data = {}
        except Exception:
            await session.execute(
                update(ScanStep)
                .where(cast(ScanStep.id, String) == step.id)
                .values(status="failed")
            )
            logger.error(
                "Phase handler failed",
                extra={"event_type": "phase_error", "phase": phase_str, "scan_id": scan_id},
            )
            await _record_event(
                session,
                tenant_id,
                scan_id,
                "error",
                phase_str,
                progress,
                message="Phase failed",
                data={"code": "phase_error"},
            )
            await _update_scan_phase_status(
                session, scan_id, phase_str, "failed", progress
            )
            await session.commit()
            raise

        phase_duration = time.monotonic() - phase_start_time
        record_phase_duration(phase_str, phase_duration)

        await _persist_phase_output(
            session, tenant_id, scan_id, phase_str, output_data
        )
        if phase in (ScanPhase.RECON, ScanPhase.VULN_ANALYSIS, ScanPhase.POST_EXPLOITATION):
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

    assert report_out is not None, "Reporting phase must complete before persist"
    await _persist_report_and_findings(
        session,
        tenant_id,
        scan_id,
        target,
        report_out,
        vuln_out,
        recon_out,
    )

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
