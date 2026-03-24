"""Celery tasks — scan phase execution, tool runs (Phase 5)."""

import asyncio
import logging
from typing import Any

from sqlalchemy import String, cast, select, update

from src.celery_app import app
from src.core.config import settings
from src.db.models import Report
from src.db.session import create_task_engine_and_session, set_session_tenant
from src.orchestration.state_machine import (
    ExploitationApprovalRequiredError,
    run_scan_state_machine,
)
from src.recon.vulnerability_analysis.active_scan.mcp_runner import (
    run_va_active_scan_sync,
)
from src.tools.executor import execute_command
from src.tools.guardrails import validate_target_for_tool

logger = logging.getLogger(__name__)


@app.task(bind=True, name="argus.scan_phase")
def scan_phase_task(
    _self,
    scan_id: str,
    tenant_id: str,
    target_url: str,
    options: dict,
) -> dict[str, Any]:
    """
    Execute full scan pipeline in background.
    Runs state machine: recon -> threat_modeling -> vuln_analysis -> exploitation -> post_exploitation -> reporting.
    """

    async def _run():
        engine, session_factory = create_task_engine_and_session()
        try:
            async with session_factory() as session:
                await set_session_tenant(session, tenant_id)
                try:
                    await run_scan_state_machine(
                        session, scan_id, tenant_id, target_url, options
                    )
                    return {"status": "completed", "scan_id": scan_id}
                except ExploitationApprovalRequiredError:
                    return {"status": "awaiting_approval", "scan_id": scan_id}
                except Exception:
                    from src.db.models import Scan

                    async with session_factory() as err_session:
                        await set_session_tenant(err_session, tenant_id)
                        await err_session.execute(
                            update(Scan)
                            .where(cast(Scan.id, String) == scan_id)
                            .values(status="failed", phase="failed")
                        )
                        await err_session.commit()
                    raise
        finally:
            await engine.dispose()

    return asyncio.run(_run())


def _sync_run_generate_report(
    report_id: str,
    tenant_id: str,
    scan_id: str | None,
    formats: list[str] | None,
    *,
    include_minio: bool = True,
) -> dict[str, Any]:
    """RPT-006 — shared Celery body: ReportGenerator pipeline, MinIO, ReportObject upserts."""
    from src.reports.report_pipeline import run_generate_report_pipeline

    async def _run():
        engine, session_factory = create_task_engine_and_session()
        try:
            async with session_factory() as session:
                await set_session_tenant(session, tenant_id)
                return await run_generate_report_pipeline(
                    session,
                    report_id=report_id,
                    tenant_id=tenant_id,
                    scan_id_hint=scan_id,
                    formats=formats,
                    include_minio=include_minio,
                )
        finally:
            await engine.dispose()

    return asyncio.run(_run())


@app.task(bind=True, name="argus.generate_all_reports")
def generate_all_reports_task(
    _self,
    tenant_id: str,
    scan_id: str,
    bundle_id: str,
    report_ids: list[str],
) -> dict[str, Any]:
    """Run ``run_generate_report_pipeline`` for each report id with bounded concurrency (semaphore 4)."""
    from src.reports.report_pipeline import normalize_generation_formats, run_generate_report_pipeline

    async def _run_one(rid: str) -> dict[str, Any]:
        engine, session_factory = create_task_engine_and_session()
        try:
            async with session_factory() as session:
                await set_session_tenant(session, tenant_id)
                res = await session.execute(select(Report).where(cast(Report.id, String) == rid))
                rep = res.scalar_one_or_none()
                if not rep:
                    return {"status": "failed", "report_id": rid, "error": "Report not found"}
                row_formats = normalize_generation_formats(None, rep.requested_formats)
                return await run_generate_report_pipeline(
                    session,
                    report_id=rid,
                    tenant_id=tenant_id,
                    scan_id_hint=scan_id,
                    formats=row_formats,
                    include_minio=True,
                )
        finally:
            await engine.dispose()

    async def _run_all() -> dict[str, Any]:
        sem = asyncio.Semaphore(4)

        async def _bounded(rid: str) -> dict[str, Any]:
            async with sem:
                return await _run_one(rid)

        results = await asyncio.gather(
            *(_bounded(rid) for rid in report_ids),
            return_exceptions=True,
        )
        normalized: list[dict[str, Any]] = []
        for i, r in enumerate(results):
            rid = report_ids[i] if i < len(report_ids) else ""
            if isinstance(r, Exception):
                logger.error(
                    "generate_all_report_item_failed",
                    extra={"event": "generate_all_report_item_failed", "report_id": rid, "bundle_id": bundle_id},
                    exc_info=r,
                )
                normalized.append({"status": "failed", "report_id": rid, "error": "task_error"})
            else:
                normalized.append(r)  # type: ignore[arg-type]
        ok = sum(1 for x in normalized if x.get("status") == "completed")
        return {
            "bundle_id": bundle_id,
            "scan_id": scan_id,
            "completed": ok,
            "total": len(report_ids),
            "results": normalized,
        }

    try:
        return asyncio.run(_run_all())
    except Exception:
        logger.exception(
            "generate_all_reports_task_failed",
            extra={"event": "generate_all_reports_task_failed", "bundle_id": bundle_id},
        )
        return {"status": "failed", "bundle_id": bundle_id, "error": "task_error"}


@app.task(bind=True, name="argus.generate_report")
def generate_report_task(
    _self,
    report_id: str,
    tenant_id: str,
    scan_id: str | None = None,
    formats: list[str] | None = None,
    include_minio: bool = True,
) -> dict[str, Any]:
    """
    Full report generation: collect scan data, sync AI sections, render HTML/JSON/CSV/PDF,
    upload to reports bucket, upsert ReportObject per format.
    """
    try:
        return _sync_run_generate_report(
            report_id,
            tenant_id,
            scan_id,
            formats,
            include_minio=include_minio,
        )
    except Exception:
        logger.exception(
            "generate_report_task_failed",
            extra={"event": "generate_report_task_failed", "report_id": report_id},
        )
        return {"status": "failed", "report_id": report_id, "error": "task_error"}


@app.task(bind=True, name="argus.report_generation")
def report_generation_task(
    _self,
    report_id: str,
    tenant_id: str,
    scan_id: str,
    _target: str,
    formats: list[str],
) -> dict[str, Any]:
    """Legacy task name; same behavior as ``argus.generate_report``."""
    try:
        return _sync_run_generate_report(report_id, tenant_id, scan_id, formats)
    except Exception:
        logger.exception(
            "report_generation_task_failed",
            extra={"event": "report_generation_task_failed", "report_id": report_id},
        )
        return {"status": "failed", "report_id": report_id, "error": "task_error"}


@app.task(bind=True, name="argus.exploitation", max_retries=1)
def run_exploitation(
    self,
    engagement_id: str,
    run_id: str,
    options: dict | None = None,
) -> dict[str, Any]:
    """Execute Stage 4 exploitation pipeline in background."""

    async def _run():
        from src.recon.exploitation.pipeline import execute_exploitation_run

        engine, session_factory = create_task_engine_and_session()
        try:
            async with session_factory() as session:
                result = await execute_exploitation_run(
                    engagement_id,
                    run_id,
                    db=session,
                    options=options,
                )
                await session.commit()
                return result
        finally:
            await engine.dispose()

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.exception(
            "Exploitation task failed",
            extra={"engagement_id": engagement_id, "run_id": run_id},
        )
        raise self.retry(exc=exc, countdown=60) from exc


@app.task(bind=True, name="argus.ai_text_generation")
def ai_text_generation_task(
    _self,
    tenant_id: str,
    scan_id: str,
    tier: str,
    section_key: str,
    input_payload: dict,
) -> dict[str, Any]:
    """
    Generate a single report section via LLM with deterministic Redis cache
    (tenant_id, scan_id, tier, section_key, payload hash, prompt version).
    """
    from src.core.redis_client import get_redis
    from src.reports.ai_text_generation import run_ai_text_generation

    redis_client = get_redis()
    return run_ai_text_generation(
        tenant_id,
        scan_id,
        tier,
        section_key,
        input_payload,
        redis_client=redis_client,
    )


@app.task(bind=True, name="argus.tool_run")
def tool_run_task(
    _self,
    tool_name: str,
    command: str,
    target: str | None = None,
    use_sandbox: bool | None = None,
) -> dict[str, Any]:
    """
    Execute security tool command in background.
    Validates target via guardrails before execution.
    """
    if target:
        validation = validate_target_for_tool(target, tool_name)
        if not validation["allowed"]:
            return {
                "success": False,
                "stdout": "",
                "stderr": validation["reason"],
                "return_code": -1,
                "execution_time": 0.0,
            }

    use_sb = use_sandbox if use_sandbox is not None else settings.sandbox_enabled
    result = execute_command(command, use_cache=False, use_sandbox=use_sb)
    result["tool"] = tool_name
    return result


@app.task(bind=True, name="argus.va_active_scan_tool")
def va_active_scan_tool_task(
    _self,
    tool_name: str,
    target: str,
    argv: list[str],
    timeout_sec: float,
    use_sandbox: bool = False,
) -> dict[str, Any]:
    """
    OWASP-003 — run VA active-scan tool via policy/guardrails/subprocess (JSON-serializable args for Celery).
    """
    try:
        out = run_va_active_scan_sync(
            tool_name=tool_name,
            target=target,
            argv=argv,
            timeout_sec=timeout_sec,
            use_sandbox=use_sandbox,
        )
        return dict(out)
    except Exception:
        logger.exception(
            "va_active_scan_tool_task_failed",
            extra={"event": "va_active_scan_tool_task_failed", "tool_name": tool_name},
        )
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "tool_id": "",
            "error_reason": "task_error",
        }


# VA-003: named VA tool tasks (registers Celery task names on import)
from . import tools as _va_named_tool_tasks  # noqa: E402, F401
