"""Celery tasks — scan phase execution, tool runs (Phase 5)."""

import asyncio
import logging
from typing import Any

from sqlalchemy import cast, select, String, update

from src.celery_app import app
from src.core.config import settings
from src.db.session import create_task_engine_and_session, set_session_tenant
from src.orchestration.state_machine import (
    ExploitationApprovalRequiredError,
    run_scan_state_machine,
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


@app.task(bind=True, name="argus.report_generation")
def report_generation_task(
    _self,
    report_id: str,
    tenant_id: str,
    scan_id: str,
    _target: str,
    formats: list[str],
) -> dict[str, Any]:
    """
    Generate report artifacts (HTML, PDF, JSON, CSV) and upload to MinIO.
    """
    async def _run():
        from src.db.models import Finding, Report
        from src.reports.generators import (
            build_report_data_from_db,
            generate_csv,
            generate_html,
            generate_json,
            generate_pdf,
        )
        from src.reports.storage import upload
        from src.storage.s3 import OBJECT_TYPE_REPORTS

        engine, session_factory = create_task_engine_and_session()
        try:
            async with session_factory() as session:
                await set_session_tenant(session, tenant_id)
                result = await session.execute(select(Report).where(cast(Report.id, String) == report_id))
                report = result.scalar_one_or_none()
                if not report:
                    return {"status": "failed", "report_id": report_id, "error": "Report not found"}

                findings_result = await session.execute(
                    select(Finding).where(cast(Finding.report_id, String) == report_id)
                )
                findings = list(findings_result.scalars().all())
                data = build_report_data_from_db(report, findings)

                generated = {}
                generators = {"pdf": generate_pdf, "html": generate_html, "json": generate_json, "csv": generate_csv}
                content_types = {"pdf": "application/pdf", "html": "text/html", "json": "application/json", "csv": "text/csv"}
                for fmt in formats:
                    if fmt in generators:
                        content = generators[fmt](data)
                        filename = f"report.{fmt}"
                        key = upload(
                            tenant_id, scan_id, OBJECT_TYPE_REPORTS, filename,
                            content, content_type=content_types.get(fmt, "application/octet-stream"),
                        )
                        if key:
                            generated[fmt] = {"object_key": key}
                return {"status": "completed", "report_id": report_id, "formats": list(generated.keys())}
        finally:
            await engine.dispose()

    try:
        return asyncio.run(_run())
    except Exception:
        return {"status": "failed", "report_id": report_id}


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
