"""Recon job runner — Celery task for executing recon tool jobs."""

import asyncio
import json
import logging
from typing import Any

from sqlalchemy import select

from src.celery_app import app
from src.db.models_recon import ScanJob
from src.db.session import create_task_engine_and_session
from src.recon.adapters import registry
from src.recon.normalization.pipeline import normalize_tool_output, save_findings
from src.recon.scope.enforcement import get_scope_validator
from src.recon.services.artifact_service import create_artifact
from src.recon.services.scanjob_service import update_job_status

logger = logging.getLogger(__name__)


async def _run_job(job_id: str) -> dict[str, Any]:
    """Async implementation of recon job execution."""
    engine, session_factory = create_task_engine_and_session()

    try:
        async with session_factory() as db:
            result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
            job = result.scalar_one_or_none()
            if not job:
                return {"error": f"Job {job_id} not found"}

            await update_job_status(db, job_id, "running")
            await db.commit()

            adapter = registry.get(job.tool_name)
            if not adapter:
                await update_job_status(
                    db,
                    job_id,
                    "failed",
                    error_message=f"No adapter for tool: {job.tool_name}",
                )
                await db.commit()
                return {"error": f"No adapter for {job.tool_name}"}

            scope_validator = await get_scope_validator(db, job.engagement_id)

            config = job.config or {}
            raw_output = config.get("raw_output", "")

            if raw_output:
                await create_artifact(
                    db,
                    tenant_id=job.tenant_id,
                    engagement_id=job.engagement_id,
                    target_id=job.target_id,
                    job_id=job.id,
                    stage=job.stage,
                    filename=f"{job.tool_name}_raw.txt",
                    data=raw_output.encode("utf-8"),
                    content_type="text/plain",
                    artifact_type="raw",
                )

            findings = await normalize_tool_output(
                job.tool_name, raw_output, scope_validator
            )

            counts = await save_findings(
                db,
                findings,
                tenant_id=job.tenant_id,
                engagement_id=job.engagement_id,
                target_id=job.target_id,
                job_id=job.id,
            )

            if findings:
                normalized_json = json.dumps(findings, default=str)
                await create_artifact(
                    db,
                    tenant_id=job.tenant_id,
                    engagement_id=job.engagement_id,
                    target_id=job.target_id,
                    job_id=job.id,
                    stage=job.stage,
                    filename=f"{job.tool_name}_normalized.json",
                    data=normalized_json.encode("utf-8"),
                    content_type="application/json",
                    artifact_type="normalized",
                )

            summary: dict[str, Any] = {
                "items_found": len(findings),
                "items_added": counts["added"],
                "items_skipped": counts["skipped"],
            }
            await update_job_status(
                db, job_id, "completed", result_summary=summary
            )
            await db.commit()

            logger.info("Recon job completed", extra={"job_id": job_id, **summary})
            return summary

    except Exception as e:
        logger.warning("Recon job failed", extra={"job_id": job_id, "error": str(e)})
        try:
            async with session_factory() as db:
                await update_job_status(db, job_id, "failed", error_message=str(e))
                await db.commit()
        except Exception:
            pass
        return {"error": str(e)}
    finally:
        await engine.dispose()


@app.task(name="argus.recon_job", bind=True, max_retries=3)
def run_recon_job(self, job_id: str) -> dict:
    """Celery task entry point for recon job execution."""
    logger.info("Recon job task received", extra={"job_id": job_id})
    return asyncio.run(_run_job(job_id))
