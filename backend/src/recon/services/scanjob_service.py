"""Scan job service - lifecycle management for recon tool runs."""

import logging
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_recon import Engagement, ReconTarget, ScanJob
from src.recon.schemas.job import ScanJobCreate
from src.recon.storage import get_stage_name

logger = logging.getLogger(__name__)


class ScanJobServiceError(Exception):
    """Base error for scan job service."""


class ScanJobNotFoundError(ScanJobServiceError):
    """Scan job not found."""


class ScanJobStateError(ScanJobServiceError):
    """Invalid job state transition."""


async def create_job(
    db: AsyncSession,
    tenant_id: str,
    engagement_id: str,
    data: ScanJobCreate,
) -> ScanJob:
    """Create scan job - validates engagement is active."""
    eng_result = await db.execute(
        select(Engagement).where(
            Engagement.id == engagement_id, Engagement.tenant_id == tenant_id
        )
    )
    engagement = eng_result.scalar_one_or_none()
    if not engagement:
        raise ScanJobServiceError(f"Engagement {engagement_id} not found")
    if engagement.status != "active":
        raise ScanJobStateError(
            f"Engagement must be active to create jobs (current: {engagement.status})"
        )

    target_result = await db.execute(
        select(ReconTarget).where(
            ReconTarget.id == data.target_id,
            ReconTarget.engagement_id == engagement_id,
        )
    )
    target = target_result.scalar_one_or_none()
    if not target:
        raise ScanJobServiceError(f"Target {data.target_id} not found in engagement")

    job = ScanJob(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        target_id=data.target_id,
        stage=data.stage,
        stage_name=get_stage_name(data.stage),
        tool_name=data.tool_name,
        status="pending",
        config=data.config,
        operator=data.operator,
    )
    db.add(job)
    await db.flush()
    logger.info(
        "Scan job created",
        extra={"job_id": job.id, "tool": data.tool_name, "stage": data.stage},
    )
    return job


async def get_job(
    db: AsyncSession, tenant_id: str, job_id: str
) -> ScanJob | None:
    """Get scan job by ID, scoped to tenant."""
    result = await db.execute(
        select(ScanJob).where(ScanJob.id == job_id, ScanJob.tenant_id == tenant_id)
    )
    return result.scalar_one_or_none()


async def list_jobs(
    db: AsyncSession,
    engagement_id: str,
    target_id: str | None = None,
    stage: int | None = None,
    status: str | None = None,
) -> tuple[list[ScanJob], int]:
    """List jobs with optional filters. Returns (items, total)."""
    base = select(ScanJob).where(ScanJob.engagement_id == engagement_id)
    if target_id:
        base = base.where(ScanJob.target_id == target_id)
    if stage is not None:
        base = base.where(ScanJob.stage == stage)
    if status:
        base = base.where(ScanJob.status == status)

    count_stmt = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    items_stmt = base.order_by(ScanJob.created_at.desc())
    result = await db.execute(items_stmt)
    items = list(result.scalars().all())
    return items, total


async def update_job_status(
    db: AsyncSession,
    job_id: str,
    status: str,
    error_message: str | None = None,
    result_summary: dict | None = None,
) -> ScanJob:
    """Update job status with optional error and summary."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise ScanJobNotFoundError(f"Job {job_id} not found")

    job.status = status
    if error_message is not None:
        job.error_message = error_message
    if result_summary is not None:
        job.result_summary = result_summary

    now = datetime.now(timezone.utc)
    if status == "running" and not job.started_at:
        job.started_at = now
    if status in ("completed", "failed", "cancelled"):
        job.completed_at = now

    await db.flush()
    logger.info("Job status updated", extra={"job_id": job_id, "status": status})
    return job


async def cancel_job(
    db: AsyncSession, tenant_id: str, job_id: str
) -> ScanJob:
    """Cancel a pending or running job."""
    job = await get_job(db, tenant_id, job_id)
    if not job:
        raise ScanJobNotFoundError(f"Job {job_id} not found")
    if job.status not in ("pending", "queued", "running"):
        raise ScanJobStateError(f"Cannot cancel job in status: {job.status}")

    job.status = "cancelled"
    job.completed_at = datetime.now(timezone.utc)
    await db.flush()
    logger.info("Job cancelled", extra={"job_id": job_id})
    return job
