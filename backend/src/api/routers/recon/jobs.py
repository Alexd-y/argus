"""Recon scan job API endpoints."""

import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.session import get_db
from src.recon.schemas.job import ScanJobCreate, ScanJobListResponse, ScanJobResponse
from src.recon.services.scanjob_service import (
    ScanJobNotFoundError,
    ScanJobServiceError,
    ScanJobStateError,
    cancel_job,
    create_job,
    get_job,
    list_jobs,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["recon-jobs"])


def _get_tenant_id() -> str:
    return settings.default_tenant_id


def _enqueue_recon_job(job_id: str) -> None:
    """Enqueue Celery task for recon job execution."""
    try:
        from src.recon.jobs.runner import run_recon_job
        run_recon_job.delay(job_id)
        logger.info("Recon job enqueued", extra={"job_id": job_id})
    except Exception as e:
        logger.warning("Failed to enqueue recon job", extra={"job_id": job_id, "error": str(e)})


@router.post(
    "/recon/engagements/{engagement_id}/jobs",
    response_model=ScanJobResponse,
    status_code=201,
)
async def create(
    engagement_id: str,
    data: ScanJobCreate,
    db: AsyncSession = Depends(get_db),
) -> ScanJobResponse:
    """Create a scan job for an engagement."""
    tenant_id = _get_tenant_id()
    try:
        job = await create_job(db, tenant_id, engagement_id, data)
        await db.commit()
        _enqueue_recon_job(job.id)
        return ScanJobResponse.model_validate(job)
    except ScanJobStateError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ScanJobServiceError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get(
    "/recon/engagements/{engagement_id}/jobs",
    response_model=ScanJobListResponse,
)
async def list_all(
    engagement_id: str,
    target_id: str | None = Query(None),
    stage: int | None = Query(None),
    status: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
) -> ScanJobListResponse:
    """List jobs for an engagement."""
    items, total = await list_jobs(db, engagement_id, target_id, stage, status)
    return ScanJobListResponse(
        items=[ScanJobResponse.model_validate(j) for j in items],
        total=total,
    )


@router.get("/recon/jobs/{job_id}", response_model=ScanJobResponse)
async def get_one(
    job_id: str, db: AsyncSession = Depends(get_db)
) -> ScanJobResponse:
    """Get scan job detail."""
    tenant_id = _get_tenant_id()
    job = await get_job(db, tenant_id, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return ScanJobResponse.model_validate(job)


@router.post("/recon/jobs/{job_id}/cancel", response_model=ScanJobResponse)
async def cancel(
    job_id: str, db: AsyncSession = Depends(get_db)
) -> ScanJobResponse:
    """Cancel a pending/running job."""
    tenant_id = _get_tenant_id()
    try:
        job = await cancel_job(db, tenant_id, job_id)
        return ScanJobResponse.model_validate(job)
    except ScanJobNotFoundError:
        raise HTTPException(status_code=404, detail="Job not found")
    except ScanJobStateError as e:
        raise HTTPException(status_code=400, detail=str(e))
