"""Vulnerability analysis run service — CRUD and recon_dir resolution."""

from __future__ import annotations

import logging
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_recon import VulnerabilityAnalysisRun

logger = logging.getLogger(__name__)


class VulnerabilityAnalysisRunNotFoundError(Exception):
    """Vulnerability analysis run not found."""


async def create_va_run(
    db: AsyncSession,
    tenant_id: str,
    engagement_id: str,
    *,
    target_id: str | None = None,
    job_id: str | None = None,
) -> VulnerabilityAnalysisRun:
    """Create VulnerabilityAnalysisRun record (pending, not executed)."""
    run_id = str(uuid4())
    j_id = job_id or f"va_{run_id[:8]}"
    input_bundle_ref = f"engagement:{engagement_id}:run:{run_id}:job:{j_id}"

    run = VulnerabilityAnalysisRun(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        target_id=target_id,
        status="pending",
        started_at=None,
        completed_at=None,
        input_bundle_ref=input_bundle_ref,
        artifact_refs=[],
        job_id=j_id,
        run_id=run_id,
    )
    db.add(run)
    await db.flush()
    logger.info(
        "Vulnerability analysis run created",
        extra={"run_id": run_id, "engagement_id": engagement_id, "job_id": j_id},
    )
    return run


async def get_va_run(
    db: AsyncSession,
    tenant_id: str,
    engagement_id: str,
    run_id: str,
) -> VulnerabilityAnalysisRun | None:
    """Get vulnerability analysis run by ID, scoped to engagement and tenant."""
    result = await db.execute(
        select(VulnerabilityAnalysisRun).where(
            VulnerabilityAnalysisRun.id == run_id,
            VulnerabilityAnalysisRun.engagement_id == engagement_id,
            VulnerabilityAnalysisRun.tenant_id == tenant_id,
        )
    )
    return result.scalar_one_or_none()
