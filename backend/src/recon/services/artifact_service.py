"""Artifact service — creates DB records and uploads to MinIO atomically."""

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_recon import Artifact
from src.recon.storage import (
    delete_artifact as storage_delete,
)
from src.recon.storage import (
    get_artifact_url as storage_url,
)
from src.recon.storage import (
    upload_artifact as storage_upload,
)

logger = logging.getLogger(__name__)


async def create_artifact(
    db: AsyncSession,
    *,
    tenant_id: str,
    engagement_id: str,
    target_id: str | None,
    job_id: str | None,
    stage: int,
    filename: str,
    data: bytes,
    content_type: str = "text/plain",
    artifact_type: str = "raw",
    extra_data: dict[str, Any] | None = None,
) -> Artifact | None:
    """Upload artifact to MinIO and create DB record.

    Returns Artifact on success, None on storage failure.
    """
    t_id = target_id or "shared"
    j_id = job_id or "manual"

    object_key, checksum, size = storage_upload(
        engagement_id=engagement_id,
        target_id=t_id,
        job_id=j_id,
        stage=stage,
        filename=filename,
        data=data,
        content_type=content_type,
    )
    if not object_key:
        logger.warning("Failed to upload artifact to storage", extra={"filename": filename})
        return None

    artifact = Artifact(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        target_id=target_id,
        job_id=job_id,
        artifact_type=artifact_type,
        stage=stage,
        filename=filename,
        content_type=content_type,
        object_key=object_key,
        size_bytes=size,
        checksum_sha256=checksum,
        extra_data=extra_data,
    )
    db.add(artifact)
    await db.flush()
    logger.info(
        "Artifact created",
        extra={"artifact_id": artifact.id, "key": object_key, "type": artifact_type},
    )
    return artifact


async def get_artifact(db: AsyncSession, artifact_id: str) -> Artifact | None:
    """Get artifact by ID."""
    result = await db.execute(select(Artifact).where(Artifact.id == artifact_id))
    return result.scalar_one_or_none()


async def get_artifacts_for_job(db: AsyncSession, job_id: str) -> list[Artifact]:
    """Get all artifacts for a scan job."""
    result = await db.execute(
        select(Artifact).where(Artifact.job_id == job_id).order_by(Artifact.created_at)
    )
    return list(result.scalars().all())


async def get_artifacts_for_engagement(
    db: AsyncSession,
    engagement_id: str,
    artifact_type: str | None = None,
) -> list[Artifact]:
    """Get artifacts for engagement, optionally filtered by type."""
    stmt = select(Artifact).where(Artifact.engagement_id == engagement_id)
    if artifact_type:
        stmt = stmt.where(Artifact.artifact_type == artifact_type)
    stmt = stmt.order_by(Artifact.created_at)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_artifact_by_engagement_job_filename(
    db: AsyncSession,
    engagement_id: str,
    job_id: str,
    filename: str,
) -> Artifact | None:
    """Get artifact by engagement, job, and filename (e.g. threat model artifacts)."""
    result = await db.execute(
        select(Artifact).where(
            Artifact.engagement_id == engagement_id,
            Artifact.job_id == job_id,
            Artifact.filename == filename,
        )
    )
    return result.scalar_one_or_none()


async def get_artifact_download_url(db: AsyncSession, artifact_id: str) -> str | None:
    """Get presigned download URL for artifact."""
    artifact = await get_artifact(db, artifact_id)
    if not artifact:
        return None
    return storage_url(artifact.object_key)


async def delete_artifact_record(db: AsyncSession, artifact_id: str) -> bool:
    """Delete artifact from storage and DB."""
    artifact = await get_artifact(db, artifact_id)
    if not artifact:
        return False
    storage_delete(artifact.object_key)
    await db.delete(artifact)
    await db.flush()
    return True
