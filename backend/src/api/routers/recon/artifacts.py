"""Recon artifact API endpoints."""

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.session import get_db
from src.recon.schemas.artifact import ArtifactListResponse, ArtifactResponse
from src.recon.services.artifact_service import (
    get_artifact,
    get_artifact_download_url,
    get_artifacts_for_engagement,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["recon-artifacts"])


@router.get(
    "/recon/engagements/{engagement_id}/artifacts",
    response_model=ArtifactListResponse,
)
async def list_all(
    engagement_id: str,
    artifact_type: str | None = None,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ArtifactListResponse:
    """List artifacts for an engagement."""
    items = await get_artifacts_for_engagement(db, engagement_id, artifact_type)
    return ArtifactListResponse(
        items=[ArtifactResponse.model_validate(a) for a in items],
        total=len(items),
    )


@router.get("/recon/artifacts/{artifact_id}", response_model=ArtifactResponse)
async def get_one(
    artifact_id: str, db: AsyncSession = Depends(get_db)  # noqa: B008
) -> ArtifactResponse:
    """Get artifact metadata."""
    art = await get_artifact(db, artifact_id)
    if not art:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return ArtifactResponse.model_validate(art)


@router.get("/recon/artifacts/{artifact_id}/download")
async def download(
    artifact_id: str, db: AsyncSession = Depends(get_db)  # noqa: B008
) -> dict:
    """Get presigned download URL for artifact."""
    url = await get_artifact_download_url(db, artifact_id)
    if not url:
        raise HTTPException(status_code=404, detail="Artifact not found or unavailable")
    return {"download_url": url}
