"""Recon engagement API endpoints."""

import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.session import get_db
from src.recon.schemas.engagement import (
    EngagementCreate,
    EngagementListResponse,
    EngagementResponse,
    EngagementUpdate,
)
from src.recon.services.engagement_service import (
    EngagementNotFoundError,
    EngagementStateError,
    activate_engagement,
    complete_engagement,
    create_engagement,
    get_engagement,
    get_engagement_stats,
    list_engagements,
    update_engagement,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/recon/engagements", tags=["recon-engagements"])


def _get_tenant_id() -> str:
    return settings.default_tenant_id


@router.post("", response_model=EngagementResponse, status_code=201)
async def create(
    data: EngagementCreate, db: AsyncSession = Depends(get_db)
) -> EngagementResponse:
    """Create a new recon engagement."""
    tenant_id = _get_tenant_id()
    eng = await create_engagement(db, tenant_id, data)
    return EngagementResponse.model_validate(eng)


@router.get("", response_model=EngagementListResponse)
async def list_all(
    status: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> EngagementListResponse:
    """List engagements with optional filters."""
    tenant_id = _get_tenant_id()
    items, total = await list_engagements(db, tenant_id, status, offset, limit)
    return EngagementListResponse(
        items=[EngagementResponse.model_validate(e) for e in items],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/{engagement_id}", response_model=EngagementResponse)
async def get_one(
    engagement_id: str, db: AsyncSession = Depends(get_db)
) -> EngagementResponse:
    """Get engagement with stats."""
    tenant_id = _get_tenant_id()
    eng = await get_engagement(db, tenant_id, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    stats = await get_engagement_stats(db, engagement_id)
    resp = EngagementResponse.model_validate(eng)
    resp.target_count = stats["target_count"]
    resp.job_count = stats["job_count"]
    resp.finding_count = stats["finding_count"]
    return resp


@router.patch("/{engagement_id}", response_model=EngagementResponse)
async def update(
    engagement_id: str,
    data: EngagementUpdate,
    db: AsyncSession = Depends(get_db),
) -> EngagementResponse:
    """Update engagement."""
    tenant_id = _get_tenant_id()
    try:
        eng = await update_engagement(db, tenant_id, engagement_id, data)
        return EngagementResponse.model_validate(eng)
    except EngagementNotFoundError:
        raise HTTPException(status_code=404, detail="Engagement not found")


@router.post("/{engagement_id}/activate", response_model=EngagementResponse)
async def activate(
    engagement_id: str, db: AsyncSession = Depends(get_db)
) -> EngagementResponse:
    """Activate engagement (requires scope rules)."""
    tenant_id = _get_tenant_id()
    try:
        eng = await activate_engagement(db, tenant_id, engagement_id)
        return EngagementResponse.model_validate(eng)
    except EngagementNotFoundError:
        raise HTTPException(status_code=404, detail="Engagement not found")
    except EngagementStateError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{engagement_id}/complete", response_model=EngagementResponse)
async def complete(
    engagement_id: str, db: AsyncSession = Depends(get_db)
) -> EngagementResponse:
    """Mark engagement as completed."""
    tenant_id = _get_tenant_id()
    try:
        eng = await complete_engagement(db, tenant_id, engagement_id)
        return EngagementResponse.model_validate(eng)
    except EngagementNotFoundError:
        raise HTTPException(status_code=404, detail="Engagement not found")
    except EngagementStateError as e:
        raise HTTPException(status_code=400, detail=str(e))
