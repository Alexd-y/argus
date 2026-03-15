"""Recon findings API endpoints."""

import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.session import get_db
from src.db.models_recon import NormalizedFinding

logger = logging.getLogger(__name__)
router = APIRouter(tags=["recon-findings"])


@router.get("/recon/engagements/{engagement_id}/findings")
async def list_findings(
    engagement_id: str,
    finding_type: str | None = Query(None),
    is_verified: bool | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List normalized findings for an engagement."""
    base = select(NormalizedFinding).where(
        NormalizedFinding.engagement_id == engagement_id
    )
    if finding_type:
        base = base.where(NormalizedFinding.finding_type == finding_type)
    if is_verified is not None:
        base = base.where(NormalizedFinding.is_verified == is_verified)

    count_stmt = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    items_stmt = base.order_by(NormalizedFinding.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(items_stmt)
    items = result.scalars().all()

    return {
        "items": [
            {
                "id": f.id,
                "finding_type": f.finding_type,
                "value": f.value,
                "data": f.data,
                "source_tool": f.source_tool,
                "confidence": f.confidence,
                "is_verified": f.is_verified,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in items
        ],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get("/recon/findings/{finding_id}")
async def get_finding(
    finding_id: str, db: AsyncSession = Depends(get_db)
) -> dict:
    """Get single finding detail."""
    result = await db.execute(
        select(NormalizedFinding).where(NormalizedFinding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {
        "id": finding.id,
        "tenant_id": finding.tenant_id,
        "engagement_id": finding.engagement_id,
        "target_id": finding.target_id,
        "job_id": finding.job_id,
        "finding_type": finding.finding_type,
        "value": finding.value,
        "data": finding.data,
        "source_tool": finding.source_tool,
        "confidence": finding.confidence,
        "is_verified": finding.is_verified,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
    }
