"""Recon target API endpoints."""

import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.session import get_db
from src.recon.schemas.target import ReconTargetCreate, ReconTargetResponse
from src.recon.services.target_service import (
    DuplicateTargetError,
    TargetOutOfScopeError,
    TargetServiceError,
    create_target,
    delete_target,
    get_target,
    list_targets,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["recon-targets"])


def _get_tenant_id() -> str:
    return settings.default_tenant_id


@router.post(
    "/recon/engagements/{engagement_id}/targets",
    response_model=ReconTargetResponse,
    status_code=201,
)
async def create(
    engagement_id: str,
    data: ReconTargetCreate,
    db: AsyncSession = Depends(get_db),
) -> ReconTargetResponse:
    """Add target to engagement (scope-validated)."""
    tenant_id = _get_tenant_id()
    try:
        target = await create_target(db, tenant_id, engagement_id, data)
        return ReconTargetResponse.model_validate(target)
    except TargetOutOfScopeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except DuplicateTargetError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except TargetServiceError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get(
    "/recon/engagements/{engagement_id}/targets",
    response_model=list[ReconTargetResponse],
)
async def list_all(
    engagement_id: str, db: AsyncSession = Depends(get_db)
) -> list[ReconTargetResponse]:
    """List all targets for an engagement."""
    targets = await list_targets(db, engagement_id)
    return [ReconTargetResponse.model_validate(t) for t in targets]


@router.get("/recon/targets/{target_id}", response_model=ReconTargetResponse)
async def get_one(
    target_id: str, db: AsyncSession = Depends(get_db)
) -> ReconTargetResponse:
    """Get target detail."""
    tenant_id = _get_tenant_id()
    target = await get_target(db, tenant_id, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return ReconTargetResponse.model_validate(target)


@router.delete("/recon/targets/{target_id}", status_code=204)
async def remove(
    target_id: str, db: AsyncSession = Depends(get_db)
) -> None:
    """Delete target."""
    tenant_id = _get_tenant_id()
    deleted = await delete_target(db, tenant_id, target_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Target not found")
