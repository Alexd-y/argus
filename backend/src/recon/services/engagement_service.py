"""Engagement service - CRUD and lifecycle management."""

import logging
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_recon import (
    Artifact,
    Engagement,
    NormalizedFinding,
    ReconTarget,
    ScanJob,
)
from src.recon.schemas.engagement import EngagementCreate, EngagementUpdate
from src.recon.schemas.scope import ScopeConfig

logger = logging.getLogger(__name__)


class EngagementServiceError(Exception):
    """Base error for engagement service."""


class EngagementNotFoundError(EngagementServiceError):
    """Engagement not found."""


class EngagementStateError(EngagementServiceError):
    """Invalid state transition."""


async def create_engagement(
    db: AsyncSession, tenant_id: str, data: EngagementCreate
) -> Engagement:
    """Create a new engagement."""
    engagement = Engagement(
        tenant_id=tenant_id,
        name=data.name,
        description=data.description,
        status="draft",
        scope_config=data.scope_config.model_dump() if data.scope_config else None,
        contacts=[c.model_dump() for c in data.contacts] if data.contacts else None,
        environment=data.environment.value if data.environment else "production",
    )
    db.add(engagement)
    await db.flush()
    logger.info("Engagement created", extra={"engagement_id": engagement.id, "engagement_name": engagement.name})
    return engagement


async def get_engagement(
    db: AsyncSession, tenant_id: str, engagement_id: str
) -> Engagement | None:
    """Get engagement by ID, scoped to tenant."""
    result = await db.execute(
        select(Engagement).where(
            Engagement.id == engagement_id,
            Engagement.tenant_id == tenant_id,
        )
    )
    return result.scalar_one_or_none()


async def list_engagements(
    db: AsyncSession,
    tenant_id: str,
    status: str | None = None,
    offset: int = 0,
    limit: int = 20,
) -> tuple[list[Engagement], int]:
    """List engagements with optional status filter. Returns (items, total)."""
    base = select(Engagement).where(Engagement.tenant_id == tenant_id)
    if status:
        base = base.where(Engagement.status == status)

    count_stmt = select(func.count()).select_from(base.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    items_stmt = base.order_by(Engagement.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(items_stmt)
    items = list(result.scalars().all())
    return items, total


async def update_engagement(
    db: AsyncSession, tenant_id: str, engagement_id: str, data: EngagementUpdate
) -> Engagement:
    """Update engagement fields."""
    engagement = await get_engagement(db, tenant_id, engagement_id)
    if not engagement:
        raise EngagementNotFoundError(f"Engagement {engagement_id} not found")

    if data.name is not None:
        engagement.name = data.name
    if data.description is not None:
        engagement.description = data.description
    if data.scope_config is not None:
        engagement.scope_config = data.scope_config.model_dump()
    if data.contacts is not None:
        engagement.contacts = [c.model_dump() for c in data.contacts]
    if data.environment is not None:
        engagement.environment = data.environment.value

    await db.flush()
    logger.info("Engagement updated", extra={"engagement_id": engagement_id})
    return engagement


async def activate_engagement(
    db: AsyncSession, tenant_id: str, engagement_id: str
) -> Engagement:
    """Activate engagement - validates scope is configured."""
    engagement = await get_engagement(db, tenant_id, engagement_id)
    if not engagement:
        raise EngagementNotFoundError(f"Engagement {engagement_id} not found")

    if engagement.status not in ("draft", "paused"):
        raise EngagementStateError(
            f"Cannot activate engagement in status: {engagement.status}"
        )

    scope_data = engagement.scope_config or {}
    scope = ScopeConfig(**scope_data) if scope_data else ScopeConfig()
    if not scope.rules:
        raise EngagementStateError("Cannot activate: no scope rules defined")

    engagement.status = "active"
    engagement.started_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(engagement)
    logger.info("Engagement activated", extra={"engagement_id": engagement_id})
    return engagement


async def complete_engagement(
    db: AsyncSession, tenant_id: str, engagement_id: str
) -> Engagement:
    """Mark engagement as completed."""
    engagement = await get_engagement(db, tenant_id, engagement_id)
    if not engagement:
        raise EngagementNotFoundError(f"Engagement {engagement_id} not found")

    if engagement.status != "active":
        raise EngagementStateError(
            f"Cannot complete engagement in status: {engagement.status}"
        )

    engagement.status = "completed"
    engagement.completed_at = datetime.now(timezone.utc)
    await db.flush()
    logger.info("Engagement completed", extra={"engagement_id": engagement_id})
    return engagement


async def get_engagement_stats(db: AsyncSession, engagement_id: str) -> dict:
    """Get aggregate stats for an engagement."""
    targets = (await db.execute(
        select(func.count()).select_from(
            select(ReconTarget.id).where(ReconTarget.engagement_id == engagement_id).subquery()
        )
    )).scalar() or 0

    jobs = (await db.execute(
        select(func.count()).select_from(
            select(ScanJob.id).where(ScanJob.engagement_id == engagement_id).subquery()
        )
    )).scalar() or 0

    findings = (await db.execute(
        select(func.count()).select_from(
            select(NormalizedFinding.id).where(
                NormalizedFinding.engagement_id == engagement_id
            ).subquery()
        )
    )).scalar() or 0

    artifacts = (await db.execute(
        select(func.count()).select_from(
            select(Artifact.id).where(Artifact.engagement_id == engagement_id).subquery()
        )
    )).scalar() or 0

    return {
        "target_count": targets,
        "job_count": jobs,
        "finding_count": findings,
        "artifact_count": artifacts,
    }
