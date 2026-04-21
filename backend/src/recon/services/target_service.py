"""Target service - CRUD with scope validation."""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_recon import Engagement, ReconTarget
from src.recon.schemas.target import ReconTargetCreate
from src.recon.scope.validator import ScopeValidator
from src.recon.schemas.scope import ScopeConfig

logger = logging.getLogger(__name__)


class TargetServiceError(Exception):
    """Base error for target service."""


class TargetNotFoundError(TargetServiceError):
    """Target not found."""


class TargetOutOfScopeError(TargetServiceError):
    """Target is not within engagement scope."""


class DuplicateTargetError(TargetServiceError):
    """Target already exists for this engagement."""


async def create_target(
    db: AsyncSession,
    tenant_id: str,
    engagement_id: str,
    data: ReconTargetCreate,
) -> ReconTarget:
    """Create target after scope validation."""
    eng_result = await db.execute(
        select(Engagement).where(
            Engagement.id == engagement_id, Engagement.tenant_id == tenant_id
        )
    )
    engagement = eng_result.scalar_one_or_none()
    if not engagement:
        raise TargetServiceError(f"Engagement {engagement_id} not found")

    scope_data = engagement.scope_config or {}
    scope = ScopeConfig(**scope_data) if scope_data else ScopeConfig()
    if scope.rules:
        validator = ScopeValidator(scope)
        result = validator.validate_target(data.domain, data.target_type.value)
        if not result.is_in_scope:
            raise TargetOutOfScopeError(
                f"Target {data.domain} is out of scope: {result.reason}"
            )

    existing = await db.execute(
        select(ReconTarget).where(
            ReconTarget.engagement_id == engagement_id,
            ReconTarget.domain == data.domain,
        )
    )
    if existing.scalar_one_or_none():
        raise DuplicateTargetError(
            f"Target {data.domain} already exists in engagement {engagement_id}"
        )

    target = ReconTarget(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        domain=data.domain,
        target_type=data.target_type.value,
        extra_data=data.extra_data,
    )
    db.add(target)
    await db.flush()
    logger.info("Target created", extra={"target_id": target.id, "domain": data.domain})
    return target


async def get_target(
    db: AsyncSession, tenant_id: str, target_id: str
) -> ReconTarget | None:
    """Get target by ID, scoped to tenant."""
    result = await db.execute(
        select(ReconTarget).where(
            ReconTarget.id == target_id, ReconTarget.tenant_id == tenant_id
        )
    )
    return result.scalar_one_or_none()


async def list_targets(
    db: AsyncSession, engagement_id: str
) -> list[ReconTarget]:
    """List all targets for an engagement."""
    result = await db.execute(
        select(ReconTarget)
        .where(ReconTarget.engagement_id == engagement_id)
        .order_by(ReconTarget.created_at)
    )
    return list(result.scalars().all())


async def delete_target(
    db: AsyncSession, tenant_id: str, target_id: str
) -> bool:
    """Delete target if it belongs to tenant."""
    target = await get_target(db, tenant_id, target_id)
    if not target:
        return False
    await db.delete(target)
    await db.flush()
    logger.info("Target deleted", extra={"target_id": target_id})
    return True
