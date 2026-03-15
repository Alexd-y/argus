"""Scope enforcement - high-level functions for scope checking with DB integration."""

import logging
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_recon import Engagement
from src.recon.schemas.scope import ScopeConfig, ScopeValidationResult
from src.recon.scope.validator import ScopeValidator

logger = logging.getLogger(__name__)


async def get_scope_validator(db: AsyncSession, engagement_id: str) -> ScopeValidator | None:
    """Load engagement scope config and create ScopeValidator."""
    result = await db.execute(
        select(Engagement).where(Engagement.id == engagement_id)
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        return None

    scope_data = engagement.scope_config or {}
    scope_config = ScopeConfig(**scope_data) if scope_data else ScopeConfig()
    return ScopeValidator(scope_config)


async def enforce_scope(
    db: AsyncSession,
    engagement_id: str,
    value: str,
    value_type: str = "domain",
) -> ScopeValidationResult:
    """Check if value is in engagement scope. Returns out-of-scope if engagement not found."""
    validator = await get_scope_validator(db, engagement_id)
    if not validator:
        return ScopeValidationResult(
            is_in_scope=False, reason=f"Engagement {engagement_id} not found"
        )
    return validator.is_in_scope(value, value_type)


async def filter_in_scope(
    db: AsyncSession,
    engagement_id: str,
    values: list[str],
    value_type: str = "domain",
) -> list[str]:
    """Batch filter - returns only in-scope values."""
    validator = await get_scope_validator(db, engagement_id)
    if not validator:
        return []
    return validator.filter_in_scope(values, value_type)
