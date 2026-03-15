"""Threat model run service — CRUD and recon_dir resolution."""

from __future__ import annotations

import logging
from pathlib import Path
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.models_recon import Engagement, ThreatModelRun

logger = logging.getLogger(__name__)


class ThreatModelRunNotFoundError(Exception):
    """Threat model run not found."""


def _get_recon_base_dir() -> Path:
    """Return resolved base directory for recon output (path traversal guard)."""
    return Path(settings.recon_output_base_dir).resolve()


def validate_recon_dir_within_base(recon_dir_str: str) -> Path:
    """Validate recon_dir is within allowed base. Raises ValueError if outside base."""
    base = _get_recon_base_dir()
    resolved = Path(recon_dir_str).resolve()
    try:
        resolved.relative_to(base)
    except ValueError:
        raise ValueError("Invalid recon_dir path") from None
    return resolved


def resolve_recon_dir(
    engagement_id: str,
    scope_config: dict | None = None,
) -> Path:
    """Resolve recon directory path for engagement.

    Uses scope_config.recon_dir if present, else default:
    {recon_output_base_dir}/pentest_reports_{engagement_id}/recon/
    """
    if scope_config and isinstance(scope_config.get("recon_dir"), str):
        path = Path(scope_config["recon_dir"])
        if path.is_absolute():
            return path.resolve()
        return (Path(settings.recon_output_base_dir) / path).resolve()
    base = Path(settings.recon_output_base_dir)
    return (base / f"pentest_reports_{engagement_id}" / "recon").resolve()


async def get_engagement(db: AsyncSession, tenant_id: str, engagement_id: str) -> Engagement | None:
    """Get engagement by ID, scoped to tenant."""
    result = await db.execute(
        select(Engagement).where(
            Engagement.id == engagement_id,
            Engagement.tenant_id == tenant_id,
        )
    )
    return result.scalar_one_or_none()


async def create_threat_model_run(
    db: AsyncSession,
    tenant_id: str,
    engagement_id: str,
    *,
    target_id: str | None = None,
    job_id: str | None = None,
) -> ThreatModelRun:
    """Create ThreatModelRun record (pending, not executed)."""
    run_id = str(uuid4())
    j_id = job_id or f"tm_{run_id[:8]}"
    input_bundle_ref = f"engagement:{engagement_id}:run:{run_id}:job:{j_id}"

    run = ThreatModelRun(
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
        "Threat model run created",
        extra={"run_id": run_id, "engagement_id": engagement_id, "job_id": j_id},
    )
    return run


async def get_threat_model_run(
    db: AsyncSession,
    tenant_id: str,
    engagement_id: str,
    run_id: str,
) -> ThreatModelRun | None:
    """Get threat model run by ID, scoped to engagement and tenant."""
    result = await db.execute(
        select(ThreatModelRun).where(
            ThreatModelRun.id == run_id,
            ThreatModelRun.engagement_id == engagement_id,
            ThreatModelRun.tenant_id == tenant_id,
        )
    )
    return result.scalar_one_or_none()


async def list_threat_model_runs(
    db: AsyncSession,
    tenant_id: str,
    engagement_id: str,
) -> list[ThreatModelRun]:
    """List threat model runs for engagement."""
    result = await db.execute(
        select(ThreatModelRun)
        .where(
            ThreatModelRun.engagement_id == engagement_id,
            ThreatModelRun.tenant_id == tenant_id,
        )
        .order_by(ThreatModelRun.created_at.desc())
    )
    return list(result.scalars().all())
