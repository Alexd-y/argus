"""Stage 1 → Stage 2 dependency check for ARGUS Threat Modeling.

Validates presence of required Stage 1 artifacts before starting Stage 2 TM.
Supports file-based recon_dir and DB-backed artifact_service.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Blocking reason constants
BLOCKED_MISSING_RECON = "blocked_missing_recon"
BLOCKED_INCOMPLETE_RECON = "blocked_incomplete_recon"
BLOCKED_UNLINKED_RECON_ARTIFACTS = "blocked_unlinked_recon_artifacts"

# Required Stage 1 artifacts for Threat Modeling (subset of STAGE1_BASELINE_ARTIFACTS)
STAGE1_BASELINE_ARTIFACTS: tuple[str, ...] = (
    "stage2_structured.json",
    "stage2_inputs.md",
    "ai_stage2_preparation_summary_normalized.json",
)


class Stage1ReadinessResult(BaseModel):
    """Result of Stage 1 readiness check for Threat Modeling."""

    model_config = ConfigDict(frozen=True)

    ready: bool
    blocking_reason: str | None = None
    missing_artifacts: list[str] = ()
    recon_dir: Path | None = None


def _check_artifacts_in_dir(recon_dir: Path) -> tuple[bool, list[str]]:
    """Check required TM artifacts exist in recon_dir. Returns (all_present, missing)."""
    missing: list[str] = []
    for filename in STAGE1_BASELINE_ARTIFACTS:
        path = recon_dir / filename
        if not path.exists() or not path.is_file():
            missing.append(filename)
    return (len(missing) == 0, missing)


async def check_stage1_readiness(
    engagement_id: str,
    target_id: str | None = None,
    recon_dir: Path | None = None,
    db: AsyncSession | None = None,
) -> Stage1ReadinessResult:
    """Check Stage 1 readiness for Threat Modeling (async, supports DB).

    When recon_dir is provided, uses file-based validation.
    When recon_dir is None and db is provided, uses artifact_service.

    Args:
        engagement_id: Engagement ID.
        target_id: Optional target ID; when provided, filters artifacts by target or shared.
        recon_dir: Path to recon directory for file-based check.
        db: AsyncSession for DB-backed artifact lookup.

    Returns:
        Stage1ReadinessResult.
    """
    if recon_dir is not None:
        base = Path(recon_dir)
        if not base.is_dir():
            logger.warning(
                "Recon dir does not exist or is not a directory",
                extra={"engagement_id": engagement_id, "path": str(base)},
            )
            return Stage1ReadinessResult(
                ready=False,
                blocking_reason=BLOCKED_MISSING_RECON,
                missing_artifacts=list(STAGE1_BASELINE_ARTIFACTS),
                recon_dir=base,
            )
        all_present, missing = _check_artifacts_in_dir(base)
        if not all_present:
            return Stage1ReadinessResult(
                ready=False,
                blocking_reason=BLOCKED_INCOMPLETE_RECON,
                missing_artifacts=missing,
                recon_dir=base,
            )
        return Stage1ReadinessResult(
            ready=True,
            blocking_reason=None,
            missing_artifacts=[],
            recon_dir=base,
        )

    if db is None:
        return Stage1ReadinessResult(
            ready=False,
            blocking_reason=BLOCKED_MISSING_RECON,
            missing_artifacts=list(STAGE1_BASELINE_ARTIFACTS),
            recon_dir=None,
        )

    from src.recon.services.artifact_service import get_artifacts_for_engagement

    artifacts = await get_artifacts_for_engagement(db, engagement_id)

    if target_id is not None and artifacts:
        linked = any(
            a.target_id is None or a.target_id == target_id
            for a in artifacts
        )
        if not linked:
            return Stage1ReadinessResult(
                ready=False,
                blocking_reason=BLOCKED_UNLINKED_RECON_ARTIFACTS,
                missing_artifacts=list(STAGE1_BASELINE_ARTIFACTS),
                recon_dir=None,
            )

    present_filenames: set[str] = set()
    for a in artifacts:
        if target_id is not None and a.target_id is not None and a.target_id != target_id:
            continue
        present_filenames.add(a.filename)

    missing = [f for f in STAGE1_BASELINE_ARTIFACTS if f not in present_filenames]

    if missing:
        return Stage1ReadinessResult(
            ready=False,
            blocking_reason=BLOCKED_INCOMPLETE_RECON,
            missing_artifacts=missing,
            recon_dir=None,
        )

    return Stage1ReadinessResult(
        ready=True,
        blocking_reason=None,
        missing_artifacts=[],
        recon_dir=None,
    )
