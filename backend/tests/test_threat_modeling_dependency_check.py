"""Tests for Stage 1 → Stage 2 dependency check (Threat Modeling).

Since the removal of pentest blocking policies, this check is advisory only:
it always returns ``ready=True`` and surfaces an informational ``*_notice``
``blocking_reason`` plus ``missing_artifacts`` when recon is incomplete.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from src.recon.threat_modeling.dependency_check import (
    INCOMPLETE_RECON_NOTICE,
    MISSING_RECON_NOTICE,
    STAGE1_BASELINE_ARTIFACTS,
    UNLINKED_RECON_NOTICE,
    Stage1ReadinessResult,
    check_stage1_readiness,
)


@pytest.mark.asyncio
async def test_check_stage1_readiness_nonexistent_recon_dir() -> None:
    """Non-existent recon dir returns advisory missing_recon_notice (never blocks)."""
    result = await check_stage1_readiness("e1", recon_dir=Path("/nonexistent/path"))
    assert result.ready is True
    assert result.blocking_reason == MISSING_RECON_NOTICE
    assert set(result.missing_artifacts) == set(STAGE1_BASELINE_ARTIFACTS)


@pytest.mark.asyncio
async def test_check_stage1_readiness_empty_recon_dir(tmp_path: Path) -> None:
    """Empty recon dir returns advisory incomplete_recon_notice."""
    result = await check_stage1_readiness("e1", recon_dir=tmp_path)
    assert result.ready is True
    assert result.blocking_reason == INCOMPLETE_RECON_NOTICE
    assert set(result.missing_artifacts) == set(STAGE1_BASELINE_ARTIFACTS)


@pytest.mark.asyncio
async def test_check_stage1_readiness_partial_recon_dir(tmp_path: Path) -> None:
    """Partial artifacts returns advisory incomplete_recon_notice with specific missing list."""
    (tmp_path / "stage2_inputs.md").write_text("# Stage 2")
    result = await check_stage1_readiness("e1", recon_dir=tmp_path)
    assert result.ready is True
    assert result.blocking_reason == INCOMPLETE_RECON_NOTICE
    assert "stage2_inputs.md" not in result.missing_artifacts
    assert "stage2_structured.json" in result.missing_artifacts
    assert "ai_stage2_preparation_summary_normalized.json" in result.missing_artifacts


@pytest.mark.asyncio
async def test_check_stage1_readiness_complete_recon_dir(tmp_path: Path) -> None:
    """All required artifacts present returns ready=True with no notice."""
    for filename in STAGE1_BASELINE_ARTIFACTS:
        (tmp_path / filename).write_text("{}")
    result = await check_stage1_readiness("e1", recon_dir=tmp_path)
    assert result.ready is True
    assert result.blocking_reason is None
    assert result.missing_artifacts == []
    assert result.recon_dir == tmp_path


@pytest.mark.asyncio
async def test_check_stage1_readiness_no_recon_no_db() -> None:
    """No recon_dir and no db is advisory: ready=True with no notice (never blocks)."""
    result = await check_stage1_readiness("e1")
    assert result.ready is True
    assert result.blocking_reason is None
    assert result.recon_dir is None


@pytest.mark.asyncio
async def test_check_stage1_readiness_db_complete() -> None:
    """DB mode with all artifacts returns ready=True."""
    mock_db = AsyncMock()
    with patch(
        "src.recon.services.artifact_service.get_artifacts_for_engagement",
        new_callable=AsyncMock,
    ) as mock_get:
        artifacts = [
            MagicMock(filename="stage2_structured.json", target_id=None),
            MagicMock(filename="stage2_inputs.md", target_id=None),
            MagicMock(filename="ai_stage2_preparation_summary_normalized.json", target_id=None),
        ]
        mock_get.return_value = artifacts

        result = await check_stage1_readiness("e1", db=mock_db)

    assert result.ready is True
    assert result.blocking_reason is None
    assert result.missing_artifacts == []


@pytest.mark.asyncio
async def test_check_stage1_readiness_db_incomplete() -> None:
    """DB mode with missing artifacts returns advisory incomplete_recon_notice."""
    with patch(
        "src.recon.services.artifact_service.get_artifacts_for_engagement",
        new_callable=AsyncMock,
    ) as mock_get:
        mock_get.return_value = [
            MagicMock(filename="stage2_inputs.md", target_id=None),
        ]

        result = await check_stage1_readiness("e1", db=AsyncMock())

    assert result.ready is True
    assert result.blocking_reason == INCOMPLETE_RECON_NOTICE
    assert "stage2_structured.json" in result.missing_artifacts
    assert "ai_stage2_preparation_summary_normalized.json" in result.missing_artifacts


@pytest.mark.asyncio
async def test_check_stage1_readiness_db_unlinked_target() -> None:
    """DB mode with target_id but artifacts only for other target returns unlinked_recon_notice."""
    with patch(
        "src.recon.services.artifact_service.get_artifacts_for_engagement",
        new_callable=AsyncMock,
    ) as mock_get:
        mock_get.return_value = [
            MagicMock(filename="stage2_inputs.md", target_id="other-target-id"),
        ]

        result = await check_stage1_readiness(
            "e1", target_id="my-target-id", db=AsyncMock()
        )

    assert result.ready is True
    assert result.blocking_reason == UNLINKED_RECON_NOTICE


@pytest.mark.asyncio
async def test_check_stage1_readiness_db_linked_target() -> None:
    """DB mode with target_id and matching/shared artifacts returns ready when complete."""
    with patch(
        "src.recon.services.artifact_service.get_artifacts_for_engagement",
        new_callable=AsyncMock,
    ) as mock_get:
        mock_get.return_value = [
            MagicMock(filename="stage2_structured.json", target_id="my-target-id"),
            MagicMock(filename="stage2_inputs.md", target_id=None),
            MagicMock(filename="ai_stage2_preparation_summary_normalized.json", target_id="my-target-id"),
        ]

        result = await check_stage1_readiness(
            "e1", target_id="my-target-id", db=AsyncMock()
        )

    assert result.ready is True
    assert result.blocking_reason is None


def test_stage1_readiness_result_frozen() -> None:
    """Stage1ReadinessResult is frozen (immutable)."""
    r = Stage1ReadinessResult(ready=True, blocking_reason=None)
    with pytest.raises(ValidationError):
        r.ready = False
