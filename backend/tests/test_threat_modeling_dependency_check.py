"""Tests for Stage 1 → Stage 2 dependency check (Threat Modeling)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError
from src.recon.threat_modeling.dependency_check import (
    BLOCKED_INCOMPLETE_RECON,
    BLOCKED_MISSING_RECON,
    BLOCKED_UNLINKED_RECON_ARTIFACTS,
    STAGE1_BASELINE_ARTIFACTS,
    Stage1ReadinessResult,
    check_stage1_readiness,
)


@pytest.mark.asyncio
async def test_check_stage1_readiness_nonexistent_recon_dir() -> None:
    """Non-existent recon dir returns blocked_missing_recon."""
    result = await check_stage1_readiness("e1", recon_dir=Path("/nonexistent/path"))
    assert result.ready is False
    assert result.blocking_reason == BLOCKED_MISSING_RECON
    assert set(result.missing_artifacts) == set(STAGE1_BASELINE_ARTIFACTS)


@pytest.mark.asyncio
async def test_check_stage1_readiness_empty_recon_dir(tmp_path: Path) -> None:
    """Empty recon dir returns blocked_incomplete_recon."""
    result = await check_stage1_readiness("e1", recon_dir=tmp_path)
    assert result.ready is False
    assert result.blocking_reason == BLOCKED_INCOMPLETE_RECON
    assert set(result.missing_artifacts) == set(STAGE1_BASELINE_ARTIFACTS)


@pytest.mark.asyncio
async def test_check_stage1_readiness_partial_recon_dir(tmp_path: Path) -> None:
    """Partial artifacts returns blocked_incomplete_recon with specific missing list."""
    (tmp_path / "stage2_inputs.md").write_text("# Stage 2")
    result = await check_stage1_readiness("e1", recon_dir=tmp_path)
    assert result.ready is False
    assert result.blocking_reason == BLOCKED_INCOMPLETE_RECON
    assert "stage2_inputs.md" not in result.missing_artifacts
    assert "stage2_structured.json" in result.missing_artifacts
    assert "ai_stage2_preparation_summary_normalized.json" in result.missing_artifacts


@pytest.mark.asyncio
async def test_check_stage1_readiness_complete_recon_dir(tmp_path: Path) -> None:
    """All required artifacts present returns ready=True."""
    for filename in STAGE1_BASELINE_ARTIFACTS:
        (tmp_path / filename).write_text("{}")
    result = await check_stage1_readiness("e1", recon_dir=tmp_path)
    assert result.ready is True
    assert result.blocking_reason is None
    assert result.missing_artifacts == []
    assert result.recon_dir == tmp_path


@pytest.mark.asyncio
async def test_check_stage1_readiness_no_recon_no_db() -> None:
    """No recon_dir and no db returns blocked_missing_recon."""
    result = await check_stage1_readiness("e1")
    assert result.ready is False
    assert result.blocking_reason == BLOCKED_MISSING_RECON
    assert result.recon_dir is None


@pytest.mark.asyncio
async def test_check_stage1_readiness_db_complete() -> None:
    """DB mode with all artifacts returns ready=True."""
    mock_artifact = MagicMock()
    mock_artifact.filename = "stage2_structured.json"
    mock_artifact.target_id = None

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
    """DB mode with missing artifacts returns blocked_incomplete_recon."""
    with patch(
        "src.recon.services.artifact_service.get_artifacts_for_engagement",
        new_callable=AsyncMock,
    ) as mock_get:
        mock_get.return_value = [
            MagicMock(filename="stage2_inputs.md", target_id=None),
        ]

        result = await check_stage1_readiness("e1", db=AsyncMock())

    assert result.ready is False
    assert result.blocking_reason == BLOCKED_INCOMPLETE_RECON
    assert "stage2_structured.json" in result.missing_artifacts
    assert "ai_stage2_preparation_summary_normalized.json" in result.missing_artifacts


@pytest.mark.asyncio
async def test_check_stage1_readiness_db_unlinked_target() -> None:
    """DB mode with target_id but artifacts only for other target returns blocked_unlinked."""
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

    assert result.ready is False
    assert result.blocking_reason == BLOCKED_UNLINKED_RECON_ARTIFACTS


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
