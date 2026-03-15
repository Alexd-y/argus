"""Unit tests for threat_model_run_service (TM-008).

Covers: resolve_recon_dir, validate_recon_dir_within_base, create_threat_model_run,
get_threat_model_run. Uses pytest, pytest-asyncio. Mocks AsyncSession for DB.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.recon.services.threat_model_run_service import (
    create_threat_model_run,
    get_threat_model_run,
    resolve_recon_dir,
    validate_recon_dir_within_base,
)


class TestResolveReconDir:
    """resolve_recon_dir from scope_config."""

    def test_resolve_recon_dir_default_when_no_scope_config(self) -> None:
        """Uses default path when scope_config is None."""
        with patch(
            "src.recon.services.threat_model_run_service.settings"
        ) as mock_settings:
            mock_settings.recon_output_base_dir = "/base/recon"
            result = resolve_recon_dir("eng-001", scope_config=None)
        assert "eng-001" in str(result)
        assert "pentest_reports_eng-001" in str(result)
        assert result.name == "recon"

    def test_resolve_recon_dir_from_scope_config_absolute(self) -> None:
        """Uses scope_config.recon_dir when absolute path."""
        with patch(
            "src.recon.services.threat_model_run_service.settings"
        ) as mock_settings:
            mock_settings.recon_output_base_dir = "/base/recon"
            result = resolve_recon_dir(
                "eng-002",
                scope_config={"recon_dir": "/custom/path/to/recon"},
            )
        assert str(result).endswith("recon") or "recon" in str(result)
        assert "custom" in str(result) and "path" in str(result)

    def test_resolve_recon_dir_from_scope_config_relative(self) -> None:
        """Uses base + relative path when scope_config.recon_dir is relative."""
        with patch(
            "src.recon.services.threat_model_run_service.settings"
        ) as mock_settings:
            mock_settings.recon_output_base_dir = "/base/recon_output"
            result = resolve_recon_dir(
                "eng-003",
                scope_config={"recon_dir": "eng-003/recon"},
            )
        assert "base" in str(result) and "recon_output" in str(result)
        assert "eng-003" in str(result)

    def test_resolve_recon_dir_ignores_non_string(self) -> None:
        """Falls back to default when recon_dir is not a string."""
        with patch(
            "src.recon.services.threat_model_run_service.settings"
        ) as mock_settings:
            mock_settings.recon_output_base_dir = "/base"
            result = resolve_recon_dir(
                "eng-004",
                scope_config={"recon_dir": 123},
            )
        assert "pentest_reports_eng-004" in str(result)


class TestValidateReconDirWithinBase:
    """validate_recon_dir_within_base rejects path traversal."""

    def test_valid_path_within_base(self, tmp_path: Path) -> None:
        """Path within base returns resolved Path."""
        sub = tmp_path / "eng" / "recon"
        sub.mkdir(parents=True, exist_ok=True)
        with patch(
            "src.recon.services.threat_model_run_service._get_recon_base_dir",
            return_value=tmp_path,
        ):
            result = validate_recon_dir_within_base(str(sub))
        assert result == sub.resolve()

    def test_path_traversal_rejected(self) -> None:
        """Path outside base raises ValueError."""
        with (
            patch(
                "src.recon.services.threat_model_run_service._get_recon_base_dir",
                return_value=Path("/allowed/base").resolve(),
            ),
            pytest.raises(ValueError, match="Invalid recon_dir path"),
        ):
            validate_recon_dir_within_base("/etc/passwd")

    def test_path_traversal_with_dotdot_rejected(self, tmp_path: Path) -> None:
        """Path with .. escaping base raises ValueError."""
        base = tmp_path / "base"
        base.mkdir()
        escape = tmp_path / "base" / "eng" / ".." / ".." / "etc"
        with patch(
            "src.recon.services.threat_model_run_service._get_recon_base_dir",
            return_value=base,
        ), pytest.raises(ValueError, match="Invalid recon_dir path"):
            validate_recon_dir_within_base(str(escape))


class TestCreateThreatModelRun:
    """create_threat_model_run."""

    @pytest.mark.asyncio
    async def test_create_threat_model_run_returns_run(self) -> None:
        """Creates ThreatModelRun with expected fields."""
        mock_db = AsyncMock()
        mock_db.flush = AsyncMock()
        mock_db.add = MagicMock()

        run = await create_threat_model_run(
            mock_db,
            tenant_id="tenant-1",
            engagement_id="eng-001",
            target_id=None,
            job_id=None,
        )

        assert run is not None
        assert run.engagement_id == "eng-001"
        assert run.tenant_id == "tenant-1"
        assert run.status == "pending"
        assert run.run_id is not None
        assert len(run.run_id) == 36
        assert run.job_id is not None
        assert run.input_bundle_ref is not None
        assert "engagement:eng-001" in run.input_bundle_ref
        mock_db.add.assert_called_once()
        mock_db.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_threat_model_run_with_job_id(self) -> None:
        """Uses provided job_id when given."""
        mock_db = AsyncMock()
        mock_db.flush = AsyncMock()
        mock_db.add = MagicMock()

        run = await create_threat_model_run(
            mock_db,
            tenant_id="tenant-1",
            engagement_id="eng-002",
            job_id="custom-job-123",
        )

        assert run.job_id == "custom-job-123"
        assert "custom-job-123" in run.input_bundle_ref

    @pytest.mark.asyncio
    async def test_create_threat_model_run_with_target_id(self) -> None:
        """Stores target_id when provided."""
        mock_db = AsyncMock()
        mock_db.flush = AsyncMock()
        mock_db.add = MagicMock()

        run = await create_threat_model_run(
            mock_db,
            tenant_id="tenant-1",
            engagement_id="eng-003",
            target_id="target-abc",
        )

        assert run.target_id == "target-abc"


class TestGetThreatModelRun:
    """get_threat_model_run."""

    @pytest.mark.asyncio
    async def test_get_threat_model_run_returns_run_when_found(self) -> None:
        """Returns run when it exists."""
        mock_run = MagicMock()
        mock_run.id = "run-db-id"
        mock_run.run_id = "run-123"
        mock_run.engagement_id = "eng-001"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_run

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)

        result = await get_threat_model_run(
            mock_db,
            tenant_id="tenant-1",
            engagement_id="eng-001",
            run_id="run-db-id",
        )

        assert result is mock_run
        assert result.run_id == "run-123"

    @pytest.mark.asyncio
    async def test_get_threat_model_run_returns_none_when_not_found(self) -> None:
        """Returns None when run does not exist."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)

        result = await get_threat_model_run(
            mock_db,
            tenant_id="tenant-1",
            engagement_id="eng-001",
            run_id="nonexistent-run",
        )

        assert result is None
