"""BKL-004: Scan lifecycle — cancel_scan revoke + exploitation 503 on dispatch failure.

Tests:
- cancel_scan calls celery_app.control.revoke
- exploitation endpoint returns 503 when send_task raises
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestCancelScanRevoke:
    """BKL-004: cancel_scan must call celery_app.control.revoke with scan_id."""

    @pytest.mark.asyncio
    async def test_cancel_scan_calls_revoke(self) -> None:
        scan_id = "test-scan-123"

        mock_scan = MagicMock()
        mock_scan.id = scan_id
        mock_scan.status = "running"
        mock_scan.tenant_id = "tenant-1"

        mock_session_ctx = AsyncMock()
        mock_session = mock_session_ctx.__aenter__.return_value
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_scan
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        mock_celery = MagicMock()
        mock_celery.control.revoke = MagicMock()

        with (
            patch(
                "src.api.routers.scans.async_session_factory",
                return_value=mock_session_ctx,
            ),
            patch(
                "src.api.routers.scans.set_session_tenant",
                new_callable=AsyncMock,
            ),
            patch(
                "src.api.routers.scans.celery_app",
                mock_celery,
            ),
        ):
            from src.api.routers.scans import cancel_scan

            result = await cancel_scan(scan_id, tenant_id="tenant-1")

        mock_celery.control.revoke.assert_called_once_with(
            scan_id, terminate=True, signal="SIGTERM",
        )
        assert result.status == "cancelled"
        assert result.scan_id == scan_id

    @pytest.mark.asyncio
    async def test_cancel_scan_survives_revoke_failure(self) -> None:
        """cancel_scan should still return cancelled even if revoke raises."""
        scan_id = "test-scan-456"

        mock_scan = MagicMock()
        mock_scan.id = scan_id
        mock_scan.status = "running"
        mock_scan.tenant_id = "tenant-1"

        mock_session_ctx = AsyncMock()
        mock_session = mock_session_ctx.__aenter__.return_value
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_scan
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        mock_celery = MagicMock()
        mock_celery.control.revoke.side_effect = ConnectionError("broker down")

        with (
            patch(
                "src.api.routers.scans.async_session_factory",
                return_value=mock_session_ctx,
            ),
            patch(
                "src.api.routers.scans.set_session_tenant",
                new_callable=AsyncMock,
            ),
            patch(
                "src.api.routers.scans.celery_app",
                mock_celery,
            ),
        ):
            from src.api.routers.scans import cancel_scan

            result = await cancel_scan(scan_id, tenant_id="tenant-1")

        assert result.status == "cancelled"


class TestExploitation503OnDispatchFailure:
    """BKL-004: exploitation endpoint must return 503 when send_task raises."""

    @pytest.mark.asyncio
    async def test_exploitation_returns_503_on_send_task_error(self) -> None:
        from fastapi import HTTPException

        engagement_id = "eng-001"

        mock_engagement = MagicMock()
        mock_engagement.id = engagement_id
        mock_engagement.tenant_id = "tenant-1"

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_engagement
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.add = MagicMock()
        mock_db.flush = AsyncMock()

        mock_celery = MagicMock()
        mock_celery.send_task.side_effect = ConnectionError("no worker")

        with (
            patch(
                "src.api.routers.recon.exploitation._get_tenant_id",
                return_value="tenant-1",
            ),
            patch(
                "src.api.routers.recon.exploitation.celery_app",
                mock_celery,
            ),
        ):
            from src.api.routers.recon.exploitation import start_exploitation_run

            with pytest.raises(HTTPException) as exc_info:
                await start_exploitation_run(engagement_id, body=None, db=mock_db)

        assert exc_info.value.status_code == 503
        assert "dispatch failed" in exc_info.value.detail.lower() or "worker" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_exploitation_marks_run_failed_on_dispatch_error(self) -> None:
        from fastapi import HTTPException

        engagement_id = "eng-002"

        mock_engagement = MagicMock()
        mock_engagement.id = engagement_id
        mock_engagement.tenant_id = "tenant-1"

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_engagement
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.flush = AsyncMock()

        captured_run = {}

        original_add = mock_db.add

        def capture_add(obj: MagicMock) -> None:
            captured_run["obj"] = obj

        mock_db.add = capture_add

        mock_celery = MagicMock()
        mock_celery.send_task.side_effect = RuntimeError("queue unavailable")

        with (
            patch(
                "src.api.routers.recon.exploitation._get_tenant_id",
                return_value="tenant-1",
            ),
            patch(
                "src.api.routers.recon.exploitation.celery_app",
                mock_celery,
            ),
        ):
            from src.api.routers.recon.exploitation import start_exploitation_run

            with pytest.raises(HTTPException):
                await start_exploitation_run(engagement_id, body=None, db=mock_db)

        assert captured_run.get("obj") is not None
        assert captured_run["obj"].status == "failed"
