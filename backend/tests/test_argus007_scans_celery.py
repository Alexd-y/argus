"""Tests for ARGUS-007 Scans router — Celery task integration."""

import sys
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


@pytest.fixture
def mock_db_session_create():
    """Mock async_session_factory for create_scan."""
    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = None

    session = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()
    session.execute = AsyncMock(return_value=tenant_result)

    @asynccontextmanager
    async def _cm():
        yield session

    def factory():
        return _cm()

    return factory


class TestCreateScanUsesCelery:
    """create_scan enqueues scan_phase_task via Celery."""

    def test_create_scan_calls_scan_phase_task_apply_async(
        self,
        client: TestClient,
        mock_db_session_create,
    ) -> None:
        """POST /scans enqueues Celery scan_phase_task via apply_async."""
        with (
            patch(
                "src.api.routers.scans.async_session_factory",
                mock_db_session_create,
            ),
            patch("src.api.routers.scans.scan_phase_task") as mock_task,
        ):
            response = client.post(
                "/api/v1/scans",
                json={
                    "target": "https://example.com",
                    "email": "user@example.com",
                },
            )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "queued"
        assert "scan_id" in data
        mock_task.apply_async.assert_called_once()
        queued_args = mock_task.apply_async.call_args.kwargs["args"]
        assert queued_args[2] == "https://example.com"
