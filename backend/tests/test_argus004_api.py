"""API integration tests for ARGUS-004 (Scan State Machine).

POST /scans creates scan and returns scan_id; GET /scans/:id with mocked DB.
"""

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient


@pytest.fixture
def mock_db_session_create():
    """Mock async_session_factory for create_scan — tenant lookup returns None."""
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


class TestPostScansArgus004:
    """POST /api/v1/scans — creates scan, returns scan_id."""

    def test_post_scans_returns_201_and_scan_id(
        self,
        client: TestClient,
        mock_db_session_create,
    ) -> None:
        """POST /scans returns 201 and valid scan_id."""
        with (
            patch(
                "src.api.routers.scans.async_session_factory",
                mock_db_session_create,
            ),
            patch("src.api.routers.scans.scan_phase_task"),
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
        assert "scan_id" in data
        assert data["status"] == "queued"
        assert data["message"] == "Scan queued successfully"
        uuid.UUID(data["scan_id"])

    def test_post_scans_with_options(
        self,
        client: TestClient,
        mock_db_session_create,
    ) -> None:
        """POST /scans accepts optional options."""
        with (
            patch(
                "src.api.routers.scans.async_session_factory",
                mock_db_session_create,
            ),
            patch("src.api.routers.scans.scan_phase_task"),
        ):
            response = client.post(
                "/api/v1/scans",
                json={
                    "target": "https://target.com",
                    "email": "admin@test.com",
                    "options": {
                        "scanType": "deep",
                        "reportFormat": "pdf",
                    },
                },
            )
        assert response.status_code == 201
        assert "scan_id" in response.json()


class TestGetScanArgus004:
    """GET /api/v1/scans/:id — returns scan detail."""

    def test_get_scan_returns_200_with_mock_db(
        self,
        client: TestClient,
    ) -> None:
        """GET /scans/:id returns 200 and scan structure when scan exists."""
        scan_id = str(uuid.uuid4())
        scan_result = MagicMock()
        mock_scan = MagicMock()
        mock_scan.id = scan_id
        mock_scan.status = "running"
        mock_scan.progress = 50
        mock_scan.phase = "vuln_analysis"
        mock_scan.target_url = "https://target.com"
        mock_scan.created_at = datetime.now(UTC)
        scan_result.scalar_one_or_none.return_value = mock_scan

        session = AsyncMock()
        session.execute = AsyncMock(return_value=scan_result)

        @asynccontextmanager
        async def _cm():
            yield session

        def factory():
            return _cm()

        with patch(
            "src.api.routers.scans.async_session_factory",
            factory,
        ):
            response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == scan_id
        assert data["status"] == "running"
        assert data["progress"] == 50
        assert data["phase"] == "vuln_analysis"
        assert data["target"] == "https://target.com"
        assert "created_at" in data

    def test_get_scan_nonexistent_returns_404(
        self,
        client: TestClient,
    ) -> None:
        """GET /scans/:id with non-existent ID returns 404."""
        scan_id = str(uuid.uuid4())
        scan_result = MagicMock()
        scan_result.scalar_one_or_none.return_value = None

        session = AsyncMock()
        session.execute = AsyncMock(return_value=scan_result)

        @asynccontextmanager
        async def _cm():
            yield session

        def factory():
            return _cm()

        with patch(
            "src.api.routers.scans.async_session_factory",
            factory,
        ):
            response = client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 404
        assert response.json().get("detail") == "Scan not found"
