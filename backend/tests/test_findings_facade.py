"""API tests for findings facade (T03–T06): GET /findings/{id} detail 404."""

import uuid
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

from starlette.testclient import TestClient


class TestFindingDetailFacade:
    """GET /api/v1/findings/{finding_id} — 404 when finding missing."""

    def test_get_finding_detail_not_found_returns_404(self, client: TestClient) -> None:
        finding_id = str(uuid.uuid4())
        empty = MagicMock()
        empty.scalar_one_or_none.return_value = None

        session = AsyncMock()
        session.execute = AsyncMock(return_value=empty)

        @asynccontextmanager
        async def _cm():
            yield session

        def factory():
            return _cm()

        with patch("src.api.routers.findings.async_session_factory", factory):
            response = client.get(f"/api/v1/findings/{finding_id}")
        assert response.status_code == 404
        assert response.json().get("detail") == "Finding not found"
