"""API tests for scan extensions (T03–T06): list, smart/skill enqueue, report 404 contract, cancel."""

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

from starlette.testclient import TestClient

from src.core.config import settings


def _session_factory_with_execute_return(result: MagicMock):
    session = AsyncMock()
    session.execute = AsyncMock(return_value=result)

    @asynccontextmanager
    async def _cm():
        yield session

    def factory():
        return _cm()

    return factory


def _list_scans_result(rows: list) -> MagicMock:
    """Mock SQLAlchemy result for list_scans: scalars().all()."""
    result = MagicMock()
    scalars = MagicMock()
    scalars.all.return_value = rows
    result.scalars.return_value = scalars
    return result


class TestListScansExtensions:
    """GET /api/v1/scans — list with mocked DB."""

    def test_list_scans_empty(self, client: TestClient) -> None:
        result = _list_scans_result([])
        factory = _session_factory_with_execute_return(result)
        with patch("src.api.routers.scans.async_session_factory", factory):
            response = client.get("/api/v1/scans")
        assert response.status_code == 200
        assert response.json() == []

    def test_list_scans_returns_items_shape(self, client: TestClient) -> None:
        scan_id = str(uuid.uuid4())
        mock_scan = MagicMock()
        mock_scan.id = scan_id
        mock_scan.status = "running"
        mock_scan.progress = 42
        mock_scan.phase = "recon"
        mock_scan.target_url = "https://example.com"
        mock_scan.created_at = datetime.now(UTC)
        mock_scan.scan_mode = "standard"

        result = _list_scans_result([mock_scan])
        factory = _session_factory_with_execute_return(result)
        with patch("src.api.routers.scans.async_session_factory", factory):
            response = client.get("/api/v1/scans")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        item = data[0]
        assert item["id"] == scan_id
        assert item["status"] == "running"
        assert item["progress"] == 42
        assert item["phase"] == "recon"
        assert item["target"] == "https://example.com"
        assert "created_at" in item
        assert item["scan_mode"] == "standard"

    def test_list_scans_tenant_query_mismatch_returns_403(self, client: TestClient) -> None:
        tid = settings.default_tenant_id
        other = str(uuid.uuid4())
        response = client.get(
            "/api/v1/scans",
            params={"tenant_id": other},
            headers={"X-Tenant-ID": tid},
        )
        assert response.status_code == 403
        body = response.json()
        msg = (body.get("detail") or body.get("error") or "").lower()
        assert "tenant" in msg

    def test_post_smart_scan_tenant_body_mismatch_returns_403(self, client: TestClient) -> None:
        tid = settings.default_tenant_id
        other = str(uuid.uuid4())
        response = client.post(
            "/api/v1/scans/smart",
            json={
                "target": "https://example.com",
                "objective": "check auth",
                "max_phases": 3,
                "tenant_id": other,
            },
            headers={"X-Tenant-ID": tid},
        )
        assert response.status_code == 403
        body = response.json()
        msg = (body.get("detail") or body.get("error") or "").lower()
        assert "tenant" in msg

    def test_post_skill_scan_tenant_body_mismatch_returns_403(self, client: TestClient) -> None:
        tid = settings.default_tenant_id
        other = str(uuid.uuid4())
        response = client.post(
            "/api/v1/scans/skill",
            json={
                "target": "https://example.com",
                "skill": "xss",
                "tenant_id": other,
            },
            headers={"X-Tenant-ID": tid},
        )
        assert response.status_code == 403
        body = response.json()
        msg = (body.get("detail") or body.get("error") or "").lower()
        assert "tenant" in msg


class TestPostSmartSkillScans:
    """POST /scans/smart and /scans/skill — 201 and ScanCreateResponse shape."""

    def test_post_smart_scan_returns_201_and_shape(
        self,
        client: TestClient,
    ) -> None:
        tenant_result = MagicMock()
        tenant_result.scalar_one_or_none.return_value = MagicMock()
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

        with (
            patch("src.api.routers.scans.async_session_factory", factory),
            patch("src.api.routers.scans.scan_phase_task"),
        ):
            response = client.post(
                "/api/v1/scans/smart",
                json={
                    "target": "https://example.com",
                    "objective": "check auth",
                    "max_phases": 3,
                },
            )
        assert response.status_code == 201
        body = response.json()
        assert "scan_id" in body
        assert body["status"] == "queued"
        assert body.get("message") == "Smart scan queued"
        uuid.UUID(body["scan_id"])

    def test_post_skill_scan_returns_201_and_shape(
        self,
        client: TestClient,
    ) -> None:
        tenant_result = MagicMock()
        tenant_result.scalar_one_or_none.return_value = MagicMock()
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

        with (
            patch("src.api.routers.scans.async_session_factory", factory),
            patch("src.api.routers.scans.scan_phase_task"),
        ):
            response = client.post(
                "/api/v1/scans/skill",
                json={
                    "target": "https://example.com",
                    "skill": "xss",
                },
            )
        assert response.status_code == 201
        body = response.json()
        assert "scan_id" in body
        assert body["status"] == "queued"
        assert body.get("message") == "Skill scan queued"
        uuid.UUID(body["scan_id"])


class TestGetScanReportNotFound:
    """GET /scans/{id}/report returns 404 JSON when scan exists but no report row."""

    def test_get_scan_report_no_report_returns_404_contract(self, client: TestClient) -> None:
        scan_id = str(uuid.uuid4())
        mock_scan = MagicMock()

        set_local_result = MagicMock()
        scan_result = MagicMock()
        scan_result.scalar_one_or_none.return_value = mock_scan
        report_result = MagicMock()
        report_result.scalar_one_or_none.return_value = None

        session = AsyncMock()
        session.execute = AsyncMock(
            side_effect=[set_local_result, scan_result, report_result],
        )

        @asynccontextmanager
        async def _cm():
            yield session

        def factory():
            return _cm()

        with patch("src.api.routers.scans.async_session_factory", factory):
            response = client.get(f"/api/v1/scans/{scan_id}/report")
        assert response.status_code == 404
        body = response.json()
        assert set(body.keys()) == {
            "error",
            "message",
            "scan_id",
            "tier",
            "generate",
        }
        assert body["error"] == "report_not_found"
        assert body["scan_id"] == scan_id
        assert body["tier"] == "midgard"
        gen = body["generate"]
        assert set(gen.keys()) == {"method", "path", "alternate"}
        assert gen["method"] == "POST"
        assert gen["path"] == f"/api/v1/scans/{scan_id}/reports/generate"
        assert gen["alternate"] == f"/api/v1/scans/{scan_id}/reports/generate-all"
        assert "report" in body["message"].lower()


class TestCancelScanExtensions:
    """POST /scans/{id}/cancel — success, 404, terminal 400."""

    def _factory_cancel(
        self,
        *,
        scan_present: bool,
        terminal: bool = False,
    ):
        mock_scan = None
        if scan_present:
            mock_scan = MagicMock()
            mock_scan.status = "completed" if terminal else "running"

        set_local_result = MagicMock()
        select_result = MagicMock()
        select_result.scalar_one_or_none.return_value = mock_scan
        update_result = MagicMock()

        session = AsyncMock()
        if scan_present and not terminal:
            session.execute = AsyncMock(
                side_effect=[set_local_result, select_result, update_result],
            )
        else:
            session.execute = AsyncMock(
                side_effect=[set_local_result, select_result],
            )
        session.commit = AsyncMock()

        @asynccontextmanager
        async def _cm():
            yield session

        def factory():
            return _cm()

        return factory

    def test_cancel_scan_success(self, client: TestClient) -> None:
        scan_id = str(uuid.uuid4())
        factory = self._factory_cancel(scan_present=True, terminal=False)
        with patch("src.api.routers.scans.async_session_factory", factory):
            response = client.post(f"/api/v1/scans/{scan_id}/cancel")
        assert response.status_code == 200
        body = response.json()
        assert body["scan_id"] == scan_id
        assert body["status"] == "cancelled"

    def test_cancel_scan_not_found_returns_404(self, client: TestClient) -> None:
        scan_id = str(uuid.uuid4())
        factory = self._factory_cancel(scan_present=False)
        with patch("src.api.routers.scans.async_session_factory", factory):
            response = client.post(f"/api/v1/scans/{scan_id}/cancel")
        assert response.status_code == 404

    def test_cancel_scan_terminal_returns_400(self, client: TestClient) -> None:
        scan_id = str(uuid.uuid4())
        factory = self._factory_cancel(scan_present=True, terminal=True)
        with patch("src.api.routers.scans.async_session_factory", factory):
            response = client.post(f"/api/v1/scans/{scan_id}/cancel")
        assert response.status_code == 400
        body = response.json()
        msg = (body.get("detail") or body.get("error") or "").lower()
        assert "terminal" in msg
