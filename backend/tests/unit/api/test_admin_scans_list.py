"""Admin GET /admin/scans and GET /admin/scans/{id} — list, detail, RBAC (mocked DB)."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from main import app
from src.core.config import settings
from src.db.models import Scan, ScanEvent, Tenant, ToolRun
from src.db.session import get_db

_ADMIN_KEY = "secret-admin-key"
_ADMIN_HEADERS = {"X-Admin-Key": _ADMIN_KEY}

LIST = "/api/v1/admin/scans"


@pytest.fixture
def _clear_db_override():
    yield
    app.dependency_overrides.pop(get_db, None)


def _session_factory(session: AsyncMock):
    @asynccontextmanager
    async def _cm():
        yield session

    return lambda: _cm()


def _tenant_row() -> MagicMock:
    t = MagicMock(spec=Tenant)
    t.id = str(uuid.uuid4())
    return t


def _scan_row(*, tid: str) -> Scan:
    s = MagicMock(spec=Scan)
    sid = str(uuid.uuid4())
    s.id = sid
    s.tenant_id = tid
    s.target_url = "https://example.com"
    s.status = "completed"
    s.progress = 100
    s.phase = "complete"
    s.scan_mode = "standard"
    s.created_at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    s.updated_at = datetime(2026, 1, 2, 3, 5, 5, tzinfo=UTC)
    return s


class TestAdminScansRbac:
    """401 when X-Admin-Key missing (same pattern as test_admin_targets_scopes)."""

    def test_list_401_without_key(self, client: TestClient, _clear_db_override) -> None:
        tid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(LIST, params={"tenant_id": tid})
        assert r.status_code == 401
        assert r.json()["detail"] == "Invalid X-Admin-Key"

    def test_detail_401_without_key(self, client: TestClient, _clear_db_override) -> None:
        scan_id = str(uuid.uuid4())
        tid = str(uuid.uuid4())
        path = f"/api/v1/admin/scans/{scan_id}"
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(path, params={"tenant_id": tid})
        assert r.status_code == 401
        assert r.json()["detail"] == "Invalid X-Admin-Key"


class TestAdminScansValidation:
    def test_list_422_missing_tenant_id(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(LIST, headers=_ADMIN_HEADERS)
        assert r.status_code == 422
        detail = r.json().get("detail")
        assert isinstance(detail, list)
        loc_joined = " ".join(str(err.get("loc", ())) for err in detail)
        assert "tenant_id" in loc_joined

    def test_detail_422_missing_tenant_id(self, client: TestClient) -> None:
        scan_id = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(f"/api/v1/admin/scans/{scan_id}", headers=_ADMIN_HEADERS)
        assert r.status_code == 422
        detail = r.json().get("detail")
        assert isinstance(detail, list)
        loc_joined = " ".join(str(err.get("loc", ())) for err in detail)
        assert "tenant_id" in loc_joined


class TestAdminScansList:
    def test_list_200_empty(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())

        r_set = MagicMock()
        r_tenant = MagicMock()
        r_tenant.scalar_one_or_none.return_value = _tenant_row()
        r_count = MagicMock()
        r_count.scalar_one.return_value = 0
        r_list = MagicMock()
        r_list.scalars.return_value.all.return_value = []

        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_set, r_tenant, r_count, r_list])
        factory = _session_factory(session)

        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch("src.api.routers.admin_scans.async_session_factory", factory):
                r = client.get(
                    LIST,
                    headers=_ADMIN_HEADERS,
                    params={"tenant_id": tid, "limit": 10, "offset": 0},
                )
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 0
        assert body["scans"] == []
        assert body["limit"] == 10
        assert body["offset"] == 0

    def test_list_200_pagination_total_matches_count(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        row_a = _scan_row(tid=tid)
        row_b = _scan_row(tid=tid)

        r_set = MagicMock()
        r_tenant = MagicMock()
        r_tenant.scalar_one_or_none.return_value = _tenant_row()
        r_count = MagicMock()
        r_count.scalar_one.return_value = 42
        r_list = MagicMock()
        r_list.scalars.return_value.all.return_value = [row_a, row_b]

        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_set, r_tenant, r_count, r_list])
        factory = _session_factory(session)

        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch("src.api.routers.admin_scans.async_session_factory", factory):
                r = client.get(
                    LIST,
                    headers=_ADMIN_HEADERS,
                    params={"tenant_id": tid, "limit": 2, "offset": 0},
                )
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 42
        assert len(body["scans"]) == 2
        assert body["limit"] == 2
        assert body["offset"] == 0

    def test_list_404_unknown_tenant(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())

        r_set = MagicMock()
        r_tenant = MagicMock()
        r_tenant.scalar_one_or_none.return_value = None

        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_set, r_tenant])
        factory = _session_factory(session)

        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch("src.api.routers.admin_scans.async_session_factory", factory):
                r = client.get(LIST, headers=_ADMIN_HEADERS, params={"tenant_id": tid})
        assert r.status_code == 404
        assert r.json()["detail"] == "Tenant not found"


class TestAdminScanDetail:
    def test_detail_404_tenant_not_found(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        r_set = MagicMock()
        r_tenant = MagicMock()
        r_tenant.scalar_one_or_none.return_value = None
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_set, r_tenant])
        factory = _session_factory(session)
        path = f"/api/v1/admin/scans/{scan_id}"
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch("src.api.routers.admin_scans.async_session_factory", factory):
                r = client.get(path, headers=_ADMIN_HEADERS, params={"tenant_id": tid})
        assert r.status_code == 404
        assert r.json()["detail"] == "Tenant not found"

    @pytest.mark.parametrize(
        "_scenario",
        ["unknown_scan_id", "wrong_tenant_scope"],
    )
    def test_detail_404_scan_not_found(self, client: TestClient, _scenario: str) -> None:
        # Same mocked DB shape for both: no Scan row for (scan_id, tenant_id).
        tid = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        r_set = MagicMock()
        r_tenant = MagicMock()
        r_tenant.scalar_one_or_none.return_value = _tenant_row()
        r_scan = MagicMock()
        r_scan.scalar_one_or_none.return_value = None
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_set, r_tenant, r_scan])
        factory = _session_factory(session)
        path = f"/api/v1/admin/scans/{scan_id}"
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch("src.api.routers.admin_scans.async_session_factory", factory):
                r = client.get(path, headers=_ADMIN_HEADERS, params={"tenant_id": tid})
        assert r.status_code == 404
        assert r.json()["detail"] == "Scan not found"

    def test_detail_tool_metrics_and_sanitized_error(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        scan = _scan_row(tid=tid)
        scan_id = scan.id

        r_set = MagicMock()
        r_tenant = MagicMock()
        r_tenant.scalar_one_or_none.return_value = _tenant_row()
        r_scan = MagicMock()
        r_scan.scalar_one_or_none.return_value = scan

        tr = ToolRun(
            id=str(uuid.uuid4()),
            tenant_id=tid,
            scan_id=scan_id,
            tool_name="nuclei",
            status="completed",
            input_params=None,
            output_raw=None,
            output_object_key=None,
            started_at=datetime(2026, 1, 2, 3, 4, 10, tzinfo=UTC),
            finished_at=datetime(2026, 1, 2, 3, 4, 40, tzinfo=UTC),
        )

        bad_ev = ScanEvent(
            id=str(uuid.uuid4()),
            tenant_id=tid,
            scan_id=scan_id,
            event="error",
            phase="vuln_analysis",
            progress=None,
            message="Traceback (most recent call last):\n  File \"x.py\"",
            data=None,
            duration_sec=None,
            created_at=datetime(2026, 1, 2, 3, 4, 50, tzinfo=UTC),
        )

        r_tools = MagicMock()
        r_tools.scalars.return_value.all.return_value = [tr]
        r_errs = MagicMock()
        r_errs.scalars.return_value.all.return_value = [bad_ev]

        session = AsyncMock()
        session.execute = AsyncMock(
            side_effect=[r_set, r_tenant, r_scan, r_tools, r_errs],
        )
        factory = _session_factory(session)

        path = f"/api/v1/admin/scans/{scan_id}"
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch("src.api.routers.admin_scans.async_session_factory", factory):
                r = client.get(
                    path,
                    headers=_ADMIN_HEADERS,
                    params={"tenant_id": tid},
                )
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == scan_id
        assert len(data["tool_metrics"]) == 1
        assert data["tool_metrics"][0]["tool_name"] == "nuclei"
        assert data["tool_metrics"][0]["duration_sec"] == 30.0
        assert len(data["error_summary"]) == 1
        assert data["error_summary"][0]["message"] == "An error occurred."

    def test_detail_error_summary_sanitizes_traceback_in_event_data(
        self, client: TestClient
    ) -> None:
        tid = str(uuid.uuid4())
        scan = _scan_row(tid=tid)
        scan_id = scan.id

        r_set = MagicMock()
        r_tenant = MagicMock()
        r_tenant.scalar_one_or_none.return_value = _tenant_row()
        r_scan = MagicMock()
        r_scan.scalar_one_or_none.return_value = scan

        tr = ToolRun(
            id=str(uuid.uuid4()),
            tenant_id=tid,
            scan_id=scan_id,
            tool_name="nuclei",
            status="completed",
            input_params=None,
            output_raw=None,
            output_object_key=None,
            started_at=datetime(2026, 1, 2, 3, 4, 10, tzinfo=UTC),
            finished_at=datetime(2026, 1, 2, 3, 4, 40, tzinfo=UTC),
        )

        bad_ev = ScanEvent(
            id=str(uuid.uuid4()),
            tenant_id=tid,
            scan_id=scan_id,
            event="error",
            phase="collect",
            progress=None,
            message=None,
            data={"error": 'Traceback (most recent call last):\n  File "job.py"'},
            duration_sec=None,
            created_at=datetime(2026, 1, 2, 3, 4, 51, tzinfo=UTC),
        )

        r_tools = MagicMock()
        r_tools.scalars.return_value.all.return_value = [tr]
        r_errs = MagicMock()
        r_errs.scalars.return_value.all.return_value = [bad_ev]

        session = AsyncMock()
        session.execute = AsyncMock(
            side_effect=[r_set, r_tenant, r_scan, r_tools, r_errs],
        )
        factory = _session_factory(session)

        path = f"/api/v1/admin/scans/{scan_id}"
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch("src.api.routers.admin_scans.async_session_factory", factory):
                r = client.get(
                    path,
                    headers=_ADMIN_HEADERS,
                    params={"tenant_id": tid},
                )
        assert r.status_code == 200
        assert r.json()["error_summary"][0]["message"] == "An error occurred."
