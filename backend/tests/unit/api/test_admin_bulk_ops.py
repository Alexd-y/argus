"""Admin bulk-cancel / bulk-suppress — RBAC, validation, idempotency (no live DB)."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from src.core.config import settings

BULK_CANCEL = "/api/v1/admin/scans/bulk-cancel"
BULK_SUPPRESS = "/api/v1/admin/findings/bulk-suppress"

_ADMIN_KEY = "secret-admin-key"
_ADMIN_HEADERS = {"X-Admin-Key": _ADMIN_KEY}


def _session_factory(session: AsyncMock):
    @asynccontextmanager
    async def _cm():
        yield session

    return lambda: _cm()


class TestAdminBulkRbac:
    def test_bulk_cancel_401_without_key(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        sid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(BULK_CANCEL, json={"tenant_id": tid, "scan_ids": [sid]})
        assert r.status_code == 401
        assert r.json().get("detail") == "Invalid X-Admin-Key"

    def test_bulk_suppress_401_wrong_key(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        fid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                BULK_SUPPRESS,
                headers={"X-Admin-Key": "wrong"},
                json={
                    "tenant_id": tid,
                    "finding_ids": [fid],
                    "reason": "Duplicate scanner noise",
                },
            )
        assert r.status_code == 401


class TestAdminBulkCancelHappyPath:
    """Bulk handlers await ``set_session_tenant`` first (one ``session.execute`` for SET LOCAL)."""

    def test_bulk_cancel_202_one_running_scan(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        sid = str(uuid.uuid4())

        # Order: SET LOCAL (set_session_tenant), then select, then update — matches handler.
        r_set = MagicMock()
        scan = MagicMock()
        scan.status = "running"
        r_sel = MagicMock()
        r_sel.scalar_one_or_none.return_value = scan
        r_upd = MagicMock()

        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_set, r_sel, r_upd])
        session.add = MagicMock()
        session.commit = AsyncMock()
        factory = _session_factory(session)

        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_bulk_ops.async_session_factory",
                factory,
            ):
                r = client.post(
                    BULK_CANCEL,
                    headers=_ADMIN_HEADERS,
                    json={"tenant_id": tid, "scan_ids": [sid]},
                )
        assert r.status_code == 202
        data = r.json()
        assert data["cancelled_count"] == 1
        assert data["skipped_terminal_count"] == 0
        assert data["not_found_count"] == 0
        assert len(data["audit_id"]) == 36
        assert data["results"][0]["scan_id"] == sid
        assert data["results"][0]["status"] == "cancelled"
        session.commit.assert_awaited()


class TestAdminBulkSuppressHappyPath:
    """Bulk handlers await ``set_session_tenant`` first (one ``session.execute`` for SET LOCAL)."""

    def test_bulk_suppress_202_one_finding(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        fid = str(uuid.uuid4())

        # Order: SET LOCAL (set_session_tenant), then select, then update — matches handler.
        r_set = MagicMock()
        finding = MagicMock()
        finding.false_positive = False
        r_sel = MagicMock()
        r_sel.scalar_one_or_none.return_value = finding
        r_upd = MagicMock()

        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_set, r_sel, r_upd])
        session.add = MagicMock()
        session.commit = AsyncMock()
        factory = _session_factory(session)

        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_bulk_ops.async_session_factory",
                factory,
            ):
                r = client.post(
                    BULK_SUPPRESS,
                    headers={**_ADMIN_HEADERS, "X-Operator-Subject": "operator-1"},
                    json={
                        "tenant_id": tid,
                        "finding_ids": [fid],
                        "reason": "Expected WAF behaviour",
                    },
                )
        assert r.status_code == 202
        data = r.json()
        assert data["suppressed_count"] == 1
        assert data["skipped_already_suppressed_count"] == 0
        assert data["not_found_count"] == 0
        assert len(data["audit_id"]) == 36
        assert data["results"][0]["finding_id"] == fid
        assert data["results"][0]["status"] == "suppressed"
        session.commit.assert_awaited()


class TestAdminBulkValidation:
    """Pydantic limits: max 100 ids, min 1 id, UUID fields, non-empty suppress reason."""

    def test_bulk_cancel_422_when_scan_ids_exceeds_100(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        ids = [str(uuid.uuid4()) for _ in range(101)]
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                BULK_CANCEL,
                headers=_ADMIN_HEADERS,
                json={"tenant_id": tid, "scan_ids": ids},
            )
        assert r.status_code == 422
        detail = r.json().get("detail")
        assert isinstance(detail, list)
        assert any("scan_ids" in str(err.get("loc", ())) for err in detail)

    def test_bulk_suppress_422_when_finding_ids_exceeds_100(
        self, client: TestClient
    ) -> None:
        tid = str(uuid.uuid4())
        ids = [str(uuid.uuid4()) for _ in range(101)]
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                BULK_SUPPRESS,
                headers=_ADMIN_HEADERS,
                json={
                    "tenant_id": tid,
                    "finding_ids": ids,
                    "reason": "noise",
                },
            )
        assert r.status_code == 422

    def test_bulk_cancel_422_empty_scan_ids(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                BULK_CANCEL,
                headers=_ADMIN_HEADERS,
                json={"tenant_id": tid, "scan_ids": []},
            )
        assert r.status_code == 422

    def test_bulk_suppress_422_empty_finding_ids(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                BULK_SUPPRESS,
                headers=_ADMIN_HEADERS,
                json={"tenant_id": tid, "finding_ids": [], "reason": "x"},
            )
        assert r.status_code == 422

    def test_bulk_cancel_422_invalid_scan_id_uuid(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                BULK_CANCEL,
                headers=_ADMIN_HEADERS,
                json={"tenant_id": tid, "scan_ids": ["not-a-uuid"]},
            )
        assert r.status_code == 422

    def test_bulk_cancel_422_invalid_tenant_id(self, client: TestClient) -> None:
        sid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                BULK_CANCEL,
                headers=_ADMIN_HEADERS,
                json={"tenant_id": "bad-tenant", "scan_ids": [sid]},
            )
        assert r.status_code == 422

    def test_bulk_suppress_422_empty_reason(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        fid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                BULK_SUPPRESS,
                headers=_ADMIN_HEADERS,
                json={"tenant_id": tid, "finding_ids": [fid], "reason": ""},
            )
        assert r.status_code == 422


class TestAdminBulkCancelIdempotencyAndNotFound:
    @pytest.mark.parametrize("terminal_status", ["completed", "failed", "cancelled"])
    def test_bulk_cancel_skipped_terminal(
        self, client: TestClient, terminal_status: str
    ) -> None:
        tid = str(uuid.uuid4())
        sid = str(uuid.uuid4())
        r_exec = MagicMock()
        r_sel = MagicMock()
        scan = MagicMock()
        scan.status = terminal_status
        r_sel.scalar_one_or_none.return_value = scan
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_exec, r_sel])
        session.add = MagicMock()
        session.commit = AsyncMock()
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_bulk_ops.async_session_factory",
                factory,
            ):
                r = client.post(
                    BULK_CANCEL,
                    headers=_ADMIN_HEADERS,
                    json={"tenant_id": tid, "scan_ids": [sid]},
                )
        assert r.status_code == 202
        data = r.json()
        assert data["cancelled_count"] == 0
        assert data["skipped_terminal_count"] == 1
        assert data["not_found_count"] == 0
        assert data["results"][0]["status"] == "skipped_terminal"
        session.commit.assert_awaited()

    def test_bulk_cancel_not_found(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        sid = str(uuid.uuid4())
        r_exec = MagicMock()
        r_sel = MagicMock()
        r_sel.scalar_one_or_none.return_value = None
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_exec, r_sel])
        session.add = MagicMock()
        session.commit = AsyncMock()
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_bulk_ops.async_session_factory",
                factory,
            ):
                r = client.post(
                    BULK_CANCEL,
                    headers=_ADMIN_HEADERS,
                    json={"tenant_id": tid, "scan_ids": [sid]},
                )
        assert r.status_code == 202
        data = r.json()
        assert data["not_found_count"] == 1
        assert data["cancelled_count"] == 0
        assert data["results"][0]["status"] == "not_found"

    def test_bulk_cancel_dedupes_duplicate_scan_ids(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        sid = str(uuid.uuid4())
        r_exec = MagicMock()
        r_sel = MagicMock()
        scan = MagicMock()
        scan.status = "running"
        r_sel.scalar_one_or_none.return_value = scan
        r_upd = MagicMock()
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_exec, r_sel, r_upd])
        session.add = MagicMock()
        session.commit = AsyncMock()
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_bulk_ops.async_session_factory",
                factory,
            ):
                r = client.post(
                    BULK_CANCEL,
                    headers=_ADMIN_HEADERS,
                    json={"tenant_id": tid, "scan_ids": [sid, sid]},
                )
        assert r.status_code == 202
        data = r.json()
        assert data["cancelled_count"] == 1
        assert len(data["results"]) == 1
        audit = session.add.call_args[0][0]
        assert audit.details["requested_count"] == 1


class TestAdminBulkSuppressIdempotencyAndNotFound:
    def test_bulk_suppress_skipped_already_suppressed(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        fid = str(uuid.uuid4())
        r_exec = MagicMock()
        r_sel = MagicMock()
        finding = MagicMock()
        finding.false_positive = True
        r_sel.scalar_one_or_none.return_value = finding
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_exec, r_sel])
        session.add = MagicMock()
        session.commit = AsyncMock()
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_bulk_ops.async_session_factory",
                factory,
            ):
                r = client.post(
                    BULK_SUPPRESS,
                    headers=_ADMIN_HEADERS,
                    json={
                        "tenant_id": tid,
                        "finding_ids": [fid],
                        "reason": "already triaged",
                    },
                )
        assert r.status_code == 202
        data = r.json()
        assert data["suppressed_count"] == 0
        assert data["skipped_already_suppressed_count"] == 1
        assert data["not_found_count"] == 0
        assert data["results"][0]["status"] == "skipped_already_suppressed"

    def test_bulk_suppress_not_found(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        fid = str(uuid.uuid4())
        r_exec = MagicMock()
        r_sel = MagicMock()
        r_sel.scalar_one_or_none.return_value = None
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_exec, r_sel])
        session.add = MagicMock()
        session.commit = AsyncMock()
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_bulk_ops.async_session_factory",
                factory,
            ):
                r = client.post(
                    BULK_SUPPRESS,
                    headers=_ADMIN_HEADERS,
                    json={
                        "tenant_id": tid,
                        "finding_ids": [fid],
                        "reason": "missing row",
                    },
                )
        assert r.status_code == 202
        data = r.json()
        assert data["not_found_count"] == 1
        assert data["suppressed_count"] == 0
        assert data["results"][0]["status"] == "not_found"


class TestAdminBulkTenantScope:
    """Without Postgres, assert RLS/session tenant is driven by the request body."""

    def test_bulk_cancel_await_set_session_tenant_with_body_tenant_id(
        self, client: TestClient
    ) -> None:
        tid = str(uuid.uuid4())
        sid = str(uuid.uuid4())
        r_sel = MagicMock()
        scan = MagicMock()
        scan.status = "running"
        r_sel.scalar_one_or_none.return_value = scan
        r_upd = MagicMock()
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_sel, r_upd])
        session.add = MagicMock()
        session.commit = AsyncMock()
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_bulk_ops.async_session_factory",
                factory,
            ):
                with patch(
                    "src.api.routers.admin_bulk_ops.set_session_tenant",
                    new_callable=AsyncMock,
                ) as mock_set_tenant:
                    r = client.post(
                        BULK_CANCEL,
                        headers=_ADMIN_HEADERS,
                        json={"tenant_id": tid, "scan_ids": [sid]},
                    )
        assert r.status_code == 202
        mock_set_tenant.assert_awaited_once()
        call_session, call_tid = mock_set_tenant.await_args[0]
        assert call_session is session
        assert call_tid == tid

    def test_bulk_suppress_await_set_session_tenant_with_body_tenant_id(
        self, client: TestClient
    ) -> None:
        tid = str(uuid.uuid4())
        fid = str(uuid.uuid4())
        r_sel = MagicMock()
        finding = MagicMock()
        finding.false_positive = False
        r_sel.scalar_one_or_none.return_value = finding
        r_upd = MagicMock()
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_sel, r_upd])
        session.add = MagicMock()
        session.commit = AsyncMock()
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_bulk_ops.async_session_factory",
                factory,
            ):
                with patch(
                    "src.api.routers.admin_bulk_ops.set_session_tenant",
                    new_callable=AsyncMock,
                ) as mock_set_tenant:
                    r = client.post(
                        BULK_SUPPRESS,
                        headers=_ADMIN_HEADERS,
                        json={
                            "tenant_id": tid,
                            "finding_ids": [fid],
                            "reason": "scope check",
                        },
                    )
        assert r.status_code == 202
        mock_set_tenant.assert_awaited_once()
        assert mock_set_tenant.await_args[0][1] == tid
