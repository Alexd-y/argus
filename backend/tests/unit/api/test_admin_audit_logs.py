"""Admin audit log search + export — validation, RBAC, mocked DB."""

from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from src.core.config import settings
from src.core.observability import tenant_hash, user_id_hash
from src.db.session import get_db
from main import app
from src.api.routers import admin as admin_router

AUDIT_LIST = "/api/v1/admin/audit-logs"
AUDIT_EXPORT = "/api/v1/admin/audit-logs/export"
_ADMIN_KEY = "secret-admin-key"
_ADMIN_HEADERS = {"X-Admin-Key": _ADMIN_KEY}

_EXPECTED_CSV_HEADER = (
    "id",
    "tenant_hash",
    "user_id_hash",
    "event_type",
    "resource_type",
    "resource_id",
    "details_json",
    "ip_address_hash",
    "created_at",
)


def _sample_row(
    *,
    tenant_id: str | None = None,
    user_id: str | None = None,
    details: dict[str, object] | None = None,
) -> SimpleNamespace:
    tid = tenant_id or str(uuid.uuid4())
    return SimpleNamespace(
        id=str(uuid.uuid4()),
        tenant_id=tid,
        user_id=user_id,
        action="bulk_scan_cancel",
        resource_type="bulk_operation",
        resource_id=str(uuid.uuid4()),
        details=details if details is not None else {"requested_count": 1},
        ip_address="203.0.113.10",
        created_at=datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc),
    )


def _override_db(rows: list[SimpleNamespace]) -> None:
    async def mock_get_db() -> AsyncGenerator[AsyncMock, None]:
        session = AsyncMock()
        result = MagicMock()
        result.scalars.return_value.all.return_value = rows
        session.execute = AsyncMock(return_value=result)
        yield session

    app.dependency_overrides[get_db] = mock_get_db


def _clear_db_override() -> None:
    app.dependency_overrides.pop(get_db, None)


class TestAdminAuditRbac:
    def test_list_401_without_key(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(AUDIT_LIST)
        assert r.status_code == 401
        assert r.json().get("detail") == "Invalid X-Admin-Key"

    def test_export_401_wrong_key(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(AUDIT_EXPORT, headers={"X-Admin-Key": "nope"})
        assert r.status_code == 401


class TestAdminAuditValidation:
    def test_list_422_until_before_since(self, client: TestClient) -> None:
        since = datetime(2026, 4, 2, tzinfo=timezone.utc)
        until = datetime(2026, 4, 1, tzinfo=timezone.utc)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                AUDIT_LIST,
                headers=_ADMIN_HEADERS,
                params={
                    "since": since.isoformat(),
                    "until": until.isoformat(),
                },
            )
        assert r.status_code == 422
        assert "until" in r.json().get("detail", "").lower()

    def test_list_422_limit_too_high(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(AUDIT_LIST, headers=_ADMIN_HEADERS, params={"limit": 201})
        assert r.status_code == 422

    def test_list_422_limit_zero(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(AUDIT_LIST, headers=_ADMIN_HEADERS, params={"limit": 0})
        assert r.status_code == 422

    def test_export_422_limit_above_cap(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                AUDIT_EXPORT,
                headers=_ADMIN_HEADERS,
                params={"limit": 2001},
            )
        assert r.status_code == 422

    def test_export_422_invalid_format(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                AUDIT_EXPORT,
                headers=_ADMIN_HEADERS,
                params={"format": "xml"},
            )
        assert r.status_code == 422
        detail = r.json().get("detail")
        assert isinstance(detail, list)
        loc_joined = " ".join(str(err.get("loc", ())) for err in detail)
        assert "format" in loc_joined


class TestCsvExportSanitization:
    def test_sanitize_csv_prefixes_tab_when_starts_with_equals(self) -> None:
        raw = "=1+1"
        out = admin_router._sanitize_csv_text_cell(raw)
        assert out[0] == "\t"
        assert out == "\t=1+1"

    def test_export_csv_neutralizes_formula_like_resource_id(self, client: TestClient) -> None:
        row = _sample_row()
        row.resource_id = "=SUM(1,2)"
        _override_db([row])
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.get(
                    AUDIT_EXPORT,
                    headers=_ADMIN_HEADERS,
                    params={"format": "csv"},
                )
        finally:
            _clear_db_override()
        assert r.status_code == 200
        parsed = list(csv.reader(io.StringIO(r.text)))
        resource_id_cell = parsed[1][5]
        assert resource_id_cell[0] == "\t"
        assert resource_id_cell == "\t=SUM(1,2)"


class TestAdminAuditHappyPath:
    def test_list_returns_rows(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        row = _sample_row(tenant_id=tid)
        _override_db([row])
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.get(AUDIT_LIST, headers=_ADMIN_HEADERS)
        finally:
            _clear_db_override()
        assert r.status_code == 200
        data = r.json()
        assert len(data) == 1
        assert data[0]["tenant_id"] == tid
        assert data[0]["action"] == "bulk_scan_cancel"

    def test_export_json_redacts_and_hashes(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        uid = str(uuid.uuid4())
        row = _sample_row(
            tenant_id=tid,
            user_id=uid,
            details={
                "api_secret": "should-not-appear",
                "contact": "ops@example.com",
                "ok": 1,
            },
        )
        _override_db([row])
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.get(
                    AUDIT_EXPORT,
                    headers=_ADMIN_HEADERS,
                    params={"format": "json"},
                )
        finally:
            _clear_db_override()
        assert r.status_code == 200
        assert r.headers.get("content-type", "").startswith("application/json")
        payload = json.loads(r.text)
        assert len(payload) == 1
        item = payload[0]
        assert item["tenant_hash"] == tenant_hash(tid)
        assert item["user_id_hash"] == user_id_hash(uid)
        assert item["details"]["api_secret"] == "[redacted]"
        assert item["details"]["contact"] == user_id_hash("ops@example.com")
        assert item["details"]["ok"] == 1
        assert "tenant_id" not in item

    def test_export_200_limit_at_max_inclusive(self, client: TestClient) -> None:
        row = _sample_row()
        _override_db([row])
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.get(
                    AUDIT_EXPORT,
                    headers=_ADMIN_HEADERS,
                    params={"format": "json", "limit": 2000},
                )
        finally:
            _clear_db_override()
        assert r.status_code == 200
        assert len(json.loads(r.text)) == 1

    def test_export_csv_header_row_and_row_count(self, client: TestClient) -> None:
        row = _sample_row()
        _override_db([row])
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.get(
                    AUDIT_EXPORT,
                    headers=_ADMIN_HEADERS,
                    params={"format": "csv"},
                )
        finally:
            _clear_db_override()
        assert r.status_code == 200
        assert "text/csv" in r.headers.get("content-type", "")
        reader = csv.reader(io.StringIO(r.text))
        rows = list(reader)
        assert rows[0] == list(_EXPECTED_CSV_HEADER)
        assert len(rows) == 2

    def test_export_csv_redacts_sensitive_keys_in_details_json_column(
        self, client: TestClient
    ) -> None:
        tid = str(uuid.uuid4())
        uid = str(uuid.uuid4())
        row = _sample_row(
            tenant_id=tid,
            user_id=uid,
            details={
                "refresh_token": "super-secret",
                "nested": {"api_key": "also-secret"},
                "safe": "ok",
            },
        )
        _override_db([row])
        try:
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                r = client.get(
                    AUDIT_EXPORT,
                    headers=_ADMIN_HEADERS,
                    params={"format": "csv"},
                )
        finally:
            _clear_db_override()
        assert r.status_code == 200
        reader = csv.reader(io.StringIO(r.text))
        parsed = list(reader)
        assert parsed[0] == list(_EXPECTED_CSV_HEADER)
        details_cell = parsed[1][6]
        details_payload = json.loads(details_cell)
        assert details_payload["refresh_token"] == "[redacted]"
        assert details_payload["nested"]["api_key"] == "[redacted]"
        assert details_payload["safe"] == "ok"
        assert "super-secret" not in r.text
        assert "also-secret" not in r.text

    def test_export_json_and_csv_exclude_raw_tenant_uuid_from_body_and_logs(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        tid = str(uuid.uuid4())
        row = _sample_row(
            tenant_id=tid,
            details={"oauth_token": "no-leak"},
        )
        _override_db([row])
        try:
            with caplog.at_level(logging.DEBUG):
                with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                    r_json = client.get(
                        AUDIT_EXPORT,
                        headers=_ADMIN_HEADERS,
                        params={"format": "json"},
                    )
                    r_csv = client.get(
                        AUDIT_EXPORT,
                        headers=_ADMIN_HEADERS,
                        params={"format": "csv"},
                    )
        finally:
            _clear_db_override()
        assert r_json.status_code == 200
        assert r_csv.status_code == 200
        assert tid not in r_json.text
        assert tid not in r_csv.text
        logged = " ".join(rec.getMessage() for rec in caplog.records)
        assert tid not in logged
