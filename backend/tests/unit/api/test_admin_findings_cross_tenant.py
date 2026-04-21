"""Admin GET /admin/findings — cross-tenant query happy paths + pagination + filters.

T24 — covers super-admin cross-tenant view, scoped queries, filter composition,
empty result envelope, pagination boundary, audit fingerprint logging, and SQL
parameterization (no f-strings reach the WHERE clause).
"""

from __future__ import annotations

import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from src.core.config import settings
from src.db.models import Finding as FindingModel

LIST = "/api/v1/admin/findings"
_ADMIN_KEY = "secret-admin-key"
_ADMIN_HEADERS = {"X-Admin-Key": _ADMIN_KEY}


def _session_factory(session: AsyncMock):
    @asynccontextmanager
    async def _cm():
        yield session

    return lambda: _cm()


def _finding_row(
    *,
    tid: str | None = None,
    severity: str = "high",
    cvss: float | None = 7.5,
    title: str = "SQL injection in login form",
    description: str | None = "Tested with sqlmap; reflected error.",
    cwe: str | None = "CWE-89",
    confidence: str = "likely",
    false_positive: bool = False,
    owasp_category: str | None = "A03",
    dedup_status: str | None = "unique",
) -> MagicMock:
    row = MagicMock(spec=FindingModel)
    row.id = str(uuid.uuid4())
    row.tenant_id = tid or str(uuid.uuid4())
    row.scan_id = str(uuid.uuid4())
    row.report_id = None
    row.severity = severity
    row.title = title
    row.description = description
    row.cwe = cwe
    row.cvss = cvss
    row.owasp_category = owasp_category
    row.confidence = confidence
    row.dedup_status = dedup_status
    row.false_positive = false_positive
    row.created_at = datetime(2026, 4, 20, 10, 0, 0, tzinfo=UTC)
    return row


def _build_session(rows: list[MagicMock], total: int | None = None) -> AsyncMock:
    """Mock async session: count → rows order matches handler execute() sequence."""
    r_count = MagicMock()
    r_count.scalar_one.return_value = total if total is not None else len(rows)
    r_list = MagicMock()
    r_list.scalars.return_value.all.return_value = rows
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=[r_count, r_list])
    session.add = MagicMock()
    session.commit = AsyncMock()
    return session


def _build_session_with_set_local(rows: list[MagicMock], total: int | None = None) -> AsyncMock:
    """Same as _build_session but with one extra leading execute() for SET LOCAL."""
    r_set = MagicMock()
    r_count = MagicMock()
    r_count.scalar_one.return_value = total if total is not None else len(rows)
    r_list = MagicMock()
    r_list.scalars.return_value.all.return_value = rows
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=[r_set, r_count, r_list])
    session.add = MagicMock()
    session.commit = AsyncMock()
    return session


class TestAdminFindingsAuth:
    """X-Admin-Key gate (existing require_admin pattern)."""

    def test_list_401_without_key(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(LIST)
        assert r.status_code == 401

    def test_list_401_wrong_key(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(LIST, headers={"X-Admin-Key": "nope"})
        assert r.status_code == 401


class TestSuperAdminCrossTenant:
    """Default role (no header) ⇒ super-admin cross-tenant behaviour preserved."""

    def test_default_role_cross_tenant_returns_rows_no_set_local(
        self, client: TestClient
    ) -> None:
        rows = [
            _finding_row(severity="critical", cvss=9.8),
            _finding_row(severity="high", cvss=7.5),
        ]
        session = _build_session(rows)
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_findings.async_session_factory",
                factory,
            ):
                with patch(
                    "src.api.routers.admin_findings.set_session_tenant",
                    new_callable=AsyncMock,
                ) as mock_set_tenant:
                    r = client.get(LIST, headers=_ADMIN_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 2
        assert len(data["findings"]) == 2
        assert data["limit"] == 50
        assert data["offset"] == 0
        assert data["has_more"] is False
        assert data["findings"][0]["severity"] == "critical"
        mock_set_tenant.assert_not_awaited()

    def test_explicit_super_admin_role_cross_tenant(self, client: TestClient) -> None:
        rows = [_finding_row(severity="medium", cvss=5.0)]
        session = _build_session(rows)
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_findings.async_session_factory",
                factory,
            ):
                r = client.get(
                    LIST,
                    headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                )
        assert r.status_code == 200
        assert r.json()["total"] == 1

    def test_super_admin_with_tenant_id_uses_set_local(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        rows = [_finding_row(tid=tid, severity="low")]
        session = _build_session_with_set_local(rows)
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_findings.async_session_factory",
                factory,
            ):
                with patch(
                    "src.api.routers.admin_findings.set_session_tenant",
                    new_callable=AsyncMock,
                ) as mock_set_tenant:
                    r = client.get(
                        LIST,
                        headers={**_ADMIN_HEADERS, "X-Admin-Role": "super-admin"},
                        params={"tenant_id": tid},
                    )
        assert r.status_code == 200
        mock_set_tenant.assert_awaited_once()
        assert mock_set_tenant.await_args[0][1] == tid


class TestAdminScopedRole:
    """admin role ⇒ tenant_id required AND must match X-Admin-Tenant header."""

    def test_admin_scoped_query_returns_rows(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        rows = [_finding_row(tid=tid, severity="high")]
        session = _build_session_with_set_local(rows)
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_findings.async_session_factory",
                factory,
            ):
                r = client.get(
                    LIST,
                    headers={
                        **_ADMIN_HEADERS,
                        "X-Admin-Role": "admin",
                        "X-Admin-Tenant": tid,
                    },
                    params={"tenant_id": tid},
                )
        assert r.status_code == 200
        assert r.json()["total"] == 1

    def test_admin_without_tenant_id_query_param_403(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                LIST,
                headers={
                    **_ADMIN_HEADERS,
                    "X-Admin-Role": "admin",
                    "X-Admin-Tenant": tid,
                },
            )
        assert r.status_code == 403
        assert "tenant_id" in r.json().get("detail", "").lower()

    def test_admin_tenant_mismatch_403(self, client: TestClient) -> None:
        my_tid = str(uuid.uuid4())
        other_tid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                LIST,
                headers={
                    **_ADMIN_HEADERS,
                    "X-Admin-Role": "admin",
                    "X-Admin-Tenant": my_tid,
                },
                params={"tenant_id": other_tid},
            )
        assert r.status_code == 403
        assert "mismatch" in r.json().get("detail", "").lower()

    def test_admin_missing_tenant_header_403(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                LIST,
                headers={**_ADMIN_HEADERS, "X-Admin-Role": "admin"},
                params={"tenant_id": tid},
            )
        assert r.status_code == 403


class TestOperatorScopedRole:
    """operator role uses identical scoping rules to admin."""

    def test_operator_scoped_query_returns_rows(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        rows = [_finding_row(tid=tid, severity="info")]
        session = _build_session_with_set_local(rows)
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_findings.async_session_factory",
                factory,
            ):
                r = client.get(
                    LIST,
                    headers={
                        **_ADMIN_HEADERS,
                        "X-Admin-Role": "operator",
                        "X-Admin-Tenant": tid,
                    },
                    params={"tenant_id": tid},
                )
        assert r.status_code == 200
        assert r.json()["total"] == 1

    def test_operator_cross_tenant_attempt_403(self, client: TestClient) -> None:
        tid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                LIST,
                headers={
                    **_ADMIN_HEADERS,
                    "X-Admin-Role": "operator",
                    "X-Admin-Tenant": tid,
                },
            )
        assert r.status_code == 403


class TestPaginationAndFilters:
    """Filters compose, pagination envelope is computed correctly."""

    def test_empty_result_envelope(self, client: TestClient) -> None:
        session = _build_session([], total=0)
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_findings.async_session_factory",
                factory,
            ):
                r = client.get(LIST, headers=_ADMIN_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["findings"] == []
        assert data["total"] == 0
        assert data["has_more"] is False

    def test_pagination_has_more_true(self, client: TestClient) -> None:
        rows = [_finding_row() for _ in range(50)]
        session = _build_session(rows, total=120)
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_findings.async_session_factory",
                factory,
            ):
                r = client.get(
                    LIST,
                    headers=_ADMIN_HEADERS,
                    params={"limit": 50, "offset": 0},
                )
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 120
        assert data["limit"] == 50
        assert data["offset"] == 0
        assert data["has_more"] is True
        assert len(data["findings"]) == 50

    def test_pagination_offset_at_boundary_has_more_false(self, client: TestClient) -> None:
        rows = [_finding_row() for _ in range(20)]
        session = _build_session(rows, total=120)
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_findings.async_session_factory",
                factory,
            ):
                r = client.get(
                    LIST,
                    headers=_ADMIN_HEADERS,
                    params={"limit": 50, "offset": 100},
                )
        assert r.status_code == 200
        data = r.json()
        assert data["offset"] == 100
        assert data["has_more"] is False

    def test_filter_severity_multi_value(self, client: TestClient) -> None:
        rows = [
            _finding_row(severity="critical"),
            _finding_row(severity="high"),
        ]
        session = _build_session(rows)
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_findings.async_session_factory",
                factory,
            ):
                r = client.get(
                    LIST,
                    headers=_ADMIN_HEADERS,
                    params=[("severity", "critical"), ("severity", "high")],
                )
        assert r.status_code == 200
        assert r.json()["total"] == 2

    def test_filter_free_text_q_with_special_chars(self, client: TestClient) -> None:
        """``%`` and ``_`` in q must not break the query (escaped for ESCAPE '\\')."""
        rows = [_finding_row(title="100%_loss")]
        session = _build_session(rows)
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_findings.async_session_factory",
                factory,
            ):
                r = client.get(
                    LIST,
                    headers=_ADMIN_HEADERS,
                    params={"q": "100%_loss"},
                )
        assert r.status_code == 200
        assert r.json()["total"] == 1

    def test_filter_false_positive_true(self, client: TestClient) -> None:
        rows = [_finding_row(false_positive=True)]
        session = _build_session(rows)
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_findings.async_session_factory",
                factory,
            ):
                r = client.get(
                    LIST,
                    headers=_ADMIN_HEADERS,
                    params={"false_positive": "true"},
                )
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 1
        assert data["findings"][0]["false_positive"] is True

    def test_filter_time_window(self, client: TestClient) -> None:
        rows = [_finding_row()]
        session = _build_session(rows)
        factory = _session_factory(session)
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            with patch(
                "src.api.routers.admin_findings.async_session_factory",
                factory,
            ):
                r = client.get(
                    LIST,
                    headers=_ADMIN_HEADERS,
                    params={
                        "since": "2026-04-01T00:00:00Z",
                        "until": "2026-04-30T00:00:00Z",
                    },
                )
        assert r.status_code == 200


class TestValidationErrors:
    def test_422_until_before_since(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                LIST,
                headers=_ADMIN_HEADERS,
                params={
                    "since": "2026-04-30T00:00:00Z",
                    "until": "2026-04-01T00:00:00Z",
                },
            )
        assert r.status_code == 422

    def test_422_limit_above_cap(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(LIST, headers=_ADMIN_HEADERS, params={"limit": 201})
        assert r.status_code == 422

    def test_422_limit_zero(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(LIST, headers=_ADMIN_HEADERS, params={"limit": 0})
        assert r.status_code == 422

    def test_422_q_too_long(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                LIST,
                headers=_ADMIN_HEADERS,
                params={"q": "x" * 201},
            )
        assert r.status_code == 422

    def test_422_invalid_tenant_uuid(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                LIST,
                headers=_ADMIN_HEADERS,
                params={"tenant_id": "not-a-uuid"},
            )
        assert r.status_code == 422


class TestAuditLogging:
    """Read-only endpoint: structured log + sha256 fingerprint, never raw IDs."""

    def test_logs_query_fingerprint_no_raw_tenant(
        self,
        client: TestClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        tid = str(uuid.uuid4())
        rows = [_finding_row(tid=tid)]
        session = _build_session_with_set_local(rows)
        factory = _session_factory(session)
        with caplog.at_level(logging.INFO):
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                with patch(
                    "src.api.routers.admin_findings.async_session_factory",
                    factory,
                ):
                    r = client.get(
                        LIST,
                        headers={
                            **_ADMIN_HEADERS,
                            "X-Admin-Role": "admin",
                            "X-Admin-Tenant": tid,
                        },
                        params={"tenant_id": tid},
                    )
        assert r.status_code == 200
        record = next(
            (rec for rec in caplog.records if rec.message == "admin.findings_query"),
            None,
        )
        assert record is not None, "expected admin.findings_query log emission"
        extra = {
            k: getattr(record, k, None)
            for k in (
                "event",
                "role",
                "tenant_hash",
                "user_id_hash",
                "query_fingerprint",
                "result_count",
                "total",
                "limit",
                "offset",
                "has_more",
                "cross_tenant",
            )
        }
        assert extra["event"] == "argus.admin.findings_query"
        assert extra["role"] == "admin"
        assert isinstance(extra["query_fingerprint"], str)
        assert len(extra["query_fingerprint"]) == 24
        assert extra["cross_tenant"] is False
        rendered = json.dumps(extra, default=str)
        assert tid not in rendered

    def test_logs_cross_tenant_true_when_no_tenant(
        self,
        client: TestClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        rows = [_finding_row()]
        session = _build_session(rows)
        factory = _session_factory(session)
        with caplog.at_level(logging.INFO):
            with patch.object(settings, "admin_api_key", _ADMIN_KEY):
                with patch(
                    "src.api.routers.admin_findings.async_session_factory",
                    factory,
                ):
                    r = client.get(LIST, headers=_ADMIN_HEADERS)
        assert r.status_code == 200
        record = next(
            (rec for rec in caplog.records if rec.message == "admin.findings_query"),
            None,
        )
        assert record is not None
        assert getattr(record, "cross_tenant", None) is True
        assert getattr(record, "tenant_hash", "sentinel") is None
