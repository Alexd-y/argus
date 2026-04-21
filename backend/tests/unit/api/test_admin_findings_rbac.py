"""Admin GET /admin/findings — full RBAC matrix.

T24 — verifies the closed-taxonomy enforcement of role × query-pattern
combinations. 4 roles (super-admin, admin, operator, unknown) × 3 query
patterns (no tenant, own tenant, other tenant) = 12 cases minimum.
"""

from __future__ import annotations

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


def _finding_row() -> MagicMock:
    row = MagicMock(spec=FindingModel)
    row.id = str(uuid.uuid4())
    row.tenant_id = str(uuid.uuid4())
    row.scan_id = str(uuid.uuid4())
    row.report_id = None
    row.severity = "high"
    row.title = "test"
    row.description = "test"
    row.cwe = None
    row.cvss = 5.0
    row.owasp_category = None
    row.confidence = "likely"
    row.dedup_status = None
    row.false_positive = False
    row.created_at = datetime(2026, 4, 20, 10, 0, 0, tzinfo=UTC)
    return row


def _ok_session(rows: list[MagicMock] | None = None, with_set_local: bool = False) -> AsyncMock:
    rows = rows if rows is not None else [_finding_row()]
    r_count = MagicMock()
    r_count.scalar_one.return_value = len(rows)
    r_list = MagicMock()
    r_list.scalars.return_value.all.return_value = rows
    side_effect: list[MagicMock] = []
    if with_set_local:
        side_effect.append(MagicMock())
    side_effect.extend([r_count, r_list])
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=side_effect)
    session.add = MagicMock()
    session.commit = AsyncMock()
    return session


@pytest.fixture
def my_tid() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def other_tid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Role 1: super-admin (default + explicit) — full matrix
# ---------------------------------------------------------------------------


class TestSuperAdminRbac:
    def test_super_admin_no_tenant_200(self, client: TestClient) -> None:
        session = _ok_session()
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

    def test_super_admin_own_tenant_200(self, client: TestClient, my_tid: str) -> None:
        session = _ok_session(with_set_local=True)
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
                        "X-Admin-Role": "super-admin",
                        "X-Admin-Tenant": my_tid,
                    },
                    params={"tenant_id": my_tid},
                )
        assert r.status_code == 200

    def test_super_admin_other_tenant_200(
        self, client: TestClient, my_tid: str, other_tid: str
    ) -> None:
        """super-admin can scope to any tenant; X-Admin-Tenant cross-check is bypassed."""
        session = _ok_session(with_set_local=True)
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
                        "X-Admin-Role": "super-admin",
                        "X-Admin-Tenant": my_tid,
                    },
                    params={"tenant_id": other_tid},
                )
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Role 2: admin — own tenant only
# ---------------------------------------------------------------------------


class TestAdminRbac:
    def test_admin_no_tenant_403(self, client: TestClient, my_tid: str) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                LIST,
                headers={
                    **_ADMIN_HEADERS,
                    "X-Admin-Role": "admin",
                    "X-Admin-Tenant": my_tid,
                },
            )
        assert r.status_code == 403

    def test_admin_own_tenant_200(self, client: TestClient, my_tid: str) -> None:
        session = _ok_session(with_set_local=True)
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
                        "X-Admin-Tenant": my_tid,
                    },
                    params={"tenant_id": my_tid},
                )
        assert r.status_code == 200

    def test_admin_other_tenant_403(
        self, client: TestClient, my_tid: str, other_tid: str
    ) -> None:
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


# ---------------------------------------------------------------------------
# Role 3: operator — same rules as admin
# ---------------------------------------------------------------------------


class TestOperatorRbac:
    def test_operator_no_tenant_403(self, client: TestClient, my_tid: str) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                LIST,
                headers={
                    **_ADMIN_HEADERS,
                    "X-Admin-Role": "operator",
                    "X-Admin-Tenant": my_tid,
                },
            )
        assert r.status_code == 403

    def test_operator_own_tenant_200(self, client: TestClient, my_tid: str) -> None:
        session = _ok_session(with_set_local=True)
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
                        "X-Admin-Tenant": my_tid,
                    },
                    params={"tenant_id": my_tid},
                )
        assert r.status_code == 200

    def test_operator_other_tenant_403(
        self, client: TestClient, my_tid: str, other_tid: str
    ) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                LIST,
                headers={
                    **_ADMIN_HEADERS,
                    "X-Admin-Role": "operator",
                    "X-Admin-Tenant": my_tid,
                },
                params={"tenant_id": other_tid},
            )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# Role 4: unknown / invalid — always 403
# ---------------------------------------------------------------------------


class TestUnknownRoleRbac:
    def test_unknown_role_no_tenant_403(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                LIST,
                headers={**_ADMIN_HEADERS, "X-Admin-Role": "viewer"},
            )
        assert r.status_code == 403

    def test_unknown_role_own_tenant_403(self, client: TestClient, my_tid: str) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                LIST,
                headers={**_ADMIN_HEADERS, "X-Admin-Role": "viewer"},
                params={"tenant_id": my_tid},
            )
        assert r.status_code == 403

    def test_unknown_role_other_tenant_403(
        self, client: TestClient, my_tid: str, other_tid: str
    ) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                LIST,
                headers={
                    **_ADMIN_HEADERS,
                    "X-Admin-Role": "viewer",
                    "X-Admin-Tenant": my_tid,
                },
                params={"tenant_id": other_tid},
            )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# Header sanitation: invalid X-Admin-Tenant UUID is rejected (403, not 500)
# ---------------------------------------------------------------------------


class TestHeaderValidation:
    def test_invalid_admin_tenant_header_uuid_403(
        self, client: TestClient, my_tid: str
    ) -> None:
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(
                LIST,
                headers={
                    **_ADMIN_HEADERS,
                    "X-Admin-Role": "admin",
                    "X-Admin-Tenant": "not-a-uuid",
                },
                params={"tenant_id": my_tid},
            )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# Closed-taxonomy errors: no stack traces, no PII in 403 details
# ---------------------------------------------------------------------------


class TestErrorTaxonomy:
    def test_403_detail_is_short_string(
        self, client: TestClient, my_tid: str, other_tid: str
    ) -> None:
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
        body = r.json()
        detail = body.get("detail", "")
        assert isinstance(detail, str)
        assert "Traceback" not in detail
        assert other_tid not in detail
        assert my_tid not in detail
