"""Admin tenant delete — RBAC and happy path (mocked DB)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from main import app
from src.core.config import settings
from src.db.session import get_db

_ADMIN_KEY = "secret-admin-key"
_ADMIN_HEADERS = {"X-Admin-Key": _ADMIN_KEY}


@pytest.fixture
def _clear_db_override():
    yield
    app.dependency_overrides.pop(get_db, None)


def test_delete_tenant_401_without_key(client: TestClient, _clear_db_override) -> None:
    tid = str(uuid.uuid4())
    with patch.object(settings, "admin_api_key", _ADMIN_KEY):
        r = client.delete(f"/api/v1/admin/tenants/{tid}")
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid X-Admin-Key"


def test_delete_tenant_204(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    tenant = MagicMock()

    r_exec = MagicMock()
    r_exec.scalar_one_or_none.return_value = tenant

    session = AsyncMock()
    session.execute = AsyncMock(return_value=r_exec)
    session.delete = AsyncMock()
    session.flush = AsyncMock()

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.delete(f"/api/v1/admin/tenants/{tid}", headers=_ADMIN_HEADERS)
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert r.status_code == 204
    assert r.content == b""
    session.delete.assert_awaited_once_with(tenant)


def test_delete_tenant_404(client: TestClient, _clear_db_override, monkeypatch) -> None:
    tid = str(uuid.uuid4())
    r_exec = MagicMock()
    r_exec.scalar_one_or_none.return_value = None
    session = AsyncMock()
    session.execute = AsyncMock(return_value=r_exec)

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.delete(f"/api/v1/admin/tenants/{tid}", headers=_ADMIN_HEADERS)
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert r.status_code == 404
    assert r.json()["detail"] == "Tenant not found"
