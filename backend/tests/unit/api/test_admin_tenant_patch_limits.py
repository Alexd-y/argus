"""Admin tenant PATCH — limit fields validation (422)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from starlette.testclient import TestClient

from main import app
from src.core.config import settings
from src.db.session import get_db

_ADMIN_KEY = "secret-admin-key"
_ADMIN_HEADERS = {"X-Admin-Key": _ADMIN_KEY, "Content-Type": "application/json"}


@pytest.fixture
def _clear_db_override():
    yield
    app.dependency_overrides.pop(get_db, None)


def test_patch_tenant_rate_limit_out_of_range_422(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    tenant = MagicMock()
    r_exec = MagicMock()
    r_exec.scalar_one_or_none.return_value = tenant
    session = AsyncMock()
    session.execute = AsyncMock(return_value=r_exec)

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.patch(
            f"/api/v1/admin/tenants/{tid}",
            headers=_ADMIN_HEADERS,
            json={"rate_limit_rpm": 0},
        )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert r.status_code == 422


def test_patch_tenant_scope_blacklist_too_long_entry_422(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    tenant = MagicMock()
    r_exec = MagicMock()
    r_exec.scalar_one_or_none.return_value = tenant
    session = AsyncMock()
    session.execute = AsyncMock(return_value=r_exec)

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.patch(
            f"/api/v1/admin/tenants/{tid}",
            headers=_ADMIN_HEADERS,
            json={"scope_blacklist": ["x" * 600]},
        )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert r.status_code == 422


def test_patch_tenant_retention_out_of_range_422(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    tenant = MagicMock()
    r_exec = MagicMock()
    r_exec.scalar_one_or_none.return_value = tenant
    session = AsyncMock()
    session.execute = AsyncMock(return_value=r_exec)

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.patch(
            f"/api/v1/admin/tenants/{tid}",
            headers=_ADMIN_HEADERS,
            json={"retention_days": 5000},
        )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert r.status_code == 422
