"""Admin tenant targets + preview-scope (mocked DB)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from main import app
from src.core.config import settings
from src.db.models import Target
from src.db.session import get_db

_ADMIN_KEY = "secret-admin-key"
_ADMIN_HEADERS = {"X-Admin-Key": _ADMIN_KEY, "Content-Type": "application/json"}


@pytest.fixture
def _clear_db_override():
    yield
    app.dependency_overrides.pop(get_db, None)


def _session_with_tenant(tenant_id: str) -> AsyncMock:
    tenant = MagicMock()
    tenant.id = tenant_id
    r_tenant = MagicMock()
    r_tenant.scalar_one_or_none.return_value = tenant
    session = AsyncMock()
    session.execute = AsyncMock(return_value=r_tenant)
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session.delete = AsyncMock()
    return session


def test_list_targets_404_unknown_tenant(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    r_tenant = MagicMock()
    r_tenant.scalar_one_or_none.return_value = None
    session = AsyncMock()
    session.execute = AsyncMock(return_value=r_tenant)

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.get(
            f"/api/v1/admin/tenants/{tid}/targets",
            headers=_ADMIN_HEADERS,
        )
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 404


def test_create_target_422_invalid_scope_rule(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    session = _session_with_tenant(tid)

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.post(
            f"/api/v1/admin/tenants/{tid}/targets",
            headers=_ADMIN_HEADERS,
            json={"url": "https://example.com", "scope_config": {"rules": [{"bad": True}]}},
        )
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 422
    assert r.json()["detail"] == "Invalid scope rule"


def test_preview_scope_probe_domain_allowed(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    session = _session_with_tenant(tid)
    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)

    async def _fake_get_db():
        yield session

    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.post(
            f"/api/v1/admin/tenants/{tid}/preview-scope",
            headers=_ADMIN_HEADERS,
            json={
                "probe": "https://a.example.com/",
                "rules": [
                    {
                        "kind": "domain",
                        "pattern": "example.com",
                        "deny": False,
                    }
                ],
            },
        )
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 200
    body = r.json()
    assert body["scope_allowed"] is True
    assert body["scope_failure_summary"] is None


def test_preview_scope_cidr_invalid_422(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    session = _session_with_tenant(tid)
    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)

    async def _fake_get_db():
        yield session

    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.post(
            f"/api/v1/admin/tenants/{tid}/preview-scope",
            headers=_ADMIN_HEADERS,
            json={
                "probe": "10.0.0.1",
                "rules": [],
                "cidr": "not-a-cidr",
            },
        )
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 422


def _tenant_result_ok(tenant_id: str) -> MagicMock:
    tenant = MagicMock()
    tenant.id = tenant_id
    r = MagicMock()
    r.scalar_one_or_none.return_value = tenant
    return r


def _policy_execute_empty() -> MagicMock:
    r_pol = MagicMock()
    r_pol.scalars.return_value.all.return_value = []
    return r_pol


def test_list_targets_200_empty(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    r_tenant = _tenant_result_ok(tid)
    r_targets = MagicMock()
    r_targets.scalars.return_value.all.return_value = []
    r_pol = _policy_execute_empty()
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=[r_tenant, r_targets, r_pol])

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.get(f"/api/v1/admin/tenants/{tid}/targets", headers=_ADMIN_HEADERS)
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 200
    assert r.json() == []


def test_create_target_200_with_mocked_session(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    r_tenant = _tenant_result_ok(tid)
    r_pol = _policy_execute_empty()
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=[r_tenant, r_pol])

    async def _flush() -> None:
        call = session.add.call_args
        assert call is not None
        row = call[0][0]
        rid = str(uuid.uuid4())
        ts = datetime.now(timezone.utc)
        object.__setattr__(row, "id", rid)
        object.__setattr__(row, "created_at", ts)

    session.flush = AsyncMock(side_effect=_flush)
    session.refresh = AsyncMock()

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.post(
            f"/api/v1/admin/tenants/{tid}/targets",
            headers=_ADMIN_HEADERS,
            json={
                "url": "https://example.com/path",
                "scope_config": {"rules": []},
            },
        )
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 200
    body = r.json()
    assert body["tenant_id"] == tid
    assert body["url"] == "https://example.com/path"
    assert body["scope_config"] == {"rules": []}
    assert body["id"]
    session.add.assert_called_once()
    added = session.add.call_args[0][0]
    assert isinstance(added, Target)
    assert added.tenant_id == tid


def test_patch_target_200(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    target_id = str(uuid.uuid4())
    r_tenant = _tenant_result_ok(tid)
    row = MagicMock()
    row.id = target_id
    row.tenant_id = tid
    row.url = "https://old.example/"
    row.scope_config = {"rules": []}
    row.created_at = datetime.now(timezone.utc)
    r_target = MagicMock()
    r_target.scalar_one_or_none.return_value = row
    r_pol = _policy_execute_empty()
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=[r_tenant, r_target, r_pol])
    session.flush = AsyncMock()
    session.refresh = AsyncMock()

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.patch(
            f"/api/v1/admin/tenants/{tid}/targets/{target_id}",
            headers=_ADMIN_HEADERS,
            json={
                "url": "https://new.example/",
                "scope_config": {
                    "rules": [
                        {"kind": "domain", "pattern": "example.com", "deny": False},
                    ]
                },
            },
        )
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == target_id
    assert body["url"] == "https://new.example/"
    assert body["scope_config"]["rules"][0]["kind"] == "domain"


def test_delete_target_204(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    target_id = str(uuid.uuid4())
    r_tenant = _tenant_result_ok(tid)
    row = MagicMock()
    r_target = MagicMock()
    r_target.scalar_one_or_none.return_value = row
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=[r_tenant, r_target])
    session.delete = AsyncMock()
    session.flush = AsyncMock()

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.delete(
            f"/api/v1/admin/tenants/{tid}/targets/{target_id}",
            headers=_ADMIN_HEADERS,
        )
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 204
    assert r.content == b""
    session.delete.assert_awaited_once_with(row)


def test_preview_scope_domain_deny_rule(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    session = _session_with_tenant(tid)
    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)

    async def _fake_get_db():
        yield session

    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.post(
            f"/api/v1/admin/tenants/{tid}/preview-scope",
            headers=_ADMIN_HEADERS,
            json={
                "probe": "https://api.example.com/",
                "rules": [
                    {"kind": "domain", "pattern": "example.com", "deny": True},
                ],
            },
        )
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 200
    body = r.json()
    assert body["scope_allowed"] is False
    assert body["scope_failure_summary"] == "target_explicitly_denied"


def test_preview_scope_out_of_scope_url(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    session = _session_with_tenant(tid)
    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)

    async def _fake_get_db():
        yield session

    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.post(
            f"/api/v1/admin/tenants/{tid}/preview-scope",
            headers=_ADMIN_HEADERS,
            json={
                "probe": "https://evil.test/",
                "rules": [
                    {"kind": "domain", "pattern": "example.com", "deny": False},
                ],
            },
        )
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 200
    body = r.json()
    assert body["scope_allowed"] is False
    assert body["scope_failure_summary"] == "target_not_in_scope"


def test_preview_scope_empty_rules_denied(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    session = _session_with_tenant(tid)
    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)

    async def _fake_get_db():
        yield session

    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.post(
            f"/api/v1/admin/tenants/{tid}/preview-scope",
            headers=_ADMIN_HEADERS,
            json={
                "probe": "https://example.com/",
                "rules": [],
            },
        )
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 200
    body = r.json()
    assert body["scope_allowed"] is False
    assert body["scope_failure_summary"] == "target_not_in_scope"


def test_delete_target_twice_same_id_second_404(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    target_id = str(uuid.uuid4())
    r_tenant = _tenant_result_ok(tid)
    row = MagicMock()
    r_target_first = MagicMock()
    r_target_first.scalar_one_or_none.return_value = row
    r_target_second = MagicMock()
    r_target_second.scalar_one_or_none.return_value = None

    request_idx = {"n": 0}

    async def _fake_get_db():
        session = AsyncMock()
        session.delete = AsyncMock()
        session.flush = AsyncMock()
        i = request_idx["n"]
        request_idx["n"] += 1
        if i == 0:
            session.execute = AsyncMock(side_effect=[r_tenant, r_target_first])
        else:
            session.execute = AsyncMock(side_effect=[r_tenant, r_target_second])
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r1 = client.delete(
            f"/api/v1/admin/tenants/{tid}/targets/{target_id}",
            headers=_ADMIN_HEADERS,
        )
        r2 = client.delete(
            f"/api/v1/admin/tenants/{tid}/targets/{target_id}",
            headers=_ADMIN_HEADERS,
        )
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r1.status_code == 204
    assert r2.status_code == 404
    assert r2.json()["detail"] == "Target not found"


def test_patch_target_422_no_fields(
    client: TestClient, _clear_db_override, monkeypatch: pytest.MonkeyPatch
) -> None:
    tid = str(uuid.uuid4())
    target_id = str(uuid.uuid4())
    session = _session_with_tenant(tid)

    async def _fake_get_db():
        yield session

    monkeypatch.setattr(settings, "admin_api_key", _ADMIN_KEY)
    app.dependency_overrides[get_db] = _fake_get_db
    try:
        r = client.patch(
            f"/api/v1/admin/tenants/{tid}/targets/{target_id}",
            headers=_ADMIN_HEADERS,
            json={},
        )
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert r.status_code == 422
    assert r.json()["detail"] == "No fields to update"


class TestAdminTargetsRbac:
    """401 when X-Admin-Key missing (same pattern as test_admin_bulk_ops / tenant_delete)."""

    def test_list_targets_401_without_key(
        self, client: TestClient, _clear_db_override
    ) -> None:
        tid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.get(f"/api/v1/admin/tenants/{tid}/targets")
        assert r.status_code == 401
        assert r.json()["detail"] == "Invalid X-Admin-Key"

    def test_create_target_401_without_key(
        self, client: TestClient, _clear_db_override
    ) -> None:
        tid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                f"/api/v1/admin/tenants/{tid}/targets",
                json={"url": "https://example.com"},
            )
        assert r.status_code == 401
        assert r.json()["detail"] == "Invalid X-Admin-Key"

    def test_patch_target_401_without_key(
        self, client: TestClient, _clear_db_override
    ) -> None:
        tid = str(uuid.uuid4())
        target_id = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.patch(
                f"/api/v1/admin/tenants/{tid}/targets/{target_id}",
                json={"url": "https://x.com"},
            )
        assert r.status_code == 401
        assert r.json()["detail"] == "Invalid X-Admin-Key"

    def test_delete_target_401_without_key(
        self, client: TestClient, _clear_db_override
    ) -> None:
        tid = str(uuid.uuid4())
        target_id = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.delete(f"/api/v1/admin/tenants/{tid}/targets/{target_id}")
        assert r.status_code == 401
        assert r.json()["detail"] == "Invalid X-Admin-Key"

    def test_preview_scope_401_without_key(
        self, client: TestClient, _clear_db_override
    ) -> None:
        tid = str(uuid.uuid4())
        with patch.object(settings, "admin_api_key", _ADMIN_KEY):
            r = client.post(
                f"/api/v1/admin/tenants/{tid}/preview-scope",
                json={"probe": "https://a.com/", "rules": []},
            )
        assert r.status_code == 401
        assert r.json()["detail"] == "Invalid X-Admin-Key"
