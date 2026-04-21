"""Admin per-tenant throttle endpoint (T31, ARG-052).

Covers RBAC, validation, tenant existence enforcement, Redis fail-closed
semantics, audit attribution, and PolicyEngine integration consequences for
``POST /admin/system/emergency/throttle``.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from src.api.routers.admin_emergency import _kill_switch_dep
from src.core.config import settings
from src.policy.kill_switch import KillSwitchService

THROTTLE = "/api/v1/admin/system/emergency/throttle"

_ADMIN_KEY = "secret-admin-key-throttle"
_HEADERS_BASE = {
    "X-Admin-Key": _ADMIN_KEY,
    "X-Admin-Role": "super-admin",
    "X-Operator-Subject": "soc-team@argus.example",
}
_HEADERS_OPERATOR = {**_HEADERS_BASE, "X-Admin-Role": "operator"}
_HEADERS_ADMIN = {**_HEADERS_BASE, "X-Admin-Role": "admin"}


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class _FakeRedis:
    def __init__(self) -> None:
        self._data: dict[str, str] = {}
        self._ttls: dict[str, int] = {}

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def set(
        self,
        key: str,
        value: str,
        *,
        ex: int | None = None,
        nx: bool = False,
    ) -> bool:
        # Mirror redis-py SET NX semantics; throttle does not currently use
        # nx, but the stub stays in lock-step with the kill_switch test stub.
        if nx and key in self._data:
            return False
        self._data[key] = value
        if ex is not None:
            self._ttls[key] = int(ex)
        return True

    def delete(self, key: str) -> int:
        existed = key in self._data
        self._data.pop(key, None)
        self._ttls.pop(key, None)
        return 1 if existed else 0

    def scan_iter(self, *, match: str, count: int = 100) -> list[str]:
        if not match.endswith("*"):
            return [k for k in self._data if k == match]
        prefix = match[:-1]
        return [k for k in self._data if k.startswith(prefix)]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_redis() -> _FakeRedis:
    return _FakeRedis()


@pytest.fixture()
def kill_switch(fake_redis: _FakeRedis) -> KillSwitchService:
    return KillSwitchService(fake_redis)


@pytest.fixture()
def offline_kill_switch() -> KillSwitchService:
    return KillSwitchService(redis_client=None)


@pytest.fixture(autouse=True)
def _admin_api_key():
    with patch.object(settings, "admin_api_key", _ADMIN_KEY):
        yield


@pytest.fixture()
def override_kill_switch(client: TestClient, kill_switch: KillSwitchService):
    client.app.dependency_overrides[_kill_switch_dep] = lambda: kill_switch
    try:
        yield kill_switch
    finally:
        client.app.dependency_overrides.pop(_kill_switch_dep, None)


@pytest.fixture()
def override_kill_switch_offline(
    client: TestClient, offline_kill_switch: KillSwitchService
):
    client.app.dependency_overrides[_kill_switch_dep] = lambda: offline_kill_switch
    try:
        yield offline_kill_switch
    finally:
        client.app.dependency_overrides.pop(_kill_switch_dep, None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _session_factory(session: AsyncMock):
    @asynccontextmanager
    async def _cm():
        yield session

    return lambda: _cm()


def _throttle_body(
    *,
    tenant_id: str | None = None,
    duration_minutes: int = 60,
    reason: str = "Tenant misconfigured scanner — throttle for triage",
) -> dict:
    return {
        "tenant_id": tenant_id or str(uuid.uuid4()),
        "duration_minutes": duration_minutes,
        "reason": reason,
    }


def _make_session(*, tenant_exists: bool = True) -> AsyncMock:
    """Mock session: one ``SELECT count(...)`` then a ``add(audit)`` flush."""
    count_result = MagicMock()
    count_result.scalar_one.return_value = 1 if tenant_exists else 0
    session = AsyncMock()
    session.execute = AsyncMock(return_value=count_result)
    session.add = MagicMock()
    session.commit = AsyncMock()
    return session


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


class TestEmergencyThrottleRbac:
    def test_throttle_401_without_admin_key(self, client: TestClient) -> None:
        r = client.post(THROTTLE, json=_throttle_body())
        assert r.status_code == 401

    def test_throttle_403_for_operator(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        r = client.post(THROTTLE, headers=_HEADERS_OPERATOR, json=_throttle_body())
        assert r.status_code == 403
        assert r.json()["detail"] == "forbidden"

    def test_throttle_403_admin_without_session_tenant_header(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        body = _throttle_body()
        r = client.post(THROTTLE, headers=_HEADERS_ADMIN, json=body)
        assert r.status_code == 403

    def test_throttle_403_admin_cross_tenant(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        target_tenant = str(uuid.uuid4())
        other_tenant = str(uuid.uuid4())
        admin_headers = {**_HEADERS_ADMIN, "X-Admin-Tenant": other_tenant}
        r = client.post(
            THROTTLE,
            headers=admin_headers,
            json=_throttle_body(tenant_id=target_tenant),
        )
        assert r.status_code == 403
        assert r.json()["detail"] == "tenant mismatch"

    def test_throttle_200_admin_own_tenant(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
        fake_redis: _FakeRedis,
    ) -> None:
        tenant_id = str(uuid.uuid4())
        admin_headers = {**_HEADERS_ADMIN, "X-Admin-Tenant": tenant_id}
        session = _make_session(tenant_exists=True)
        with patch(
            "src.api.routers.admin_emergency.async_session_factory",
            _session_factory(session),
        ):
            r = client.post(
                THROTTLE,
                headers=admin_headers,
                json=_throttle_body(tenant_id=tenant_id, duration_minutes=15),
            )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "throttled"
        assert body["tenant_id"] == tenant_id
        assert body["duration_minutes"] == 15
        assert f"argus:emergency:tenant:{tenant_id}" in fake_redis._data


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestEmergencyThrottleValidation:
    @pytest.mark.parametrize("bad_duration", [0, 1, 5, 30, 90, 9999])
    def test_throttle_422_for_disallowed_duration(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
        bad_duration: int,
    ) -> None:
        r = client.post(
            THROTTLE,
            headers=_HEADERS_BASE,
            json=_throttle_body(duration_minutes=bad_duration),
        )
        assert r.status_code == 422

    def test_throttle_422_when_reason_blank(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        r = client.post(
            THROTTLE,
            headers=_HEADERS_BASE,
            json=_throttle_body(reason="          "),
        )
        assert r.status_code == 422

    def test_throttle_422_when_tenant_id_invalid_uuid(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        r = client.post(
            THROTTLE,
            headers=_HEADERS_BASE,
            json={
                "tenant_id": "not-a-uuid",
                "duration_minutes": 60,
                "reason": "tenant misconfig — throttle",
            },
        )
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# Existence + 503 + happy path
# ---------------------------------------------------------------------------


class TestEmergencyThrottleHappyPath:
    @pytest.mark.parametrize("duration_minutes", [15, 60, 240, 1440])
    def test_throttle_200_for_each_allowed_duration(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
        fake_redis: _FakeRedis,
        duration_minutes: int,
    ) -> None:
        tenant_id = str(uuid.uuid4())
        session = _make_session(tenant_exists=True)
        with patch(
            "src.api.routers.admin_emergency.async_session_factory",
            _session_factory(session),
        ):
            r = client.post(
                THROTTLE,
                headers=_HEADERS_BASE,
                json=_throttle_body(
                    tenant_id=tenant_id, duration_minutes=duration_minutes
                ),
            )
        assert r.status_code == 200
        body = r.json()
        assert body["duration_minutes"] == duration_minutes
        assert (
            fake_redis._ttls[f"argus:emergency:tenant:{tenant_id}"]
            == duration_minutes * 60
        )
        session.commit.assert_awaited()

    def test_throttle_404_when_tenant_does_not_exist(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        session = _make_session(tenant_exists=False)
        with patch(
            "src.api.routers.admin_emergency.async_session_factory",
            _session_factory(session),
        ):
            r = client.post(THROTTLE, headers=_HEADERS_BASE, json=_throttle_body())
        assert r.status_code == 404
        assert r.json()["detail"] == "tenant not found"

    def test_throttle_503_when_redis_unavailable(
        self,
        client: TestClient,
        override_kill_switch_offline: KillSwitchService,
    ) -> None:
        session = _make_session(tenant_exists=True)
        with patch(
            "src.api.routers.admin_emergency.async_session_factory",
            _session_factory(session),
        ):
            r = client.post(THROTTLE, headers=_HEADERS_BASE, json=_throttle_body())
        assert r.status_code == 503
        assert r.json()["detail"] == "emergency_store_unavailable"

    def test_throttle_persists_hashed_operator_subject_only(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
        fake_redis: _FakeRedis,
    ) -> None:
        tenant_id = str(uuid.uuid4())
        operator = "named-operator@argus.example"
        session = _make_session(tenant_exists=True)
        with patch(
            "src.api.routers.admin_emergency.async_session_factory",
            _session_factory(session),
        ):
            r = client.post(
                THROTTLE,
                headers={**_HEADERS_BASE, "X-Operator-Subject": operator},
                json=_throttle_body(tenant_id=tenant_id),
            )
        assert r.status_code == 200
        raw = fake_redis.get(f"argus:emergency:tenant:{tenant_id}")
        assert raw is not None
        assert operator not in raw, (
            "raw operator subject must never be persisted to Redis"
        )

    def test_throttle_response_includes_audit_id_and_expires_at(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
    ) -> None:
        session = _make_session(tenant_exists=True)
        with patch(
            "src.api.routers.admin_emergency.async_session_factory",
            _session_factory(session),
        ):
            r = client.post(
                THROTTLE,
                headers=_HEADERS_BASE,
                json=_throttle_body(duration_minutes=240),
            )
        body = r.json()
        assert len(body["audit_id"]) == 36
        assert "expires_at" in body
