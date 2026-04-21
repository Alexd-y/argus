"""Admin emergency stop_all + resume_all + status + audit-trail (T31, ARG-052).

Covers RBAC, validation, idempotency, audit attribution, and Redis fail-open
/ fail-closed semantics for the global emergency endpoints. ``fakeredis`` is
NOT a project dependency, so a deterministic in-memory ``_FakeRedis`` is
injected as the kill-switch backing store via FastAPI dependency override.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from src.api.routers.admin_emergency import (
    EVENT_RESUME_ALL,
    EVENT_STOP_ALL,
    _kill_switch_dep,
)
from src.core.config import settings
from src.policy.kill_switch import KillSwitchService

STOP_ALL = "/api/v1/admin/system/emergency/stop_all"
RESUME_ALL = "/api/v1/admin/system/emergency/resume_all"
STATUS = "/api/v1/admin/system/emergency/status"
AUDIT_TRAIL = "/api/v1/admin/system/emergency/audit-trail"

_ADMIN_KEY = "secret-admin-key-emergency"
_HEADERS_BASE = {
    "X-Admin-Key": _ADMIN_KEY,
    "X-Admin-Role": "super-admin",
    "X-Operator-Subject": "incident-commander@argus.example",
}
_HEADERS_OPERATOR = {**_HEADERS_BASE, "X-Admin-Role": "operator"}
_HEADERS_ADMIN = {**_HEADERS_BASE, "X-Admin-Role": "admin"}


# ---------------------------------------------------------------------------
# In-memory Redis stub — mirrors the redis-py surface used by the service.
# ---------------------------------------------------------------------------


class _FakeRedis:
    def __init__(self) -> None:
        self._data: dict[str, str] = {}
        self._ttls: dict[str, int] = {}

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def set(self, key: str, value: str, *, ex: int | None = None) -> bool:
        self._data[key] = value
        if ex is not None:
            self._ttls[key] = int(ex)
        else:
            self._ttls.pop(key, None)
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
# Helpers / fixtures
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
    """Pin admin key for every test in this module."""
    with patch.object(settings, "admin_api_key", _ADMIN_KEY):
        yield


@pytest.fixture()
def override_kill_switch(client: TestClient, kill_switch: KillSwitchService):
    """Inject a deterministic KillSwitchService into the FastAPI dep graph."""
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


def _session_factory(session: AsyncMock):
    @asynccontextmanager
    async def _cm():
        yield session

    return lambda: _cm()


def _stop_all_body(reason: str = "Critical incident — halt all scans now") -> dict:
    return {"reason": reason, "confirmation_phrase": "STOP ALL SCANS"}


def _resume_all_body(reason: str = "Incident resolved — resume normal ops") -> dict:
    return {"reason": reason, "confirmation_phrase": "RESUME ALL SCANS"}


def _make_stop_session(*, cancelled: int = 5, tenants: int = 3) -> AsyncMock:
    """Mock async session for the cross-tenant cancel + audit pipeline."""
    count_row = MagicMock()
    count_row.one.return_value = (cancelled, tenants)
    update_result = MagicMock()
    session = AsyncMock()
    if cancelled == 0:
        session.execute = AsyncMock(side_effect=[count_row])
    else:
        session.execute = AsyncMock(side_effect=[count_row, update_result])
    session.add = MagicMock()
    session.commit = AsyncMock()
    return session


def _make_resume_session() -> AsyncMock:
    """Mock async session that only persists the resume_all audit row."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    return session


# ---------------------------------------------------------------------------
# stop_all — RBAC + validation + happy path
# ---------------------------------------------------------------------------


class TestEmergencyStopAllRbac:
    def test_stop_all_401_without_admin_key(self, client: TestClient) -> None:
        r = client.post(STOP_ALL, json=_stop_all_body())
        assert r.status_code == 401

    def test_stop_all_403_for_operator(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        r = client.post(STOP_ALL, headers=_HEADERS_OPERATOR, json=_stop_all_body())
        assert r.status_code == 403
        assert r.json()["detail"] == "forbidden"

    def test_stop_all_403_for_admin(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        r = client.post(STOP_ALL, headers=_HEADERS_ADMIN, json=_stop_all_body())
        assert r.status_code == 403
        assert r.json()["detail"] == "forbidden"


class TestEmergencyStopAllValidation:
    def test_stop_all_422_when_reason_too_short(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        r = client.post(
            STOP_ALL,
            headers=_HEADERS_BASE,
            json={"reason": "short", "confirmation_phrase": "STOP ALL SCANS"},
        )
        assert r.status_code == 422

    def test_stop_all_422_when_confirmation_phrase_wrong(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        r = client.post(
            STOP_ALL,
            headers=_HEADERS_BASE,
            json={
                "reason": "Critical incident — halt scans",
                "confirmation_phrase": "stop all scans",  # wrong case
            },
        )
        assert r.status_code == 422

    def test_stop_all_422_when_extra_field_present(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        r = client.post(
            STOP_ALL,
            headers=_HEADERS_BASE,
            json={**_stop_all_body(), "force": True},
        )
        assert r.status_code == 422


class TestEmergencyStopAllHappyPath:
    def test_stop_all_202_persists_redis_flag_and_cancels_scans(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
        fake_redis: _FakeRedis,
    ) -> None:
        session = _make_stop_session(cancelled=7, tenants=4)
        with patch(
            "src.api.routers.admin_emergency.async_session_factory",
            _session_factory(session),
        ):
            r = client.post(STOP_ALL, headers=_HEADERS_BASE, json=_stop_all_body())

        assert r.status_code == 202
        body = r.json()
        assert body["status"] == "stopped"
        assert body["cancelled_count"] == 7
        assert body["tenants_affected"] == 4
        assert body["skipped_terminal_count"] == 0
        assert len(body["audit_id"]) == 36
        assert "argus:emergency:global" in fake_redis._data
        session.commit.assert_awaited()
        session.add.assert_called_once()

    def test_stop_all_202_with_zero_active_scans_still_persists_flag(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
        fake_redis: _FakeRedis,
    ) -> None:
        session = _make_stop_session(cancelled=0, tenants=0)
        with patch(
            "src.api.routers.admin_emergency.async_session_factory",
            _session_factory(session),
        ):
            r = client.post(STOP_ALL, headers=_HEADERS_BASE, json=_stop_all_body())

        assert r.status_code == 202
        body = r.json()
        assert body["cancelled_count"] == 0
        assert body["tenants_affected"] == 0
        assert "argus:emergency:global" in fake_redis._data


class TestEmergencyStopAllConflict:
    def test_stop_all_409_when_emergency_already_active(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
    ) -> None:
        override_kill_switch.set_global(
            reason="Pre-existing incident in flight",
            operator_subject="incumbent@argus.example",
        )
        session = _make_stop_session()
        with patch(
            "src.api.routers.admin_emergency.async_session_factory",
            _session_factory(session),
        ):
            r = client.post(STOP_ALL, headers=_HEADERS_BASE, json=_stop_all_body())
        assert r.status_code == 409
        assert r.json()["detail"] == "emergency_already_active"
        session.execute.assert_not_called()

    def test_stop_all_503_when_redis_unavailable(
        self,
        client: TestClient,
        override_kill_switch_offline: KillSwitchService,
    ) -> None:
        session = _make_stop_session()
        with patch(
            "src.api.routers.admin_emergency.async_session_factory",
            _session_factory(session),
        ):
            r = client.post(STOP_ALL, headers=_HEADERS_BASE, json=_stop_all_body())
        assert r.status_code == 503
        assert r.json()["detail"] == "emergency_store_unavailable"
        session.execute.assert_not_called()


# ---------------------------------------------------------------------------
# resume_all — RBAC + happy path + idempotency
# ---------------------------------------------------------------------------


class TestEmergencyResumeAll:
    def test_resume_all_403_for_operator(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        r = client.post(RESUME_ALL, headers=_HEADERS_OPERATOR, json=_resume_all_body())
        assert r.status_code == 403

    def test_resume_all_200_clears_active_global_flag(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
        fake_redis: _FakeRedis,
    ) -> None:
        override_kill_switch.set_global(
            reason="initial halt for incident",
            operator_subject="incumbent@argus.example",
        )
        assert "argus:emergency:global" in fake_redis._data
        session = _make_resume_session()
        with patch(
            "src.api.routers.admin_emergency.async_session_factory",
            _session_factory(session),
        ):
            r = client.post(RESUME_ALL, headers=_HEADERS_BASE, json=_resume_all_body())
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "resumed"
        assert "argus:emergency:global" not in fake_redis._data
        session.commit.assert_awaited()

    def test_resume_all_409_when_no_global_flag_set(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
    ) -> None:
        r = client.post(RESUME_ALL, headers=_HEADERS_BASE, json=_resume_all_body())
        assert r.status_code == 409
        assert r.json()["detail"] == "emergency_not_active"

    def test_resume_all_422_wrong_phrase(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
    ) -> None:
        r = client.post(
            RESUME_ALL,
            headers=_HEADERS_BASE,
            json={
                "reason": "Resuming after fake incident",
                "confirmation_phrase": "RESUME NOW",
            },
        )
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# status — RBAC + payload shape
# ---------------------------------------------------------------------------


class TestEmergencyStatus:
    def test_status_200_global_inactive(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        r = client.get(STATUS, headers=_HEADERS_BASE)
        assert r.status_code == 200
        body = r.json()
        assert body["global_state"]["active"] is False
        assert body["tenant_throttles"] == []

    def test_status_200_reports_global_active(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
    ) -> None:
        override_kill_switch.set_global(
            reason="Live incident in flight",
            operator_subject="commander@argus.example",
        )
        r = client.get(STATUS, headers=_HEADERS_BASE)
        assert r.status_code == 200
        body = r.json()
        assert body["global_state"]["active"] is True
        assert body["global_state"]["reason"] == "Live incident in flight"

    def test_status_200_admin_with_own_tenant_filter(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
    ) -> None:
        tenant_id = str(uuid.uuid4())
        override_kill_switch.set_tenant_throttle(
            tenant_id,
            duration_seconds=900,
            reason="targeted tenant throttle",
            operator_subject="admin@argus.example",
        )
        admin_headers = {**_HEADERS_ADMIN, "X-Admin-Tenant": tenant_id}
        r = client.get(STATUS, headers=admin_headers, params={"tenant_id": tenant_id})
        assert r.status_code == 200
        body = r.json()
        assert len(body["tenant_throttles"]) == 1
        assert body["tenant_throttles"][0]["tenant_id"] == tenant_id

    def test_status_403_admin_without_tenant_filter(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        r = client.get(
            STATUS,
            headers={**_HEADERS_ADMIN, "X-Admin-Tenant": str(uuid.uuid4())},
        )
        assert r.status_code == 403

    def test_status_403_admin_tenant_mismatch(
        self, client: TestClient, override_kill_switch: KillSwitchService
    ) -> None:
        a, b = str(uuid.uuid4()), str(uuid.uuid4())
        r = client.get(
            STATUS,
            headers={**_HEADERS_ADMIN, "X-Admin-Tenant": a},
            params={"tenant_id": b},
        )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# audit-trail — RBAC + projection
# ---------------------------------------------------------------------------


class TestEmergencyAuditTrail:
    def _make_audit_session(
        self, *, rows_actions: list[str], reason: str | None = "test reason"
    ) -> AsyncMock:
        rows = []
        now = datetime.now(tz=timezone.utc)
        for i, action in enumerate(rows_actions):
            row = MagicMock()
            row.id = str(uuid.uuid4())
            row.action = action
            row.tenant_id = str(uuid.uuid4())
            row.details = {
                "reason": reason,
                "operator_user_id_hash": "deadbeef" * 8,
            }
            row.created_at = now - timedelta(minutes=i)
            rows.append(row)
        result = MagicMock()
        scalar = MagicMock()
        scalar.all.return_value = rows
        result.scalars.return_value = scalar
        session = AsyncMock()
        session.execute = AsyncMock(return_value=result)
        return session

    def test_audit_trail_200_super_admin_no_filter(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
    ) -> None:
        session = self._make_audit_session(
            rows_actions=[EVENT_STOP_ALL, EVENT_RESUME_ALL]
        )
        with patch(
            "src.api.routers.admin_emergency.async_session_factory",
            _session_factory(session),
        ):
            r = client.get(AUDIT_TRAIL, headers=_HEADERS_BASE)
        assert r.status_code == 200
        body = r.json()
        assert len(body["items"]) == 2
        assert body["items"][0]["event_type"] == EVENT_STOP_ALL

    def test_audit_trail_pagination_has_more(
        self,
        client: TestClient,
        override_kill_switch: KillSwitchService,
    ) -> None:
        session = self._make_audit_session(rows_actions=[EVENT_STOP_ALL] * 6)
        with patch(
            "src.api.routers.admin_emergency.async_session_factory",
            _session_factory(session),
        ):
            r = client.get(AUDIT_TRAIL, headers=_HEADERS_BASE, params={"limit": 5})
        assert r.status_code == 200
        body = r.json()
        assert body["has_more"] is True
        assert len(body["items"]) == 5
