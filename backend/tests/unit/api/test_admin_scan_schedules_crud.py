"""Admin scan_schedules CRUD + run-now (T33, ARG-056).

Covers RBAC across operator/admin/super-admin, validation of cron + URL
inputs, unique-name conflicts, run-now maintenance-window guard / bypass,
kill-switch interaction, audit emission, and RedBeat sync invocations.

Mocking strategy
----------------

* Database is mocked with an ``AsyncMock`` session and an
  ``asynccontextmanager`` factory that the router's
  ``async_session_factory`` symbol is patched to.
* RedBeat sync helpers (``_sync_redbeat_safe`` / ``_remove_redbeat_safe``)
  and the Celery dispatch (``_dispatch_run_now``) are patched directly
  via :func:`unittest.mock.patch` so we never touch a live broker.
* ``KillSwitchService`` is replaced by a stub at the
  ``get_kill_switch_service`` import inside ``_ensure_kill_switch_clear``.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from src.api.routers.admin_schedules import (
    EVENT_SCHEDULE_CREATED,
    EVENT_SCHEDULE_DELETED,
    EVENT_SCHEDULE_RUN_NOW,
    EVENT_SCHEDULE_UPDATED,
)
from src.core.config import settings

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LIST_PATH = "/api/v1/admin/scan-schedules"
ITEM_PATH = "/api/v1/admin/scan-schedules/{schedule_id}"
RUN_NOW_PATH = "/api/v1/admin/scan-schedules/{schedule_id}/run-now"

_ADMIN_KEY = "secret-admin-key-schedules"
_TENANT_A = "11111111-1111-4111-8111-111111111111"
_TENANT_B = "22222222-2222-4222-8222-222222222222"
_SCHEDULE_ID = "33333333-3333-4333-8333-333333333333"

_HEADERS_SUPER = {
    "X-Admin-Key": _ADMIN_KEY,
    "X-Admin-Role": "super-admin",
    "X-Operator-Subject": "soc-team@argus.example",
}
_HEADERS_OPERATOR = {**_HEADERS_SUPER, "X-Admin-Role": "operator"}
_HEADERS_ADMIN_A = {
    **_HEADERS_SUPER,
    "X-Admin-Role": "admin",
    "X-Admin-Tenant": _TENANT_A,
}
_HEADERS_ADMIN_B = {
    **_HEADERS_SUPER,
    "X-Admin-Role": "admin",
    "X-Admin-Tenant": _TENANT_B,
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _admin_api_key():
    with patch.object(settings, "admin_api_key", _ADMIN_KEY):
        yield


def _session_factory(session: AsyncMock):
    @asynccontextmanager
    async def _cm():
        yield session

    return lambda: _cm()


# ---------------------------------------------------------------------------
# Mock-session builders
# ---------------------------------------------------------------------------


def _scalar_result(value: Any) -> MagicMock:
    """A SQLAlchemy result whose ``scalar_one`` / ``scalar_one_or_none`` returns ``value``."""
    res = MagicMock()
    res.scalar_one.return_value = value
    res.scalar_one_or_none.return_value = value
    return res


def _scalars_list_result(rows: list[Any]) -> MagicMock:
    """Result whose ``.scalars().all()`` returns ``rows``."""
    res = MagicMock()
    scalars = MagicMock()
    scalars.all.return_value = rows
    res.scalars.return_value = scalars
    return res


def _make_create_session(
    *,
    tenant_exists: bool = True,
    integrity_error: bool = False,
) -> AsyncMock:
    """Mock for POST /scan-schedules: tenant existence check then add+flush.

    ``session.refresh`` is patched so it backfills ``created_at`` /
    ``updated_at`` on the added row, simulating PostgreSQL's
    ``func.now()`` server-side defaults that the unit DB layer cannot
    reproduce.
    """
    from sqlalchemy.exc import IntegrityError

    tenant_count = _scalar_result(1 if tenant_exists else 0)
    added: list[Any] = []

    def _record_add(row: Any) -> None:
        added.append(row)

    async def _refresh(row: Any) -> None:
        now = datetime(2026, 4, 22, 12, 0, tzinfo=timezone.utc)
        if getattr(row, "created_at", None) is None:
            row.created_at = now
        if getattr(row, "updated_at", None) is None:
            row.updated_at = now

    session = AsyncMock()
    session.execute = AsyncMock(return_value=tenant_count)
    session.add = MagicMock(side_effect=_record_add)
    if integrity_error:
        session.flush = AsyncMock(
            side_effect=IntegrityError("stmt", {}, Exception("conflict"))
        )
    else:
        session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.refresh = AsyncMock(side_effect=_refresh)
    session._added_rows = added  # exposed for assertions
    return session


def _build_schedule_row(
    *,
    schedule_id: str = _SCHEDULE_ID,
    tenant_id: str = _TENANT_A,
    name: str = "nightly-prod-scan",
    cron_expression: str = "0 2 * * *",
    target_url: str = "https://example.com/login",
    scan_mode: str = "standard",
    enabled: bool = True,
    maintenance_window_cron: str | None = None,
    last_run_at: datetime | None = None,
    next_run_at: datetime | None = None,
) -> MagicMock:
    """Stand-in for a ``ScanSchedule`` ORM row."""
    row = MagicMock()
    row.id = schedule_id
    row.tenant_id = tenant_id
    row.name = name
    row.cron_expression = cron_expression
    row.target_url = target_url
    row.scan_mode = scan_mode
    row.enabled = enabled
    row.maintenance_window_cron = maintenance_window_cron
    row.last_run_at = last_run_at
    row.next_run_at = next_run_at
    row.created_at = datetime(2026, 4, 22, 12, 0, tzinfo=timezone.utc)
    row.updated_at = datetime(2026, 4, 22, 12, 0, tzinfo=timezone.utc)
    return row


def _make_load_session(row: Any | None) -> AsyncMock:
    """Mock for endpoints that load a single schedule row."""
    session = AsyncMock()
    session.execute = AsyncMock(return_value=_scalar_result(row))
    session.add = MagicMock()
    session.delete = AsyncMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.refresh = AsyncMock()
    return session


def _make_list_session(*, total: int, rows: list[Any]) -> AsyncMock:
    """Mock for GET /scan-schedules: count then paged list."""
    session = AsyncMock()
    session.execute = AsyncMock(
        side_effect=[_scalar_result(total), _scalars_list_result(rows)]
    )
    return session


# ---------------------------------------------------------------------------
# Body helpers
# ---------------------------------------------------------------------------


def _create_body(**overrides: Any) -> dict:
    base: dict = {
        "tenant_id": _TENANT_A,
        "name": "nightly-prod-scan",
        "cron_expression": "0 2 * * *",
        "target_url": "https://example.com/login",
        "scan_mode": "standard",
        "enabled": True,
        "maintenance_window_cron": None,
    }
    base.update(overrides)
    return base


def _patch_session(session: AsyncMock):
    return patch(
        "src.api.routers.admin_schedules.async_session_factory",
        _session_factory(session),
    )


def _patch_redbeat_sync():
    return patch("src.api.routers.admin_schedules._sync_redbeat_safe")


def _patch_redbeat_remove():
    return patch("src.api.routers.admin_schedules._remove_redbeat_safe")


def _patch_dispatch():
    fake_async_result = MagicMock()
    fake_async_result.id = "fake-task-id-0001"
    return patch(
        "src.api.routers.admin_schedules._dispatch_run_now",
        return_value=fake_async_result.id,
    )


def _patch_kill_switch_clear():
    """Patch ``_ensure_kill_switch_clear`` to a no-op (not blocked)."""
    return patch(
        "src.api.routers.admin_schedules._ensure_kill_switch_clear",
        return_value=None,
    )


# ===========================================================================
# RBAC
# ===========================================================================


class TestScanScheduleRbac:
    def test_create_401_without_admin_key(self, client: TestClient) -> None:
        r = client.post(LIST_PATH, json=_create_body())
        assert r.status_code == 401

    def test_create_403_for_operator(self, client: TestClient) -> None:
        r = client.post(LIST_PATH, headers=_HEADERS_OPERATOR, json=_create_body())
        assert r.status_code == 403
        assert r.json()["detail"] == "forbidden"

    def test_create_403_admin_cross_tenant(self, client: TestClient) -> None:
        body = _create_body(tenant_id=_TENANT_B)
        r = client.post(LIST_PATH, headers=_HEADERS_ADMIN_A, json=body)
        assert r.status_code == 403
        assert r.json()["detail"] == "tenant mismatch"

    def test_create_403_admin_without_session_tenant_header(
        self, client: TestClient
    ) -> None:
        headers = {**_HEADERS_SUPER, "X-Admin-Role": "admin"}
        r = client.post(LIST_PATH, headers=headers, json=_create_body())
        assert r.status_code == 403

    def test_list_403_operator_without_tenant(self, client: TestClient) -> None:
        # operator must scope to a tenant; missing X-Admin-Tenant + missing
        # ``tenant_id`` query → 403
        r = client.get(LIST_PATH, headers=_HEADERS_OPERATOR)
        assert r.status_code == 403


# ===========================================================================
# Validation
# ===========================================================================


class TestScanScheduleValidation:
    def test_create_422_when_name_blank(self, client: TestClient) -> None:
        r = client.post(LIST_PATH, headers=_HEADERS_SUPER, json=_create_body(name=""))
        assert r.status_code == 422

    def test_create_422_when_target_url_invalid(self, client: TestClient) -> None:
        # Leading hyphen violates the project TARGET_PATTERN (first char must
        # be alnum). The tenant existence DB call must NOT be reached because
        # 422 fires before request body dispatch.
        r = client.post(
            LIST_PATH,
            headers=_HEADERS_SUPER,
            json=_create_body(target_url="-badscheme://nope"),
        )
        assert r.status_code == 422

    def test_create_422_when_extra_field_present(self, client: TestClient) -> None:
        body = {**_create_body(), "force": True}
        r = client.post(LIST_PATH, headers=_HEADERS_SUPER, json=body)
        assert r.status_code == 422

    def test_create_400_when_cron_invalid(self, client: TestClient) -> None:
        r = client.post(
            LIST_PATH,
            headers=_HEADERS_SUPER,
            json=_create_body(cron_expression="not-a-cron"),
        )
        assert r.status_code == 400
        assert r.json()["detail"] == "invalid cron expression"

    def test_create_400_when_cron_too_frequent(self, client: TestClient) -> None:
        # */1 violates the 5-minute DOS-guard floor in validate_cron.
        r = client.post(
            LIST_PATH,
            headers=_HEADERS_SUPER,
            json=_create_body(cron_expression="* * * * *"),
        )
        assert r.status_code == 400

    def test_create_400_when_maintenance_cron_invalid(self, client: TestClient) -> None:
        r = client.post(
            LIST_PATH,
            headers=_HEADERS_SUPER,
            json=_create_body(maintenance_window_cron="bogus"),
        )
        assert r.status_code == 400
        assert r.json()["detail"] == "invalid maintenance window cron"

    def test_create_422_when_tenant_id_not_uuid(self, client: TestClient) -> None:
        r = client.post(
            LIST_PATH,
            headers=_HEADERS_SUPER,
            json=_create_body(tenant_id="not-a-uuid"),
        )
        assert r.status_code == 422


# ===========================================================================
# CREATE happy path / error handling
# ===========================================================================


class TestScanScheduleCreate:
    def test_create_201_persists_and_emits_audit(self, client: TestClient) -> None:
        session = _make_create_session()
        with _patch_session(session), _patch_redbeat_sync() as sync_mock:
            r = client.post(LIST_PATH, headers=_HEADERS_SUPER, json=_create_body())

        assert r.status_code == 201
        body = r.json()
        assert body["tenant_id"] == _TENANT_A
        assert body["name"] == "nightly-prod-scan"
        assert body["scan_mode"] == "standard"
        assert body["enabled"] is True
        # Two ``add`` calls: schedule row + audit row.
        assert session.add.call_count == 2
        session.commit.assert_awaited()
        sync_mock.assert_called_once()

    def test_create_201_admin_own_tenant(self, client: TestClient) -> None:
        session = _make_create_session()
        with _patch_session(session), _patch_redbeat_sync():
            r = client.post(LIST_PATH, headers=_HEADERS_ADMIN_A, json=_create_body())
        assert r.status_code == 201

    def test_create_404_when_tenant_missing(self, client: TestClient) -> None:
        session = _make_create_session(tenant_exists=False)
        with _patch_session(session), _patch_redbeat_sync():
            r = client.post(LIST_PATH, headers=_HEADERS_SUPER, json=_create_body())
        assert r.status_code == 404
        assert r.json()["detail"] == "tenant not found"

    def test_create_409_on_duplicate_name(self, client: TestClient) -> None:
        session = _make_create_session(integrity_error=True)
        with _patch_session(session), _patch_redbeat_sync():
            r = client.post(LIST_PATH, headers=_HEADERS_SUPER, json=_create_body())
        assert r.status_code == 409
        assert r.json()["detail"] == "schedule name already exists for tenant"
        session.rollback.assert_awaited()

    def test_create_audit_action_is_canonical(self, client: TestClient) -> None:
        """The emitted AuditLog row carries ``scan_schedule.created``."""
        session = _make_create_session()
        captured_actions: list[str] = []

        def _capture_add(obj: Any) -> None:
            action = getattr(obj, "action", None)
            if action is not None:
                captured_actions.append(action)

        session.add = MagicMock(side_effect=_capture_add)
        with _patch_session(session), _patch_redbeat_sync():
            r = client.post(LIST_PATH, headers=_HEADERS_SUPER, json=_create_body())
        assert r.status_code == 201
        assert EVENT_SCHEDULE_CREATED in captured_actions


# ===========================================================================
# LIST
# ===========================================================================


class TestScanScheduleList:
    def test_list_200_super_admin_cross_tenant(self, client: TestClient) -> None:
        rows = [_build_schedule_row(name=f"schedule-{i}") for i in range(3)]
        session = _make_list_session(total=3, rows=rows)
        with _patch_session(session):
            r = client.get(LIST_PATH, headers=_HEADERS_SUPER)
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 3
        assert body["limit"] == 50
        assert body["offset"] == 0
        assert len(body["items"]) == 3

    def test_list_200_admin_own_tenant(self, client: TestClient) -> None:
        rows = [_build_schedule_row()]
        session = _make_list_session(total=1, rows=rows)
        with _patch_session(session):
            r = client.get(
                LIST_PATH,
                headers=_HEADERS_ADMIN_A,
                params={"tenant_id": _TENANT_A},
            )
        assert r.status_code == 200
        assert r.json()["total"] == 1

    def test_list_403_admin_cross_tenant(self, client: TestClient) -> None:
        r = client.get(
            LIST_PATH,
            headers=_HEADERS_ADMIN_A,
            params={"tenant_id": _TENANT_B},
        )
        assert r.status_code == 403
        assert r.json()["detail"] == "tenant mismatch"

    def test_list_filters_enabled(self, client: TestClient) -> None:
        rows = [_build_schedule_row(enabled=True)]
        session = _make_list_session(total=1, rows=rows)
        with _patch_session(session):
            r = client.get(
                LIST_PATH,
                headers=_HEADERS_SUPER,
                params={"enabled": "true"},
            )
        assert r.status_code == 200
        assert all(item["enabled"] is True for item in r.json()["items"])


# ===========================================================================
# UPDATE (PATCH)
# ===========================================================================


class TestScanScheduleUpdate:
    def test_update_200_partial_change(self, client: TestClient) -> None:
        row = _build_schedule_row()
        session = _make_load_session(row)
        with _patch_session(session), _patch_redbeat_sync() as sync_mock:
            r = client.patch(
                ITEM_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_SUPER,
                json={"enabled": False},
            )
        assert r.status_code == 200
        assert r.json()["enabled"] is False
        sync_mock.assert_called_once()

    def test_update_200_changes_cron_recomputes_next_run(
        self, client: TestClient
    ) -> None:
        row = _build_schedule_row()
        session = _make_load_session(row)
        with _patch_session(session), _patch_redbeat_sync():
            r = client.patch(
                ITEM_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_SUPER,
                json={"cron_expression": "*/30 * * * *"},
            )
        assert r.status_code == 200
        # next_run_at must be present in the response (now-rooted)
        assert r.json()["next_run_at"] is not None

    def test_update_404_when_missing(self, client: TestClient) -> None:
        session = _make_load_session(None)
        with _patch_session(session), _patch_redbeat_sync():
            r = client.patch(
                ITEM_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_SUPER,
                json={"enabled": False},
            )
        assert r.status_code == 404
        assert r.json()["detail"] == "schedule not found"

    def test_update_403_admin_cross_tenant(self, client: TestClient) -> None:
        row = _build_schedule_row(tenant_id=_TENANT_B)
        session = _make_load_session(row)
        with _patch_session(session), _patch_redbeat_sync():
            r = client.patch(
                ITEM_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_ADMIN_A,
                json={"enabled": False},
            )
        assert r.status_code == 403

    def test_update_400_when_new_cron_invalid(self, client: TestClient) -> None:
        # No DB hit needed — validator runs first.
        r = client.patch(
            ITEM_PATH.format(schedule_id=_SCHEDULE_ID),
            headers=_HEADERS_SUPER,
            json={"cron_expression": "garbage"},
        )
        assert r.status_code == 400

    def test_update_409_when_name_collision(self, client: TestClient) -> None:
        from sqlalchemy.exc import IntegrityError

        row = _build_schedule_row()
        session = _make_load_session(row)
        session.flush = AsyncMock(
            side_effect=IntegrityError("stmt", {}, Exception("conflict"))
        )
        with _patch_session(session), _patch_redbeat_sync():
            r = client.patch(
                ITEM_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_SUPER,
                json={"name": "collides"},
            )
        assert r.status_code == 409


# ===========================================================================
# DELETE
# ===========================================================================


class TestScanScheduleDelete:
    def test_delete_204_removes_redbeat(self, client: TestClient) -> None:
        row = _build_schedule_row()
        session = _make_load_session(row)
        with _patch_session(session), _patch_redbeat_remove() as rm_mock:
            r = client.delete(
                ITEM_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_SUPER,
            )
        assert r.status_code == 204
        rm_mock.assert_called_once_with(_SCHEDULE_ID)
        session.delete.assert_awaited()

    def test_delete_404_when_missing(self, client: TestClient) -> None:
        session = _make_load_session(None)
        with _patch_session(session), _patch_redbeat_remove():
            r = client.delete(
                ITEM_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_SUPER,
            )
        assert r.status_code == 404

    def test_delete_403_admin_cross_tenant(self, client: TestClient) -> None:
        row = _build_schedule_row(tenant_id=_TENANT_B)
        session = _make_load_session(row)
        with _patch_session(session), _patch_redbeat_remove():
            r = client.delete(
                ITEM_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_ADMIN_A,
            )
        assert r.status_code == 403

    def test_delete_audit_action_is_canonical(self, client: TestClient) -> None:
        row = _build_schedule_row()
        session = _make_load_session(row)
        captured_actions: list[str] = []

        def _capture(obj: Any) -> None:
            action = getattr(obj, "action", None)
            if action is not None:
                captured_actions.append(action)

        session.add = MagicMock(side_effect=_capture)
        with _patch_session(session), _patch_redbeat_remove():
            r = client.delete(
                ITEM_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_SUPER,
            )
        assert r.status_code == 204
        assert EVENT_SCHEDULE_DELETED in captured_actions


# ===========================================================================
# RUN-NOW
# ===========================================================================


class TestScanScheduleRunNow:
    def test_run_now_202_dispatches_task(self, client: TestClient) -> None:
        row = _build_schedule_row()
        session = _make_load_session(row)
        with (
            _patch_session(session),
            _patch_kill_switch_clear(),
            _patch_dispatch() as dispatch_mock,
        ):
            r = client.post(
                RUN_NOW_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_SUPER,
                json={
                    "bypass_maintenance_window": False,
                    "reason": "Operator manual override for incident triage",
                },
            )
        assert r.status_code == 202
        body = r.json()
        assert body["enqueued_task_id"] == "fake-task-id-0001"
        assert body["bypassed_maintenance_window"] is False
        dispatch_mock.assert_called_once()

    def test_run_now_403_for_operator(self, client: TestClient) -> None:
        r = client.post(
            RUN_NOW_PATH.format(schedule_id=_SCHEDULE_ID),
            headers=_HEADERS_OPERATOR,
            json={
                "bypass_maintenance_window": False,
                "reason": "Operator triage attempt",
            },
        )
        assert r.status_code == 403

    def test_run_now_404_when_schedule_missing(self, client: TestClient) -> None:
        session = _make_load_session(None)
        with _patch_session(session), _patch_kill_switch_clear(), _patch_dispatch():
            r = client.post(
                RUN_NOW_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_SUPER,
                json={
                    "bypass_maintenance_window": False,
                    "reason": "Operator manual override for incident triage",
                },
            )
        assert r.status_code == 404

    def test_run_now_423_when_maintenance_window_active(
        self, client: TestClient
    ) -> None:
        # window cron that fires every hour AND the default duration is
        # 60min — guarantees ``is_in_maintenance_window`` returns True
        # for the current instant.
        row = _build_schedule_row(maintenance_window_cron="0 * * * *")
        session = _make_load_session(row)
        with _patch_session(session), _patch_kill_switch_clear(), _patch_dispatch():
            r = client.post(
                RUN_NOW_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_SUPER,
                json={
                    "bypass_maintenance_window": False,
                    "reason": "Operator manual override for incident triage",
                },
            )
        assert r.status_code == 423
        assert r.json()["detail"] == "maintenance window currently active"

    def test_run_now_202_with_bypass_skips_maintenance_check(
        self, client: TestClient
    ) -> None:
        row = _build_schedule_row(maintenance_window_cron="0 * * * *")
        session = _make_load_session(row)
        with (
            _patch_session(session),
            _patch_kill_switch_clear(),
            _patch_dispatch(),
        ):
            r = client.post(
                RUN_NOW_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_SUPER,
                json={
                    "bypass_maintenance_window": True,
                    "reason": "Critical fix — bypass maintenance window",
                },
            )
        assert r.status_code == 202
        assert r.json()["bypassed_maintenance_window"] is True

    def test_run_now_423_when_kill_switch_blocked(self, client: TestClient) -> None:
        from fastapi import HTTPException

        row = _build_schedule_row()
        session = _make_load_session(row)

        def _block(_tenant_id: str) -> None:
            raise HTTPException(
                status_code=423, detail="scans are currently blocked for tenant"
            )

        with (
            _patch_session(session),
            patch(
                "src.api.routers.admin_schedules._ensure_kill_switch_clear",
                side_effect=_block,
            ),
            _patch_dispatch(),
        ):
            r = client.post(
                RUN_NOW_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_SUPER,
                json={
                    "bypass_maintenance_window": False,
                    "reason": "Operator manual override for incident triage",
                },
            )
        assert r.status_code == 423
        assert r.json()["detail"] == "scans are currently blocked for tenant"

    def test_run_now_422_when_reason_too_short(self, client: TestClient) -> None:
        r = client.post(
            RUN_NOW_PATH.format(schedule_id=_SCHEDULE_ID),
            headers=_HEADERS_SUPER,
            json={"bypass_maintenance_window": False, "reason": "short"},
        )
        assert r.status_code == 422

    def test_run_now_audit_records_bypass_flag_and_reason(
        self, client: TestClient
    ) -> None:
        row = _build_schedule_row()
        session = _make_load_session(row)
        captured_actions: list[str] = []
        captured_details: list[dict] = []

        def _capture(obj: Any) -> None:
            action = getattr(obj, "action", None)
            if action is not None:
                captured_actions.append(action)
            details = getattr(obj, "details", None)
            if isinstance(details, dict):
                captured_details.append(details)

        session.add = MagicMock(side_effect=_capture)
        with _patch_session(session), _patch_kill_switch_clear(), _patch_dispatch():
            r = client.post(
                RUN_NOW_PATH.format(schedule_id=_SCHEDULE_ID),
                headers=_HEADERS_SUPER,
                json={
                    "bypass_maintenance_window": True,
                    "reason": "Critical fix — bypass maintenance window",
                },
            )
        assert r.status_code == 202
        assert EVENT_SCHEDULE_RUN_NOW in captured_actions
        assert any(d.get("bypass_maintenance_window") is True for d in captured_details)


# ===========================================================================
# Operator subject hashing — never persists raw subject
# ===========================================================================


class TestScanScheduleAuditAttribution:
    def test_create_audit_persists_only_hashed_operator(
        self, client: TestClient
    ) -> None:
        operator_subject = "named-operator@argus.example"
        session = _make_create_session()
        captured_details: list[dict] = []

        def _capture(obj: Any) -> None:
            details = getattr(obj, "details", None)
            if isinstance(details, dict):
                captured_details.append(details)

        session.add = MagicMock(side_effect=_capture)
        headers = {**_HEADERS_SUPER, "X-Operator-Subject": operator_subject}
        with _patch_session(session), _patch_redbeat_sync():
            r = client.post(LIST_PATH, headers=headers, json=_create_body())
        assert r.status_code == 201
        # Hash is opaque and the raw subject must never leak.
        for d in captured_details:
            assert operator_subject not in str(d), (
                "raw operator subject must never be persisted to audit details"
            )
            assert "operator_user_id_hash" in d


# ===========================================================================
# Parametrized RBAC fan-out
# ===========================================================================


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("post", LIST_PATH, _create_body()),
        ("patch", ITEM_PATH.format(schedule_id=_SCHEDULE_ID), {"enabled": False}),
        ("delete", ITEM_PATH.format(schedule_id=_SCHEDULE_ID), None),
        (
            "post",
            RUN_NOW_PATH.format(schedule_id=_SCHEDULE_ID),
            {
                "bypass_maintenance_window": False,
                "reason": "Operator manual override for incident triage",
            },
        ),
    ],
)
def test_mutating_endpoints_403_for_operator(
    client: TestClient, method: str, path: str, body: dict | None
) -> None:
    """Every mutation endpoint refuses an operator role with 403."""
    fn = getattr(client, method)
    if body is None:
        r = fn(path, headers=_HEADERS_OPERATOR)
    else:
        r = fn(path, headers=_HEADERS_OPERATOR, json=body)
    assert r.status_code == 403


# ===========================================================================
# Update audit action canonical name
# ===========================================================================


def test_update_audit_action_is_canonical(client: TestClient) -> None:
    row = _build_schedule_row()
    session = _make_load_session(row)
    captured_actions: list[str] = []

    def _capture(obj: Any) -> None:
        action = getattr(obj, "action", None)
        if action is not None:
            captured_actions.append(action)

    session.add = MagicMock(side_effect=_capture)
    with _patch_session(session), _patch_redbeat_sync():
        r = client.patch(
            ITEM_PATH.format(schedule_id=_SCHEDULE_ID),
            headers=_HEADERS_SUPER,
            json={"name": "renamed-schedule"},
        )
    assert r.status_code == 200
    assert EVENT_SCHEDULE_UPDATED in captured_actions


# Misc constants used in the test module — guard against import unused.
_ = uuid
