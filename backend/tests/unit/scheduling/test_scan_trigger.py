"""Unit tests for :mod:`src.scheduling.scan_trigger` (T33, ARG-056).

Exercises the Celery task that RedBeat fires for each scheduled scan.

Coverage:

* Pure helpers — :func:`_should_skip_for_maintenance_window` (None / valid /
  invalid cron) and :func:`_compute_next_run_at` (success + failure paths).
* Async task body — every gate of
  :func:`_run_scheduled_scan_async` (kill-switch blocked, kill-switch
  unavailable, schedule missing / disabled, in maintenance window, happy
  path) plus the dispatcher invocation.
* Celery wrapper — :func:`run_scheduled_scan` correctly forwards kwargs
  and returns the async result.

All Redis / DB / Celery boundaries are patched at the module-level seams
exposed by ``scan_trigger`` (``_build_kill_switch``,
``create_task_engine_and_session``, ``_load_schedule``, etc.) so the suite
runs entirely in-process without requiring a broker, Postgres, or Redis.
"""

from __future__ import annotations

from datetime import UTC, datetime, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.policy.kill_switch import (
    KillSwitchScope,
    KillSwitchUnavailableError,
    KillSwitchVerdict,
)
from src.scheduling import scan_trigger
from src.scheduling.cron_parser import CronValidationError
from src.scheduling.scan_trigger import (
    DEFAULT_MAINTENANCE_WINDOW_DURATION_MINUTES,
    EVENT_SKIPPED_EMERGENCY_STOP,
    EVENT_SKIPPED_MAINTENANCE_WINDOW,
    _compute_next_run_at,
    _run_scheduled_scan_async,
    _should_skip_for_maintenance_window,
    run_scheduled_scan,
)


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------


_SCHEDULE_ID = "00000000-0000-4000-8000-000000000001"
_TENANT_ID = "11111111-1111-4111-8111-111111111111"
_FIRED_AT = datetime(2026, 4, 22, 12, 0, 0, tzinfo=UTC)


def _build_schedule(
    *,
    schedule_id: str = _SCHEDULE_ID,
    tenant_id: str = _TENANT_ID,
    enabled: bool = True,
    cron_expression: str = "*/15 * * * *",
    target_url: str = "https://example.com/app",
    scan_mode: str = "standard",
    maintenance_window_cron: str | None = None,
) -> SimpleNamespace:
    """Lightweight stand-in for a :class:`ScanSchedule` ORM row.

    The Celery body only reads attributes — it never persists the row
    object back — so a ``SimpleNamespace`` is sufficient and keeps the
    test free of SQLAlchemy mapper instantiation cost.
    """
    return SimpleNamespace(
        id=schedule_id,
        tenant_id=tenant_id,
        enabled=enabled,
        cron_expression=cron_expression,
        target_url=target_url,
        scan_mode=scan_mode,
        maintenance_window_cron=maintenance_window_cron,
    )


class _AsyncSessionCM:
    """Minimal ``async with`` ↔ ``AsyncSession`` adapter.

    The Celery body uses ``async with session_factory() as session:`` and
    the test patches every helper that touches the session so we only
    need the protocol shape, not real DB behaviour.
    """

    def __init__(self, session: Any) -> None:
        self._session = session

    async def __aenter__(self) -> Any:
        return self._session

    async def __aexit__(self, *exc_info: Any) -> None:
        return None


def _build_session_factory() -> tuple[MagicMock, MagicMock, AsyncMock]:
    """Return ``(engine_mock, factory_mock, session_mock)``.

    ``engine.dispose`` is an :class:`AsyncMock` because the production
    code awaits it from the ``finally`` block. ``factory()`` returns the
    async-context manager wrapping ``session_mock`` so every patched
    helper sees the same instance.
    """
    session = AsyncMock()
    session.commit = AsyncMock()
    # T33 S2.1 — production calls ``session.add(audit_row)`` synchronously
    # (real ``AsyncSession.add`` is sync). Override the auto-spawned
    # AsyncMock so the test does not emit ``coroutine never awaited``.
    session.add = MagicMock()
    factory = MagicMock(return_value=_AsyncSessionCM(session))
    engine = MagicMock()
    engine.dispose = AsyncMock()
    return engine, factory, session


def _patch_kill_switch(verdict: KillSwitchVerdict | Exception) -> Any:
    """Patch :func:`_build_kill_switch` so ``is_blocked`` returns / raises.

    Pass an exception instance to simulate
    :class:`KillSwitchUnavailableError`; pass a verdict to simulate a
    healthy backend response.
    """
    ks = MagicMock()
    if isinstance(verdict, Exception):
        ks.is_blocked = MagicMock(side_effect=verdict)
    else:
        ks.is_blocked = MagicMock(return_value=verdict)
    return patch.object(scan_trigger, "_build_kill_switch", return_value=ks)


# ===========================================================================
# Pure decision helpers
# ===========================================================================


class TestShouldSkipForMaintenanceWindow:
    def test_returns_false_for_none_cron(self) -> None:
        assert (
            _should_skip_for_maintenance_window(window_cron=None, at=_FIRED_AT) is False
        )

    def test_returns_false_for_empty_string_cron(self) -> None:
        assert (
            _should_skip_for_maintenance_window(window_cron="", at=_FIRED_AT) is False
        )

    def test_delegates_to_is_in_maintenance_window_when_in_window(self) -> None:
        with patch.object(
            scan_trigger, "is_in_maintenance_window", return_value=True
        ) as window_mock:
            result = _should_skip_for_maintenance_window(
                window_cron="0 12 * * *", at=_FIRED_AT
            )
        assert result is True
        window_mock.assert_called_once_with(
            "0 12 * * *",
            at=_FIRED_AT,
            window_duration_minutes=DEFAULT_MAINTENANCE_WINDOW_DURATION_MINUTES,
        )

    def test_returns_false_when_outside_window(self) -> None:
        with patch.object(scan_trigger, "is_in_maintenance_window", return_value=False):
            assert (
                _should_skip_for_maintenance_window(
                    window_cron="0 3 * * *", at=_FIRED_AT
                )
                is False
            )

    def test_invalid_cron_logs_warning_and_returns_false(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Failing-open: a bad cron must NOT silently suppress every fire."""
        with patch.object(
            scan_trigger,
            "is_in_maintenance_window",
            side_effect=CronValidationError("bad"),
        ):
            with caplog.at_level("WARNING", logger=scan_trigger.logger.name):
                result = _should_skip_for_maintenance_window(
                    window_cron="not a cron", at=_FIRED_AT
                )
        assert result is False
        assert any(
            "scan_trigger.maintenance_window_invalid" in record.message
            for record in caplog.records
        )


class TestComputeNextRunAt:
    def test_returns_datetime_for_valid_cron(self) -> None:
        sentinel = datetime(2026, 4, 22, 12, 15, tzinfo=UTC)
        with patch.object(scan_trigger, "next_fire_time", return_value=sentinel) as ff:
            result = _compute_next_run_at("*/15 * * * *", after=_FIRED_AT)
        assert result is sentinel
        ff.assert_called_once_with("*/15 * * * *", after=_FIRED_AT)

    def test_returns_none_for_invalid_cron(self) -> None:
        with patch.object(
            scan_trigger,
            "next_fire_time",
            side_effect=CronValidationError("bad cron"),
        ):
            assert _compute_next_run_at("garbage", after=_FIRED_AT) is None


# ===========================================================================
# Async task body — gates
# ===========================================================================


class TestRunScheduledScanAsyncGates:
    @pytest.mark.asyncio
    async def test_kill_switch_blocked_skips_without_opening_session(self) -> None:
        verdict = KillSwitchVerdict(
            blocked=True, scope=KillSwitchScope.GLOBAL, reason="exercise"
        )
        with (
            _patch_kill_switch(verdict),
            patch.object(
                scan_trigger, "create_task_engine_and_session"
            ) as factory_mock,
            patch.object(scan_trigger, "_dispatch_scan_phase") as dispatch_mock,
        ):
            result = await _run_scheduled_scan_async(
                schedule_id=_SCHEDULE_ID,
                tenant_id=_TENANT_ID,
                fired_at=_FIRED_AT,
            )
        assert result == {
            "status": "skipped_kill_switch",
            "schedule_id": _SCHEDULE_ID,
        }
        factory_mock.assert_not_called()
        dispatch_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_kill_switch_unavailable_fails_closed(self) -> None:
        with (
            _patch_kill_switch(KillSwitchUnavailableError("redis down")),
            patch.object(
                scan_trigger, "create_task_engine_and_session"
            ) as factory_mock,
            patch.object(scan_trigger, "_dispatch_scan_phase") as dispatch_mock,
        ):
            result = await _run_scheduled_scan_async(
                schedule_id=_SCHEDULE_ID,
                tenant_id=_TENANT_ID,
                fired_at=_FIRED_AT,
            )
        assert result == {
            "status": "skipped_kill_switch_unavailable",
            "schedule_id": _SCHEDULE_ID,
        }
        factory_mock.assert_not_called()
        dispatch_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_when_schedule_missing(self) -> None:
        engine, factory, session = _build_session_factory()
        verdict = KillSwitchVerdict(blocked=False)

        with (
            _patch_kill_switch(verdict),
            patch.object(
                scan_trigger,
                "create_task_engine_and_session",
                return_value=(engine, factory),
            ),
            patch.object(scan_trigger, "set_session_tenant", new=AsyncMock()),
            patch.object(
                scan_trigger, "_load_schedule", new=AsyncMock(return_value=None)
            ),
            patch.object(scan_trigger, "_dispatch_scan_phase") as dispatch_mock,
        ):
            result = await _run_scheduled_scan_async(
                schedule_id=_SCHEDULE_ID,
                tenant_id=_TENANT_ID,
                fired_at=_FIRED_AT,
            )

        assert result == {"status": "skipped_missing", "schedule_id": _SCHEDULE_ID}
        dispatch_mock.assert_not_called()
        engine.dispose.assert_awaited_once()
        session.commit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_when_schedule_disabled(self) -> None:
        engine, factory, session = _build_session_factory()
        schedule = _build_schedule(enabled=False)

        with (
            _patch_kill_switch(KillSwitchVerdict(blocked=False)),
            patch.object(
                scan_trigger,
                "create_task_engine_and_session",
                return_value=(engine, factory),
            ),
            patch.object(scan_trigger, "set_session_tenant", new=AsyncMock()),
            patch.object(
                scan_trigger,
                "_load_schedule",
                new=AsyncMock(return_value=schedule),
            ),
            patch.object(scan_trigger, "_dispatch_scan_phase") as dispatch_mock,
        ):
            result = await _run_scheduled_scan_async(
                schedule_id=_SCHEDULE_ID,
                tenant_id=_TENANT_ID,
                fired_at=_FIRED_AT,
            )

        assert result == {"status": "skipped_disabled", "schedule_id": _SCHEDULE_ID}
        dispatch_mock.assert_not_called()
        session.commit.assert_not_awaited()
        engine.dispose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_skips_when_inside_maintenance_window(self) -> None:
        engine, factory, session = _build_session_factory()
        schedule = _build_schedule(maintenance_window_cron="0 12 * * *")

        with (
            _patch_kill_switch(KillSwitchVerdict(blocked=False)),
            patch.object(
                scan_trigger,
                "create_task_engine_and_session",
                return_value=(engine, factory),
            ),
            patch.object(scan_trigger, "set_session_tenant", new=AsyncMock()),
            patch.object(
                scan_trigger,
                "_load_schedule",
                new=AsyncMock(return_value=schedule),
            ),
            patch.object(scan_trigger, "is_in_maintenance_window", return_value=True),
            patch.object(scan_trigger, "_dispatch_scan_phase") as dispatch_mock,
        ):
            result = await _run_scheduled_scan_async(
                schedule_id=_SCHEDULE_ID,
                tenant_id=_TENANT_ID,
                fired_at=_FIRED_AT,
            )

        assert result == {
            "status": "skipped_maintenance_window",
            "schedule_id": _SCHEDULE_ID,
        }
        dispatch_mock.assert_not_called()
        # T33 S2.1 — the maintenance-window skip path now writes a
        # ``scan_schedule.skipped_maintenance_window`` AuditLog row in the
        # already-open session and commits it. ``_dispatch_scan_phase`` is
        # still NOT invoked (the early-return is what we care about); the
        # commit is observed in TestSkipPathAuditEmission with row
        # introspection.
        assert session.commit.await_count == 1


# ===========================================================================
# Async task body — happy path
# ===========================================================================


class TestRunScheduledScanAsyncHappyPath:
    @pytest.mark.asyncio
    async def test_dispatches_persists_and_updates_timestamps(self) -> None:
        engine, factory, session = _build_session_factory()
        schedule = _build_schedule(
            target_url="https://t.example.com/api",
            scan_mode="deep",
        )
        next_run = datetime(2026, 4, 22, 12, 15, tzinfo=UTC)

        with (
            _patch_kill_switch(KillSwitchVerdict(blocked=False)),
            patch.object(
                scan_trigger,
                "create_task_engine_and_session",
                return_value=(engine, factory),
            ),
            patch.object(
                scan_trigger, "set_session_tenant", new=AsyncMock()
            ) as tenant_mock,
            patch.object(
                scan_trigger,
                "_load_schedule",
                new=AsyncMock(return_value=schedule),
            ),
            patch.object(
                scan_trigger, "_ensure_tenant", new=AsyncMock()
            ) as ensure_tenant_mock,
            patch.object(
                scan_trigger,
                "_persist_scheduled_scan",
                new=AsyncMock(return_value="scan-uuid-123"),
            ) as persist_mock,
            patch.object(
                scan_trigger, "_compute_next_run_at", return_value=next_run
            ) as compute_mock,
            patch.object(
                scan_trigger,
                "_update_run_timestamps",
                new=AsyncMock(),
            ) as update_mock,
            patch.object(scan_trigger, "_dispatch_scan_phase") as dispatch_mock,
        ):
            result = await _run_scheduled_scan_async(
                schedule_id=_SCHEDULE_ID,
                tenant_id=_TENANT_ID,
                fired_at=_FIRED_AT,
            )

        assert result == {
            "status": "dispatched",
            "schedule_id": _SCHEDULE_ID,
            "scan_id": "scan-uuid-123",
        }
        tenant_mock.assert_awaited_once_with(session, _TENANT_ID)
        ensure_tenant_mock.assert_awaited_once_with(session, _TENANT_ID)
        persist_mock.assert_awaited_once_with(
            session,
            tenant_id=_TENANT_ID,
            target_url="https://t.example.com/api",
            scan_mode="deep",
            schedule_id=_SCHEDULE_ID,
        )
        compute_mock.assert_called_once_with(schedule.cron_expression, after=_FIRED_AT)
        update_mock.assert_awaited_once_with(
            session,
            schedule_id=_SCHEDULE_ID,
            fired_at=_FIRED_AT,
            next_run_at=next_run,
        )
        session.commit.assert_awaited_once()
        engine.dispose.assert_awaited_once()
        dispatch_mock.assert_called_once_with(
            scan_id="scan-uuid-123",
            tenant_id=_TENANT_ID,
            target_url="https://t.example.com/api",
        )

    @pytest.mark.asyncio
    async def test_dispatch_proceeds_even_when_next_run_unknown(self) -> None:
        """A malformed cron should not block the *current* fire; only
        ``next_run_at`` is left untouched."""
        engine, factory, session = _build_session_factory()
        schedule = _build_schedule()

        with (
            _patch_kill_switch(KillSwitchVerdict(blocked=False)),
            patch.object(
                scan_trigger,
                "create_task_engine_and_session",
                return_value=(engine, factory),
            ),
            patch.object(scan_trigger, "set_session_tenant", new=AsyncMock()),
            patch.object(
                scan_trigger,
                "_load_schedule",
                new=AsyncMock(return_value=schedule),
            ),
            patch.object(scan_trigger, "_ensure_tenant", new=AsyncMock()),
            patch.object(
                scan_trigger,
                "_persist_scheduled_scan",
                new=AsyncMock(return_value="scan-1"),
            ),
            patch.object(scan_trigger, "_compute_next_run_at", return_value=None),
            patch.object(
                scan_trigger, "_update_run_timestamps", new=AsyncMock()
            ) as update_mock,
            patch.object(scan_trigger, "_dispatch_scan_phase") as dispatch_mock,
        ):
            result = await _run_scheduled_scan_async(
                schedule_id=_SCHEDULE_ID,
                tenant_id=_TENANT_ID,
                fired_at=_FIRED_AT,
            )

        assert result["status"] == "dispatched"
        update_mock.assert_awaited_once_with(
            session,
            schedule_id=_SCHEDULE_ID,
            fired_at=_FIRED_AT,
            next_run_at=None,
        )
        dispatch_mock.assert_called_once()


# ===========================================================================
# Celery wrapper
# ===========================================================================


class TestCeleryWrapper:
    def test_wrapper_invokes_async_with_kwargs(self) -> None:
        """``run_scheduled_scan`` is ``bind=True`` so the first arg is
        ``self``; the wrapper must forward the schedule + tenant via
        kwargs and return the async coroutine's result.
        """
        captured: dict[str, Any] = {}

        async def _fake(
            *, schedule_id: str, tenant_id: str, fired_at: datetime
        ) -> dict[str, Any]:
            captured["schedule_id"] = schedule_id
            captured["tenant_id"] = tenant_id
            captured["fired_at"] = fired_at
            return {"status": "dispatched", "schedule_id": schedule_id, "scan_id": "x"}

        with patch.object(scan_trigger, "_run_scheduled_scan_async", new=_fake):
            result = run_scheduled_scan.run(_SCHEDULE_ID, _TENANT_ID)

        assert result == {
            "status": "dispatched",
            "schedule_id": _SCHEDULE_ID,
            "scan_id": "x",
        }
        assert captured["schedule_id"] == _SCHEDULE_ID
        assert captured["tenant_id"] == _TENANT_ID
        assert captured["fired_at"].tzinfo is timezone.utc


# ===========================================================================
# Skip-path audit emission — S2.1 / ARG-056
# ===========================================================================


class TestSkipPathAuditEmission:
    """The kill-switch + maintenance-window skip branches must persist a
    ``scan_schedule.skipped_*`` AuditLog row so operators can audit WHY
    a scheduled scan didn't fire (logger.info alone may be sampled or
    rotated out)."""

    @pytest.mark.asyncio
    async def test_kill_switch_blocked_writes_skipped_emergency_stop_audit(
        self,
    ) -> None:
        """Kill-switch blocked path opens its own short-lived session and
        inserts an ``AuditLog`` row with action ``scan_schedule.skipped_emergency_stop``."""
        verdict = KillSwitchVerdict(
            blocked=True,
            scope=KillSwitchScope.GLOBAL,
            reason="exercise",
        )
        captured_rows: list[Any] = []
        audit_session = AsyncMock()
        audit_session.add = MagicMock(side_effect=captured_rows.append)
        audit_session.commit = AsyncMock()
        audit_factory = MagicMock(return_value=_AsyncSessionCM(audit_session))

        with (
            _patch_kill_switch(verdict),
            patch.object(
                scan_trigger,
                "async_session_factory",
                audit_factory,
            ),
            patch.object(
                scan_trigger, "create_task_engine_and_session"
            ) as engine_factory_mock,
            patch.object(scan_trigger, "_dispatch_scan_phase") as dispatch_mock,
        ):
            result = await _run_scheduled_scan_async(
                schedule_id=_SCHEDULE_ID,
                tenant_id=_TENANT_ID,
                fired_at=_FIRED_AT,
            )

        assert result["status"] == "skipped_kill_switch"
        engine_factory_mock.assert_not_called()
        dispatch_mock.assert_not_called()
        # Exactly one AuditLog row inserted.
        assert len(captured_rows) == 1
        row = captured_rows[0]
        assert row.action == EVENT_SKIPPED_EMERGENCY_STOP
        assert row.tenant_id == _TENANT_ID
        assert row.resource_type == "scan_schedule"
        assert row.resource_id == _SCHEDULE_ID
        # Raw tenant_id MUST NOT appear in details — only the hash.
        assert "tenant_id_hash" in row.details
        assert _TENANT_ID not in str(row.details)
        assert row.details["reason"] == "kill_switch_blocked"
        assert row.details["verdict_reason"] == "exercise"
        audit_session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_maintenance_window_skip_writes_audit_using_open_session(
        self,
    ) -> None:
        """Maintenance-window skip path reuses the already-open session
        (it ran ``_load_schedule`` already) and inserts an AuditLog row
        with action ``scan_schedule.skipped_maintenance_window``."""
        engine, factory, session = _build_session_factory()
        captured_rows: list[Any] = []
        session.add = MagicMock(side_effect=captured_rows.append)

        schedule = _build_schedule(maintenance_window_cron="0 12 * * *")

        with (
            _patch_kill_switch(KillSwitchVerdict(blocked=False)),
            patch.object(
                scan_trigger,
                "create_task_engine_and_session",
                return_value=(engine, factory),
            ),
            patch.object(scan_trigger, "set_session_tenant", new=AsyncMock()),
            patch.object(
                scan_trigger,
                "_load_schedule",
                new=AsyncMock(return_value=schedule),
            ),
            patch.object(scan_trigger, "is_in_maintenance_window", return_value=True),
            patch.object(scan_trigger, "_dispatch_scan_phase") as dispatch_mock,
        ):
            result = await _run_scheduled_scan_async(
                schedule_id=_SCHEDULE_ID,
                tenant_id=_TENANT_ID,
                fired_at=_FIRED_AT,
            )

        assert result["status"] == "skipped_maintenance_window"
        dispatch_mock.assert_not_called()
        assert len(captured_rows) == 1
        row = captured_rows[0]
        assert row.action == EVENT_SKIPPED_MAINTENANCE_WINDOW
        assert row.tenant_id == _TENANT_ID
        assert row.resource_type == "scan_schedule"
        assert row.resource_id == _SCHEDULE_ID
        # Raw tenant_id MUST NOT appear in details — only the hash.
        assert "tenant_id_hash" in row.details
        assert _TENANT_ID not in str(row.details)
        assert row.details["reason"] == "in_maintenance_window"
        assert row.details["maintenance_window_cron"] == "0 12 * * *"
        # Session commit invoked for the audit row insert.
        session.commit.assert_awaited_once()
        engine.dispose.assert_awaited_once()
