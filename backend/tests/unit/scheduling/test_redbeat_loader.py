"""Unit tests for :mod:`src.scheduling.redbeat_loader` (T33, ARG-056).

Validates the dynamic CRUD-to-RedBeat bridge:

* :func:`sync_one`        — happy-path persist, disabled rows still
                            registered, defensive returns when redbeat /
                            celery / Redis is unavailable.
* :func:`remove_one`      — idempotent deletes, missing-key handling,
                            unavailable-stack returns.
* :func:`sync_all_from_db`— bulk reconciliation count vs. partial
                            failure semantics.

The loader is intentionally pure-Python — Celery + RedBeat + Redis are
patched at module-level seams (``_get_redbeat_entry_cls``,
``_get_celery_app``, ``_get_celery_crontab``) so no broker or Redis
connection is required.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.scheduling import redbeat_loader
from src.scheduling.redbeat_loader import (
    SCAN_TRIGGER_TASK_NAME,
    _build_celery_schedule,
    _entry_name,
    remove_one,
    sync_all_from_db,
    sync_one,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _build_row(
    *,
    schedule_id: str = "00000000-0000-4000-8000-000000000001",
    tenant_id: str = "11111111-1111-4111-8111-111111111111",
    cron_expression: str = "*/15 * * * *",
    enabled: bool = True,
) -> MagicMock:
    """Stand-in for a :class:`ScanSchedule` ORM row.

    Only the attributes :func:`sync_one` reads are populated; using
    ``MagicMock`` means a future field added to the model still passes
    these tests until a unit deliberately asserts on it.
    """
    row = MagicMock()
    row.id = schedule_id
    row.tenant_id = tenant_id
    row.cron_expression = cron_expression
    row.enabled = enabled
    return row


def _patch_entry_cls(value: Any):
    return patch.object(redbeat_loader, "_get_redbeat_entry_cls", return_value=value)


def _patch_celery_app(value: Any):
    return patch.object(redbeat_loader, "_get_celery_app", return_value=value)


def _patch_crontab(value: Any):
    return patch.object(redbeat_loader, "_get_celery_crontab", return_value=value)


# ===========================================================================
# Module-level helpers (pure logic)
# ===========================================================================


class TestEntryName:
    def test_entry_name_uses_argus_schedule_prefix(self) -> None:
        assert _entry_name("abc-123") == "argus.schedule.abc-123"

    def test_entry_name_does_not_collide_with_intel_namespace(self) -> None:
        """Intel-refresh entries live under ``argus.intel.*`` — prefix
        difference is what keeps operator KEYS scans cheap."""
        name = _entry_name("11111111-1111-4111-8111-111111111111")
        assert name.startswith("argus.schedule.")
        assert "intel" not in name


class TestBuildCelerySchedule:
    def test_build_returns_none_when_celery_missing(self) -> None:
        with _patch_crontab(None):
            assert _build_celery_schedule("*/5 * * * *") is None

    def test_build_returns_none_for_field_count_mismatch(self) -> None:
        crontab_cls = MagicMock()
        with _patch_crontab(crontab_cls):
            assert _build_celery_schedule("0 0 *") is None
        crontab_cls.assert_not_called()

    def test_build_invokes_crontab_with_named_fields(self) -> None:
        crontab_cls = MagicMock(return_value="schedule-obj")
        with _patch_crontab(crontab_cls):
            result = _build_celery_schedule("*/5 12 1 6 *")
        crontab_cls.assert_called_once_with(
            minute="*/5",
            hour="12",
            day_of_month="1",
            month_of_year="6",
            day_of_week="*",
        )
        assert result == "schedule-obj"

    def test_build_returns_none_when_crontab_raises(self) -> None:
        crontab_cls = MagicMock(side_effect=ValueError("bad spec"))
        with _patch_crontab(crontab_cls):
            assert _build_celery_schedule("*/5 * * * *") is None


# ===========================================================================
# sync_one
# ===========================================================================


class TestSyncOne:
    def test_returns_false_when_redbeat_not_installed(self) -> None:
        row = _build_row()
        with _patch_entry_cls(None):
            assert sync_one(row) is False

    def test_returns_false_when_celery_app_unavailable(self) -> None:
        row = _build_row()
        entry_cls = MagicMock()
        with _patch_entry_cls(entry_cls), _patch_celery_app(None):
            assert sync_one(row) is False
        entry_cls.assert_not_called()

    def test_returns_false_when_crontab_translation_fails(self) -> None:
        """Field-count mismatch propagates as a False return without
        attempting any Redis I/O."""
        row = _build_row(cron_expression="bad cron")
        entry_cls = MagicMock()
        with (
            _patch_entry_cls(entry_cls),
            _patch_celery_app(MagicMock()),
            _patch_crontab(MagicMock()),
        ):
            assert sync_one(row) is False
        entry_cls.assert_not_called()

    def test_happy_path_persists_entry(self) -> None:
        """Entry constructed with correct kwargs and ``save()`` called once."""
        row = _build_row(enabled=True)
        celery_app = MagicMock()
        entry_instance = MagicMock()
        entry_cls = MagicMock(return_value=entry_instance)
        crontab_cls = MagicMock(return_value="cron-obj")

        with (
            _patch_entry_cls(entry_cls),
            _patch_celery_app(celery_app),
            _patch_crontab(crontab_cls),
        ):
            assert sync_one(row) is True

        entry_cls.assert_called_once()
        kwargs = entry_cls.call_args.kwargs
        assert kwargs["name"] == _entry_name(row.id)
        assert kwargs["task"] == SCAN_TRIGGER_TASK_NAME
        assert kwargs["schedule"] == "cron-obj"
        assert kwargs["kwargs"] == {
            "schedule_id": row.id,
            "tenant_id": row.tenant_id,
        }
        assert kwargs["options"] == {"queue": "argus.scans"}
        assert kwargs["enabled"] is True
        assert kwargs["app"] is celery_app
        entry_instance.save.assert_called_once()

    def test_disabled_row_still_writes_entry_but_marked_disabled(self) -> None:
        """Disabled schedules round-trip as ``enabled=False`` so re-enable
        is a single Redis write, not a re-create."""
        row = _build_row(enabled=False)
        entry_instance = MagicMock()
        entry_cls = MagicMock(return_value=entry_instance)
        with (
            _patch_entry_cls(entry_cls),
            _patch_celery_app(MagicMock()),
            _patch_crontab(MagicMock(return_value="cron-obj")),
        ):
            assert sync_one(row) is True
        assert entry_cls.call_args.kwargs["enabled"] is False
        entry_instance.save.assert_called_once()

    def test_redis_failure_returns_false_without_raising(self) -> None:
        """Any exception from ``save()`` is swallowed → defensive False."""
        row = _build_row()
        entry_instance = MagicMock()
        entry_instance.save.side_effect = ConnectionError("redis down")
        entry_cls = MagicMock(return_value=entry_instance)
        with (
            _patch_entry_cls(entry_cls),
            _patch_celery_app(MagicMock()),
            _patch_crontab(MagicMock(return_value="cron-obj")),
        ):
            assert sync_one(row) is False


# ===========================================================================
# remove_one
# ===========================================================================


class TestRemoveOne:
    def test_returns_false_when_redbeat_not_installed(self) -> None:
        with _patch_entry_cls(None):
            assert remove_one("any-id") is False

    def test_returns_false_when_celery_app_unavailable(self) -> None:
        with _patch_entry_cls(MagicMock()), _patch_celery_app(None):
            assert remove_one("any-id") is False

    def test_returns_true_when_entry_already_absent(self) -> None:
        """Idempotent semantics: missing key is success."""
        entry_cls = MagicMock()
        entry_cls.generate_key = MagicMock(
            return_value="argus:redbeat:argus.schedule.x"
        )
        entry_cls.from_key = MagicMock(side_effect=KeyError("missing"))

        with _patch_entry_cls(entry_cls), _patch_celery_app(MagicMock()):
            assert remove_one("schedule-x") is True

    def test_returns_false_when_lookup_raises_unexpected(self) -> None:
        entry_cls = MagicMock()
        entry_cls.generate_key = MagicMock(return_value="some-key")
        entry_cls.from_key = MagicMock(side_effect=ConnectionError("redis"))

        with _patch_entry_cls(entry_cls), _patch_celery_app(MagicMock()):
            assert remove_one("schedule-y") is False

    def test_happy_path_calls_delete_and_returns_true(self) -> None:
        entry_instance = MagicMock()
        entry_cls = MagicMock()
        entry_cls.generate_key = MagicMock(return_value="some-key")
        entry_cls.from_key = MagicMock(return_value=entry_instance)

        with _patch_entry_cls(entry_cls), _patch_celery_app(MagicMock()):
            assert remove_one("schedule-z") is True
        entry_instance.delete.assert_called_once()

    def test_delete_failure_returns_false(self) -> None:
        entry_instance = MagicMock()
        entry_instance.delete.side_effect = ConnectionError("redis")
        entry_cls = MagicMock()
        entry_cls.generate_key = MagicMock(return_value="some-key")
        entry_cls.from_key = MagicMock(return_value=entry_instance)

        with _patch_entry_cls(entry_cls), _patch_celery_app(MagicMock()):
            assert remove_one("schedule-z") is False


# ===========================================================================
# sync_all_from_db
# ===========================================================================


def _make_async_session(rows: list[Any]) -> AsyncMock:
    """An ``AsyncSession`` whose single ``execute()`` returns ``rows``."""
    scalars = MagicMock()
    scalars.all.return_value = rows
    result = MagicMock()
    result.scalars.return_value = scalars
    session = AsyncMock()
    session.execute = AsyncMock(return_value=result)
    return session


class TestSyncAllFromDb:
    @pytest.mark.asyncio
    async def test_returns_zero_when_redbeat_unavailable(self) -> None:
        rows = [_build_row(), _build_row()]
        session = _make_async_session(rows)
        with _patch_entry_cls(None):
            count = await sync_all_from_db(session)
        assert count == 0
        session.execute.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_returns_zero_when_celery_app_unavailable(self) -> None:
        rows = [_build_row()]
        session = _make_async_session(rows)
        with _patch_entry_cls(MagicMock()), _patch_celery_app(None):
            count = await sync_all_from_db(session)
        assert count == 0
        session.execute.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_counts_only_successful_syncs(self) -> None:
        """Mixed pass/fail rows return a partial count, not all-or-nothing."""
        rows = [
            _build_row(schedule_id="a", cron_expression="*/5 * * * *"),
            _build_row(schedule_id="b", cron_expression="bad cron"),  # fails
            _build_row(schedule_id="c", cron_expression="0 0 * * *"),
        ]
        session = _make_async_session(rows)
        entry_cls = MagicMock(return_value=MagicMock())
        with (
            _patch_entry_cls(entry_cls),
            _patch_celery_app(MagicMock()),
            _patch_crontab(MagicMock(return_value="cron-obj")),
        ):
            count = await sync_all_from_db(session)

        assert count == 2  # row-b skipped on field-count mismatch
        session.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_zero_for_empty_table(self) -> None:
        session = _make_async_session([])
        with (
            _patch_entry_cls(MagicMock()),
            _patch_celery_app(MagicMock()),
            _patch_crontab(MagicMock(return_value="cron-obj")),
        ):
            count = await sync_all_from_db(session)
        assert count == 0
