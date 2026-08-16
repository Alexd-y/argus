"""QUICK-004 — cancel propagates to workers; evidence is never deleted."""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.quick import cancellation as cancel_mod
from src.quick.cancellation import (
    CancellationResult,
    ScanCancelledError,
    cancel_sandbox_for_scan,
    is_scan_cancelled,
    mark_scan_cancelled,
    propagate_scan_cancellation,
    register_celery_task_id,
    registered_celery_task_ids,
    revoke_celery_task_ids,
    revoke_scan_workers,
    scan_row_is_cancelled,
    unregister_celery_task_id,
)
from src.quick.schemas import QuickTaskStatus

_SCAN_ID = "eeeeeeee-ffff-0000-1111-222222222222"
_TENANT_ID = "tenant-quick-004-cancel-01"


@pytest.fixture(autouse=True)
def _reset_cancel_state() -> Iterator[None]:
    with cancel_mod._CANCEL_LOCK:
        cancel_mod._CANCELLED_SCANS.clear()
        cancel_mod._CELERY_IDS.clear()
    yield
    with cancel_mod._CANCEL_LOCK:
        cancel_mod._CANCELLED_SCANS.clear()
        cancel_mod._CELERY_IDS.clear()


def test_mark_and_is_scan_cancelled() -> None:
    assert is_scan_cancelled("") is False
    assert is_scan_cancelled(_SCAN_ID) is False
    mark_scan_cancelled(_SCAN_ID)
    assert is_scan_cancelled(_SCAN_ID) is True
    assert is_scan_cancelled("other-scan-id-00000000000000000000") is False


def test_register_unregister_celery_task_ids() -> None:
    register_celery_task_id("", "celery-1")
    register_celery_task_id(_SCAN_ID, "")
    assert registered_celery_task_ids(_SCAN_ID) == ()
    register_celery_task_id(_SCAN_ID, "celery-1")
    register_celery_task_id(_SCAN_ID, "celery-2")
    register_celery_task_id(_SCAN_ID, "celery-1")
    ids = set(registered_celery_task_ids(_SCAN_ID))
    assert ids == {"celery-1", "celery-2"}
    unregister_celery_task_id(_SCAN_ID, "celery-1")
    assert registered_celery_task_ids(_SCAN_ID) == ("celery-2",)
    unregister_celery_task_id(_SCAN_ID, "celery-2")
    assert registered_celery_task_ids(_SCAN_ID) == ()


def test_revoke_celery_task_ids_uses_mock_control_never_raises() -> None:
    celery = MagicMock()
    celery.control.revoke = MagicMock()
    revoked = revoke_celery_task_ids(
        [_SCAN_ID, "", "child-1"],
        celery_app=celery,
    )
    assert revoked == (_SCAN_ID, "child-1")
    assert celery.control.revoke.call_count == 2
    celery.control.revoke.assert_any_call(_SCAN_ID, terminate=True, signal="SIGTERM")
    celery.control.revoke.assert_any_call("child-1", terminate=True, signal="SIGTERM")

    celery.control.revoke.side_effect = ConnectionError("broker down")
    failed = revoke_celery_task_ids(["child-2"], celery_app=celery)
    assert failed == ()

    assert revoke_celery_task_ids(["x"], celery_app=MagicMock(control=None)) == ()
    no_revoke = MagicMock()
    no_revoke.control = object()
    assert revoke_celery_task_ids(["x"], celery_app=no_revoke) == ()


def test_cancel_sandbox_skips_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cancel_mod.settings, "sandbox_enabled", False)
    ran = MagicMock()
    monkeypatch.setattr(cancel_mod.subprocess, "run", ran)
    assert cancel_sandbox_for_scan(_SCAN_ID) is False
    ran.assert_not_called()


def test_cancel_sandbox_pkill_is_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cancel_mod.settings, "sandbox_enabled", True)
    monkeypatch.setattr(cancel_mod.settings, "sandbox_container_name", "argus-sandbox")
    completed = MagicMock()
    completed.returncode = 0
    ran = MagicMock(return_value=completed)
    monkeypatch.setattr(cancel_mod.subprocess, "run", ran)
    assert cancel_sandbox_for_scan(_SCAN_ID) is True
    ran.assert_called_once()
    argv = ran.call_args.args[0]
    assert argv[:3] == ["docker", "exec", "argus-sandbox"]
    assert "pkill" in argv
    assert "-TERM" in argv
    assert _SCAN_ID in argv
    assert ran.call_args.kwargs["shell"] is False


def test_revoke_scan_workers_includes_registered_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cancel_mod.settings, "sandbox_enabled", False)
    celery = MagicMock()
    register_celery_task_id(_SCAN_ID, "child-reg")
    revoked = revoke_scan_workers(
        _SCAN_ID,
        extra_celery_ids=["child-extra", _SCAN_ID],
        celery_app=celery,
    )
    called = [call.args[0] for call in celery.control.revoke.call_args_list]
    assert called[0] == _SCAN_ID
    assert "child-reg" in called
    assert "child-extra" in called
    assert called.count(_SCAN_ID) == 1
    assert set(revoked) == {_SCAN_ID, "child-reg", "child-extra"}


@pytest.mark.asyncio
async def test_propagate_marks_cancelled_revokes_and_does_not_delete_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cancel_mod.settings, "sandbox_enabled", True)
    monkeypatch.setattr(
        cancel_mod.subprocess,
        "run",
        MagicMock(return_value=MagicMock(returncode=1)),
    )
    celery = MagicMock()
    executed: list[str] = []

    select_result = MagicMock()
    select_result.all.return_value = [
        (
            "10000000-0000-4000-8000-000000000001",
            "quick-celery-1",
            QuickTaskStatus.RUNNING.value,
        ),
        (
            "10000000-0000-4000-8000-000000000002",
            None,
            QuickTaskStatus.SUCCEEDED.value,
        ),
    ]

    async def _execute(stmt, *args, **kwargs):
        executed.append(str(stmt).lower())
        result = MagicMock()
        result.all.return_value = select_result.all.return_value
        result.scalar_one_or_none.return_value = None
        return result

    session = AsyncMock()
    session.execute = AsyncMock(side_effect=_execute)
    session.delete = MagicMock()

    result = await propagate_scan_cancellation(
        scan_id=_SCAN_ID,
        tenant_id=_TENANT_ID,
        reason="api_cancel",
        session=session,
        celery_app=celery,
    )
    assert isinstance(result, CancellationResult)
    assert result.scan_id == _SCAN_ID
    assert is_scan_cancelled(_SCAN_ID) is True
    assert result.cancelled_quick_tasks == 1
    assert "quick-celery-1" in result.revoked_task_ids
    assert _SCAN_ID in result.revoked_task_ids
    session.delete.assert_not_called()
    joined = " ".join(executed)
    assert "delete from" not in joined
    assert "phase_output" not in joined
    assert "minio" not in joined
    assert any("update" in item for item in executed)


@pytest.mark.asyncio
async def test_propagate_survives_session_and_revoke_failures() -> None:
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=RuntimeError("quick tables missing"))
    celery = MagicMock()
    celery.control.revoke.side_effect = ConnectionError("broker down")
    result = await propagate_scan_cancellation(
        scan_id=_SCAN_ID,
        tenant_id=_TENANT_ID,
        reason="status_cancelled",
        session=session,
        celery_app=celery,
    )
    assert is_scan_cancelled(_SCAN_ID) is True
    assert result.cancelled_quick_tasks == 0
    assert result.celery_revoke_ok is True
    assert result.revoked_task_ids == ()


@pytest.mark.asyncio
async def test_scan_row_is_cancelled_reads_status_and_caches() -> None:
    session = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = "cancelled"
    session.execute = AsyncMock(return_value=result)
    assert await scan_row_is_cancelled(session, _SCAN_ID) is True
    assert is_scan_cancelled(_SCAN_ID) is True
    session.execute.reset_mock()
    assert await scan_row_is_cancelled(session, _SCAN_ID) is True
    session.execute.assert_not_called()


def test_scan_cancelled_error_carries_scan_id() -> None:
    err = ScanCancelledError(_SCAN_ID)
    assert err.scan_id == _SCAN_ID
    assert str(err) == "scan_cancelled"
