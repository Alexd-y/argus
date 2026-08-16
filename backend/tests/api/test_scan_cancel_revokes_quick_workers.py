"""QUICK-004 — POST /scans/{id}/cancel revokes Quick Celery workers; evidence kept.

Mocks Celery ``control.revoke``. No live Redis/broker is required.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-prod-but-required-by-settings")
os.environ.setdefault("ARGUS_TEST_MODE", "1")

import pytest  # noqa: E402

from src.api.routers.scans import cancel_scan  # noqa: E402
from src.quick import cancellation as cancel_mod  # noqa: E402
from src.quick.schemas import QuickTaskStatus  # noqa: E402

_SCAN_ID = "abcdabcd-abcd-4000-8000-abcdabcdabcd"
_TENANT_ID = "tenant-1"
_CHILD_REGISTERED = "quick-worker-registered-1"
_CHILD_FROM_ROW = "quick-worker-db-1"


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    """Do not boot FastAPI ``app`` — this module calls the router with mocks."""
    yield


@pytest.fixture(autouse=True)
def _reset_cancel_state() -> Iterator[None]:
    with cancel_mod._CANCEL_LOCK:
        cancel_mod._CANCELLED_SCANS.clear()
        cancel_mod._CELERY_IDS.clear()
    yield
    with cancel_mod._CANCEL_LOCK:
        cancel_mod._CANCELLED_SCANS.clear()
        cancel_mod._CELERY_IDS.clear()


def _session_with_running_scan() -> AsyncMock:
    mock_scan = MagicMock()
    mock_scan.id = _SCAN_ID
    mock_scan.status = "running"
    mock_scan.tenant_id = _TENANT_ID

    executed: list[str] = []

    async def _execute(stmt, *args, **kwargs):
        rendered = str(stmt).lower()
        executed.append(rendered)
        result = MagicMock()
        result.scalar_one_or_none.return_value = mock_scan
        result.all.return_value = [
            (
                "10000000-0000-4000-8000-0000000000cc",
                _CHILD_FROM_ROW,
                QuickTaskStatus.RUNNING.value,
            ),
        ]
        return result

    session = AsyncMock()
    session.execute = AsyncMock(side_effect=_execute)
    session.commit = AsyncMock()
    session.delete = MagicMock()
    session._executed_sql = executed
    return session


@pytest.mark.asyncio
async def test_cancel_scan_revokes_scan_and_quick_child_workers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cancel_mod.settings, "sandbox_enabled", True)
    pkill = MagicMock(return_value=MagicMock(returncode=0))
    monkeypatch.setattr(cancel_mod.subprocess, "run", pkill)

    session = _session_with_running_scan()
    mock_session_ctx = AsyncMock()
    mock_session_ctx.__aenter__.return_value = session

    celery = MagicMock()
    celery.control.revoke = MagicMock()

    cancel_mod.register_celery_task_id(_SCAN_ID, _CHILD_REGISTERED)

    with (
        patch(
            "src.api.routers.scans.async_session_factory",
            return_value=mock_session_ctx,
        ),
        patch(
            "src.api.routers.scans.set_session_tenant",
            new_callable=AsyncMock,
        ),
        patch(
            "src.api.routers.scans.celery_app",
            celery,
        ),
    ):
        result = await cancel_scan(_SCAN_ID, tenant_id=_TENANT_ID)

    assert result.status == "cancelled"
    assert result.scan_id == _SCAN_ID
    revoked_ids = [call.args[0] for call in celery.control.revoke.call_args_list]
    assert _SCAN_ID in revoked_ids
    assert _CHILD_REGISTERED in revoked_ids
    assert _CHILD_FROM_ROW in revoked_ids
    for call in celery.control.revoke.call_args_list:
        assert call.kwargs["terminate"] is True
        assert call.kwargs["signal"] == "SIGTERM"
    session.delete.assert_not_called()
    assert "delete from" not in " ".join(session._executed_sql)
    pkill.assert_called()
    assert cancel_mod.is_scan_cancelled(_SCAN_ID) is True


@pytest.mark.asyncio
async def test_cancel_scan_keeps_evidence_when_revoke_fails() -> None:
    session = _session_with_running_scan()
    mock_session_ctx = AsyncMock()
    mock_session_ctx.__aenter__.return_value = session

    celery = MagicMock()
    celery.control.revoke.side_effect = ConnectionError("broker down")

    with (
        patch(
            "src.api.routers.scans.async_session_factory",
            return_value=mock_session_ctx,
        ),
        patch(
            "src.api.routers.scans.set_session_tenant",
            new_callable=AsyncMock,
        ),
        patch(
            "src.api.routers.scans.celery_app",
            celery,
        ),
    ):
        result = await cancel_scan(_SCAN_ID, tenant_id=_TENANT_ID)

    assert result.status == "cancelled"
    session.delete.assert_not_called()
    assert "delete from" not in " ".join(session._executed_sql)
    assert cancel_mod.is_scan_cancelled(_SCAN_ID) is True
