"""Propagate scan cancellation to Celery workers, sandbox, and Quick tasks.

Raw evidence in MinIO / PhaseOutput is never deleted. Celery import is lazy
because ``celery_app`` includes ``src.tasks`` which imports the state machine
which imports this module.
"""

from __future__ import annotations

import logging
import subprocess
import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import String, cast, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.models import Scan
from src.quick.audit import emit_quick_audit_event
from src.quick.models import QuickBudgetLeaseRow, QuickTaskRow
from src.quick.schemas import QuickTaskStatus

logger = logging.getLogger(__name__)

_CANCEL_LOCK = threading.Lock()
_CANCELLED_SCANS: set[str] = set()
_CELERY_IDS: dict[str, set[str]] = {}

_ACTIVE_TASK_STATUSES = frozenset(
    {
        QuickTaskStatus.QUEUED.value,
        QuickTaskStatus.LEASED.value,
        QuickTaskStatus.RUNNING.value,
    }
)
_REVOKE_SIGNAL = "SIGTERM"


class ScanCancelledError(Exception):
    """Scan was cancelled. Stop new work; keep already-written artifacts."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        super().__init__("scan_cancelled")


@dataclass(frozen=True)
class CancellationResult:
    scan_id: str
    revoked_task_ids: tuple[str, ...] = ()
    cancelled_quick_tasks: int = 0
    sandbox_signaled: bool = False
    celery_revoke_ok: bool = True


def mark_scan_cancelled(scan_id: str) -> None:
    with _CANCEL_LOCK:
        _CANCELLED_SCANS.add(scan_id)


def is_scan_cancelled(scan_id: str) -> bool:
    if not scan_id:
        return False
    with _CANCEL_LOCK:
        return scan_id in _CANCELLED_SCANS


def register_celery_task_id(scan_id: str, celery_task_id: str) -> None:
    if not scan_id or not celery_task_id:
        return
    with _CANCEL_LOCK:
        _CELERY_IDS.setdefault(scan_id, set()).add(celery_task_id)


def unregister_celery_task_id(scan_id: str, celery_task_id: str) -> None:
    with _CANCEL_LOCK:
        ids = _CELERY_IDS.get(scan_id)
        if not ids:
            return
        ids.discard(celery_task_id)
        if not ids:
            _CELERY_IDS.pop(scan_id, None)


def registered_celery_task_ids(scan_id: str) -> tuple[str, ...]:
    with _CANCEL_LOCK:
        return tuple(_CELERY_IDS.get(scan_id, ()))


def _load_celery_app(explicit: Any | None) -> Any | None:
    if explicit is not None:
        return explicit
    # Circular: celery_app include → src.tasks → state_machine → cancellation.
    from src.celery_app import app as celery_app

    return celery_app


def revoke_celery_task_ids(
    task_ids: Sequence[str],
    *,
    celery_app: Any | None = None,
) -> tuple[str, ...]:
    """Best-effort revoke. Never raises. Does not delete artifacts."""
    app = _load_celery_app(celery_app)
    revoked: list[str] = []
    if app is None:
        return ()
    control = getattr(app, "control", None)
    if control is None or not hasattr(control, "revoke"):
        return ()
    for task_id in task_ids:
        if not task_id:
            continue
        try:
            control.revoke(task_id, terminate=True, signal=_REVOKE_SIGNAL)
            revoked.append(task_id)
        except Exception:  # noqa: BLE001 — broker/control failures must not fail cancel
            logger.warning(
                "quick_celery_revoke_failed",
                extra={"event": "quick_celery_revoke_failed", "celery_task_id": task_id},
            )
    return tuple(revoked)


def cancel_sandbox_for_scan(scan_id: str) -> bool:
    """Best-effort SIGTERM of sandbox processes whose cmdline contains scan_id."""
    if not scan_id or not settings.sandbox_enabled:
        return False
    container = (settings.sandbox_container_name or "").strip() or "argus-sandbox"
    try:
        completed = subprocess.run(
            ["docker", "exec", container, "pkill", "-TERM", "-f", scan_id],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            shell=False,
        )
        logger.info(
            "quick_sandbox_cancel",
            extra={
                "event": "quick_sandbox_cancel",
                "scan_id": scan_id,
                "return_code": completed.returncode,
            },
        )
        return True
    except (subprocess.TimeoutExpired, OSError):
        logger.warning(
            "quick_sandbox_cancel_failed",
            extra={"event": "quick_sandbox_cancel_failed", "scan_id": scan_id},
        )
        return False


def revoke_scan_workers(
    scan_id: str,
    *,
    extra_celery_ids: Iterable[str] | None = None,
    celery_app: Any | None = None,
) -> tuple[str, ...]:
    """Revoke the scan-phase task (id often equals scan_id) plus registered children."""
    ids: list[str] = [scan_id]
    ids.extend(registered_celery_task_ids(scan_id))
    if extra_celery_ids:
        ids.extend(str(item) for item in extra_celery_ids if item)
    unique: list[str] = []
    seen: set[str] = set()
    for item in ids:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    revoked = revoke_celery_task_ids(unique, celery_app=celery_app)
    sandbox_ok = cancel_sandbox_for_scan(scan_id)
    logger.info(
        "quick_workers_revoked",
        extra={
            "event": "quick_workers_revoked",
            "scan_id": scan_id,
            "revoked_count": len(revoked),
            "sandbox_signaled": sandbox_ok,
        },
    )
    return revoked


async def _cancel_quick_task_rows(
    session: AsyncSession,
    *,
    scan_id: str,
    tenant_id: str,
) -> tuple[int, tuple[str, ...]]:
    result = await session.execute(
        select(QuickTaskRow.id, QuickTaskRow.celery_task_id, QuickTaskRow.status).where(
            cast(QuickTaskRow.scan_id, String) == scan_id,
            cast(QuickTaskRow.tenant_id, String) == tenant_id,
        )
    )
    celery_ids: list[str] = []
    cancellable = 0
    for row_id, celery_id, status in result.all():
        if celery_id:
            celery_ids.append(str(celery_id))
        if status in _ACTIVE_TASK_STATUSES:
            cancellable += 1
    if cancellable:
        await session.execute(
            update(QuickTaskRow)
            .where(
                cast(QuickTaskRow.scan_id, String) == scan_id,
                cast(QuickTaskRow.tenant_id, String) == tenant_id,
                QuickTaskRow.status.in_(tuple(_ACTIVE_TASK_STATUSES)),
            )
            .values(status=QuickTaskStatus.CANCELLED.value)
        )
    await session.execute(
        update(QuickBudgetLeaseRow)
        .where(
            cast(QuickBudgetLeaseRow.scan_id, String) == scan_id,
            cast(QuickBudgetLeaseRow.tenant_id, String) == tenant_id,
            QuickBudgetLeaseRow.status == "active",
        )
        .values(status="released")
    )
    return cancellable, tuple(celery_ids)


async def propagate_scan_cancellation(
    *,
    scan_id: str,
    tenant_id: str,
    reason: str,
    session: AsyncSession | None = None,
    celery_app: Any | None = None,
    revoke_workers: bool = True,
) -> CancellationResult:
    """Stop new work, revoke workers, mark Quick tasks cancelled. Evidence is left intact."""
    mark_scan_cancelled(scan_id)
    extra_ids: tuple[str, ...] = ()
    cancelled_tasks = 0
    if session is not None:
        try:
            cancelled_tasks, extra_ids = await _cancel_quick_task_rows(
                session, scan_id=scan_id, tenant_id=tenant_id
            )
        except Exception:  # noqa: BLE001 — missing quick tables must not fail cancel
            logger.warning(
                "quick_task_cancel_failed",
                extra={"event": "quick_task_cancel_failed", "scan_id": scan_id},
            )
    revoked: tuple[str, ...] = ()
    celery_ok = True
    sandbox_ok = False
    if revoke_workers:
        try:
            revoked = revoke_scan_workers(
                scan_id,
                extra_celery_ids=extra_ids,
                celery_app=celery_app,
            )
            sandbox_ok = True
        except Exception:  # noqa: BLE001 — worker revoke is best-effort
            celery_ok = False
            logger.warning(
                "quick_cancel_revoke_failed",
                extra={"event": "quick_cancel_revoke_failed", "scan_id": scan_id},
            )
    logger.info(
        "quick_scan_cancelled",
        extra={
            "event": "quick_scan_cancelled",
            "scan_id": scan_id,
            "reason_len": len(reason or ""),
            "cancelled_quick_tasks": cancelled_tasks,
        },
    )
    emit_quick_audit_event(
        "quick.cancel",
        scan_id=scan_id,
        tenant_id=tenant_id,
        payload={"cancelled_quick_tasks": cancelled_tasks, "reason_present": bool(reason)},
    )
    return CancellationResult(
        scan_id=scan_id,
        revoked_task_ids=revoked,
        cancelled_quick_tasks=cancelled_tasks,
        sandbox_signaled=sandbox_ok,
        celery_revoke_ok=celery_ok,
    )


async def scan_row_is_cancelled(session: AsyncSession, scan_id: str) -> bool:
    if is_scan_cancelled(scan_id):
        return True
    result = await session.execute(
        select(Scan.status).where(cast(Scan.id, String) == scan_id)
    )
    status = result.scalar_one_or_none()
    cancelled = str(status or "").lower() == "cancelled"
    if cancelled:
        mark_scan_cancelled(scan_id)
    return cancelled


__all__ = [
    "CancellationResult",
    "ScanCancelledError",
    "cancel_sandbox_for_scan",
    "is_scan_cancelled",
    "mark_scan_cancelled",
    "propagate_scan_cancellation",
    "register_celery_task_id",
    "registered_celery_task_ids",
    "revoke_celery_task_ids",
    "revoke_scan_workers",
    "scan_row_is_cancelled",
    "unregister_celery_task_id",
]
