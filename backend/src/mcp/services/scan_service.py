"""Tenant-scoped scan operations consumed by MCP ``scan.*`` tools.

The functions here are DB-only (no Celery dispatch, no FastAPI). The MCP
``scan.create`` tool calls :func:`enqueue_scan` to write the row and then
defers to the existing Celery task via the parent ``scans`` router service.
For unit testing we expose a thin service that can be overridden via
:func:`set_scan_dispatcher`.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import String, cast, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Finding as FindingModel
from src.db.models import Scan, Target, Tenant
from src.db.session import async_session_factory, set_session_tenant
from src.mcp.exceptions import (
    ResourceNotFoundError,
    UpstreamServiceError,
    ValidationError,
)
from src.mcp.schemas.scan import (
    ScanCreateInput,
    ScanCreateResult,
    ScanProfile,
    ScanScopeInput,
    ScanStatus,
    ScanStatusResult,
)

_logger = logging.getLogger(__name__)

_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {"completed", "failed", "cancelled", "errored"}
)

ScanDispatcher = Callable[[str, str, str, dict[str, Any]], Awaitable[None]]
"""Async callback invoked after the scan row is committed.

Signature: ``(scan_id, tenant_id, target, options) -> None``. Production
deploys wire this to ``scan_phase_task.delay`` — tests substitute a no-op.
"""


_default_dispatcher: ScanDispatcher | None = None


def set_scan_dispatcher(dispatcher: ScanDispatcher | None) -> None:
    """Override the post-commit dispatcher (test hook)."""
    global _default_dispatcher
    _default_dispatcher = dispatcher


async def _default_celery_dispatch(
    scan_id: str, tenant_id: str, target: str, options: dict[str, Any]
) -> None:
    try:
        # Optional Celery dispatcher: ``src.tasks.scan_tasks`` only ships in
        # deployments that bundle the scan worker. Silence mypy: the soft
        # import is the canonical contract for "queue is reachable".
        from src.tasks.scan_tasks import scan_phase_task  # type: ignore[import-not-found]
    except ImportError:
        _logger.warning(
            "mcp.scan.dispatch_unavailable",
            extra={"scan_id": scan_id, "tenant_id": tenant_id},
        )
        return
    scan_phase_task.delay(scan_id, tenant_id, target, options)


def _resolve_dispatcher() -> ScanDispatcher:
    return _default_dispatcher or _default_celery_dispatch


@dataclass(frozen=True, slots=True)
class _ScanRow:
    """Internal projection of a Scan row used by the MCP layer."""

    scan_id: str
    tenant_id: str
    target: str
    status: str
    progress: int
    started_at: datetime | None
    finished_at: datetime | None


def _coerce_scan_status(raw: str | None) -> ScanStatus:
    """Map internal status (queued / running / done / etc.) to the MCP enum.

    Values outside the closed taxonomy are mapped to :attr:`ScanStatus.RUNNING`
    and a warning is logged so we do not silently leak unknown enum values.
    """
    value = (raw or "pending").lower().strip()
    mapping = {
        "pending": ScanStatus.PENDING,
        "queued": ScanStatus.PENDING,
        "init": ScanStatus.PENDING,
        "running": ScanStatus.RUNNING,
        "in_progress": ScanStatus.RUNNING,
        "completed": ScanStatus.COMPLETED,
        "done": ScanStatus.COMPLETED,
        "failed": ScanStatus.FAILED,
        "errored": ScanStatus.FAILED,
        "cancelled": ScanStatus.CANCELLED,
        "canceled": ScanStatus.CANCELLED,
    }
    if value not in mapping:
        _logger.warning("mcp.scan.unknown_status", extra={"raw": value})
    return mapping.get(value, ScanStatus.RUNNING)


def _profile_to_scan_mode(profile: ScanProfile) -> str:
    return profile.value


def _scope_to_options(scope: ScanScopeInput) -> dict[str, Any]:
    return {
        "scope": {
            "include_subdomains": scope.include_subdomains,
            "max_depth": scope.max_depth,
            "follow_redirects": scope.follow_redirects,
        }
    }


async def enqueue_scan(
    *,
    tenant_id: str,
    user_id: str,
    payload: ScanCreateInput,
) -> ScanCreateResult:
    """Persist a scan row and notify the dispatcher.

    Tenant isolation: the row is written with ``tenant_id`` and the session
    has ``set_session_tenant`` applied so RLS rules see the correct GUC.
    """
    if not tenant_id:
        raise ValidationError("tenant_id is required to enqueue a scan.")

    scan_id = str(uuid.uuid4())
    options = _scope_to_options(payload.scope)
    options["mcp_actor"] = "mcp_client"
    options["mcp_user_id"] = user_id

    try:
        async with async_session_factory() as session:
            await set_session_tenant(session, tenant_id)
            tenant_existing = await session.execute(
                select(Tenant).where(cast(Tenant.id, String) == tenant_id)
            )
            if tenant_existing.scalar_one_or_none() is None:
                session.add(Tenant(id=tenant_id, name="default"))
                await session.flush()

            target_row = Target(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                url=payload.target,
            )
            session.add(target_row)
            await session.flush()

            scan_row = Scan(
                id=scan_id,
                tenant_id=tenant_id,
                target_id=target_row.id,
                target_url=payload.target,
                status="queued",
                progress=0,
                phase="init",
                options=options,
                scan_mode=_profile_to_scan_mode(payload.profile),
            )
            session.add(scan_row)
            await session.commit()
    except Exception as exc:
        _logger.exception(
            "mcp.scan.enqueue_failed",
            extra={"tenant_id": tenant_id, "target": payload.target},
        )
        raise UpstreamServiceError(
            "Failed to persist the scan row; please retry later."
        ) from exc

    dispatcher = _resolve_dispatcher()
    try:
        await dispatcher(scan_id, tenant_id, payload.target, options)
    except Exception:
        _logger.exception(
            "mcp.scan.dispatch_failed",
            extra={"scan_id": scan_id, "tenant_id": tenant_id},
        )

    requires_approval = payload.profile is ScanProfile.DEEP and not bool(
        payload.justification
    )
    return ScanCreateResult(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        target=payload.target,
        profile=payload.profile,
        requires_approval=requires_approval,
    )


async def get_scan_status(*, tenant_id: str, scan_id: str) -> ScanStatusResult:
    """Return the current scan status with severity counts.

    Raises :class:`ResourceNotFoundError` if the scan is missing OR owned
    by a different tenant — never disclose whether the id exists in another
    tenant's namespace.
    """
    try:
        async with async_session_factory() as session:
            await set_session_tenant(session, tenant_id)
            scan_query = await session.execute(
                select(Scan).where(
                    cast(Scan.id, String) == scan_id,
                    cast(Scan.tenant_id, String) == tenant_id,
                )
            )
            scan = scan_query.scalar_one_or_none()
            if scan is None:
                raise ResourceNotFoundError(
                    f"Scan {scan_id!r} was not found in this tenant scope."
                )

            severity_counts = await _severity_counts(session, scan_id, tenant_id)

            started_at, finished_at = _extract_timestamps(scan)
            return ScanStatusResult(
                scan_id=scan_id,
                status=_coerce_scan_status(scan.status),
                progress_percent=int(scan.progress or 0),
                target=scan.target_url,
                started_at=started_at,
                finished_at=finished_at,
                finding_counts=severity_counts,
            )
    except ResourceNotFoundError:
        raise
    except Exception as exc:
        _logger.exception(
            "mcp.scan.status_failed",
            extra={"scan_id": scan_id, "tenant_id": tenant_id},
        )
        raise UpstreamServiceError(
            "Failed to read scan status; please retry later."
        ) from exc


async def cancel_scan(*, tenant_id: str, scan_id: str, reason: str) -> ScanStatus:
    """Mark the scan cancelled if it is still in a non-terminal state."""
    try:
        async with async_session_factory() as session:
            await set_session_tenant(session, tenant_id)
            scan_query = await session.execute(
                select(Scan).where(
                    cast(Scan.id, String) == scan_id,
                    cast(Scan.tenant_id, String) == tenant_id,
                )
            )
            scan = scan_query.scalar_one_or_none()
            if scan is None:
                raise ResourceNotFoundError(
                    f"Scan {scan_id!r} was not found in this tenant scope."
                )
            if (scan.status or "").lower() in _TERMINAL_STATUSES:
                _logger.info(
                    "mcp.scan.cancel.noop",
                    extra={
                        "scan_id": scan_id,
                        "current_status": scan.status,
                        "reason_len": len(reason),
                    },
                )
                return _coerce_scan_status(scan.status)

            await session.execute(
                update(Scan)
                .where(
                    cast(Scan.id, String) == scan_id,
                    cast(Scan.tenant_id, String) == tenant_id,
                )
                .values(status="cancelled", phase="cancelled")
            )
            await session.commit()
            _logger.info(
                "mcp.scan.cancel.committed",
                extra={"scan_id": scan_id, "reason_len": len(reason)},
            )
            return ScanStatus.CANCELLED
    except ResourceNotFoundError:
        raise
    except Exception as exc:
        _logger.exception(
            "mcp.scan.cancel_failed",
            extra={"scan_id": scan_id, "tenant_id": tenant_id},
        )
        raise UpstreamServiceError(
            "Failed to cancel the scan; please retry later."
        ) from exc


async def _severity_counts(
    session: AsyncSession, scan_id: str, tenant_id: str
) -> dict[str, int]:
    """Aggregate findings by severity for the scan."""
    rows = await session.execute(
        select(FindingModel.severity).where(
            cast(FindingModel.scan_id, String) == scan_id,
            cast(FindingModel.tenant_id, String) == tenant_id,
        )
    )
    counts: dict[str, int] = {}
    for severity in rows.scalars():
        if not severity:
            continue
        key = str(severity).lower()
        counts[key] = counts.get(key, 0) + 1
    return counts


def _extract_timestamps(scan: Scan) -> tuple[datetime | None, datetime | None]:
    started: datetime | None = None
    finished: datetime | None = None
    options = scan.options if isinstance(scan.options, Mapping) else None
    if options:
        candidate = options.get("started_at") if isinstance(options, dict) else None
        if isinstance(candidate, str):
            started = _parse_iso(candidate)
    created = getattr(scan, "created_at", None)
    if started is None and isinstance(created, datetime):
        started = created
    if (scan.status or "").lower() in _TERMINAL_STATUSES:
        finished = getattr(scan, "updated_at", None)
        if finished is None and started is not None:
            finished = started
    return started, finished


def _parse_iso(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


__all__ = [
    "ScanDispatcher",
    "cancel_scan",
    "enqueue_scan",
    "get_scan_status",
    "set_scan_dispatcher",
]
