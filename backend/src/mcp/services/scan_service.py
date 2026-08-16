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
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import String, cast, desc, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.datetime_format import format_created_at_iso_z
from src.db.models import Finding as FindingModel
from src.db.models import Scan, Target, Tenant
from src.db.session import async_session_factory, set_session_tenant
from src.execution_mode.mode import ExecutionMode
from src.mcp.exceptions import (
    ResourceNotFoundError,
    UpstreamServiceError,
    ValidationError,
)
from src.mcp.schemas.scan import (
    ScanCoverageResult,
    ScanCreateInput,
    ScanCreateResult,
    ScanPlanResult,
    ScanProfile,
    ScanScopeInput,
    ScanStatus,
    ScanStatusResult,
)
from src.orchestration.coverage_phase_sink import snapshot_coverage_dicts
from src.orchestration.execution_mode_context import is_lab_lease_active_from_options
from src.policy.scan_queue import try_pick_queued_scan
from src.quick.cancellation import propagate_scan_cancellation
from src.quick.create import (
    PLAN_NOT_APPLICABLE,
    QuickCreateError,
    assert_execution_mode_payload,
    overlay_quick_options,
    parse_requested_execution_mode,
    persist_quick_rows,
    resolve_quick_runtime,
)
from src.quick.models import QuickScanPlanRow
from src.quick.resolver import UnknownQuickProfileError

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
        from src.tasks.scan_tasks import (
            scan_phase_task,  # type: ignore[import-not-found]
        )
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


def lab_lease_skips_deep_justification(
    scan_options: dict[str, Any] | None,
    *,
    tenant_id: str | None = None,
) -> bool:
    """True when a usable LAB lease is present — DEEP justification is not required."""
    return is_lab_lease_active_from_options(scan_options, tenant_id=tenant_id)


def _mcp_quick_error(exc: QuickCreateError | UnknownQuickProfileError) -> ValidationError:
    code = getattr(exc, "code", "mcp_validation_error")
    return ValidationError(str(exc) if str(exc) else code, code=code)


def _resolve_create_execution_mode(payload: ScanCreateInput) -> ExecutionMode:
    nested = None
    if isinstance(payload.scan_options, dict):
        nested = payload.scan_options.get("execution_mode")
    typed = payload.execution_mode
    if typed and nested and str(typed).strip().lower() != str(nested).strip().lower():
        raise ValidationError(
            "execution_mode conflicts with scan_options.execution_mode",
            code="conflicting_execution_mode",
        )
    raw = typed or nested
    try:
        return parse_requested_execution_mode(str(raw) if raw is not None else None)
    except QuickCreateError as exc:
        raise _mcp_quick_error(exc) from exc


def _quick_payload_from_create(payload: ScanCreateInput) -> dict[str, Any] | None:
    if payload.quick is not None:
        return payload.quick.model_dump(exclude_none=True)
    if isinstance(payload.scan_options, dict):
        nested = payload.scan_options.get("quick")
        if isinstance(nested, dict):
            return dict(nested)
    return None


async def enqueue_scan(
    *,
    tenant_id: str,
    user_id: str,
    payload: ScanCreateInput,
) -> ScanCreateResult:
    """Persist a scan row and notify the dispatcher.

    Tenant isolation: the row is written with ``tenant_id`` and the session
    has ``set_session_tenant`` applied so RLS rules see the correct GUC.
    Quick execution mode never inherits lab_unrestricted options and cannot
    bypass the feature flag, scope, policy, or budget path.
    """
    if not tenant_id:
        raise ValidationError("tenant_id is required to enqueue a scan.")

    execution_mode = _resolve_create_execution_mode(payload)
    quick_payload = _quick_payload_from_create(payload)
    try:
        assert_execution_mode_payload(
            execution_mode,
            has_quick_payload=quick_payload is not None,
        )
    except QuickCreateError as exc:
        raise _mcp_quick_error(exc) from exc

    scan_id = str(uuid.uuid4())
    options = _scope_to_options(payload.scope)
    if isinstance(payload.scan_options, dict):
        options.update(payload.scan_options)
    options["mcp_actor"] = "mcp_client"
    options["mcp_user_id"] = user_id

    scan_mode = _profile_to_scan_mode(payload.profile)
    deadline_at = None
    quick_profile = None
    quick_config = None
    quick_budget = None
    if execution_mode is ExecutionMode.QUICK:
        scan_mode = ScanProfile.QUICK.value
        started_at = datetime.now(UTC)
        try:
            quick_config, quick_budget, deadline_at = resolve_quick_runtime(
                tenant_id=tenant_id,
                quick_payload=quick_payload,
                started_at=started_at,
            )
        except UnknownQuickProfileError as exc:
            raise _mcp_quick_error(exc) from exc
        except QuickCreateError as exc:
            raise _mcp_quick_error(exc) from exc
        quick_profile = quick_config.profile.value
        options = overlay_quick_options(
            options,
            config=quick_config,
            budget=quick_budget,
            deadline_at=deadline_at,
        )
    elif execution_mode is not ExecutionMode.PRODUCTION:
        options["execution_mode"] = execution_mode.value

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
                scan_mode=scan_mode,
                execution_mode=execution_mode.value,
                deadline_at=deadline_at,
                quick_profile=quick_profile,
            )
            session.add(scan_row)
            if quick_config is not None and quick_budget is not None and deadline_at is not None:
                persist_quick_rows(
                    session,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    config=quick_config,
                    budget=quick_budget,
                    deadline_at=deadline_at,
                )
            await session.commit()
    except ValidationError:
        raise
    except Exception as exc:
        _logger.exception(
            "mcp.scan.enqueue_failed",
            extra={"tenant_id": tenant_id, "target": payload.target},
        )
        raise UpstreamServiceError(
            "Failed to persist the scan row; please retry later."
        ) from exc

    await try_pick_queued_scan(tenant_id)

    lab_ok = lab_lease_skips_deep_justification(options, tenant_id=tenant_id)
    requires_approval = (
        payload.profile is ScanProfile.DEEP
        and not bool(payload.justification)
        and not lab_ok
        and execution_mode is not ExecutionMode.QUICK
    )
    return ScanCreateResult(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        target=payload.target,
        profile=payload.profile,
        execution_mode=execution_mode.value,
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
            try:
                await propagate_scan_cancellation(
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    reason=reason,
                    session=session,
                )
            except Exception:  # noqa: BLE001 — MCP cancel is committed; revoke is best-effort
                _logger.warning(
                    "mcp.scan.cancel_revoke_failed",
                    extra={"scan_id": scan_id, "tenant_id": tenant_id},
                )
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
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


async def get_scan_plan(*, tenant_id: str, scan_id: str) -> ScanPlanResult:
    """Return the latest Quick plan. Non-quick scans raise plan_not_applicable."""
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
            mode = str(getattr(scan, "execution_mode", None) or ExecutionMode.PRODUCTION.value)
            if mode != ExecutionMode.QUICK.value:
                raise ResourceNotFoundError(
                    "plan_not_applicable",
                    code=PLAN_NOT_APPLICABLE,
                )
            plan_query = await session.execute(
                select(QuickScanPlanRow)
                .where(
                    cast(QuickScanPlanRow.scan_id, String) == scan_id,
                    cast(QuickScanPlanRow.tenant_id, String) == tenant_id,
                )
                .order_by(desc(QuickScanPlanRow.plan_version))
                .limit(1)
            )
            plan_row = plan_query.scalar_one_or_none()
            profile = str(getattr(scan, "quick_profile", None) or "balanced")
            if plan_row is None:
                options = scan.options if isinstance(scan.options, dict) else {}
                budget = options.get("quick_budget") if isinstance(options.get("quick_budget"), dict) else {}
                return ScanPlanResult(
                    scan_id=scan_id,
                    mode="quick",
                    profile=profile,
                    plan_version=0,
                    deadline_at=format_created_at_iso_z(getattr(scan, "deadline_at", None)),
                    budget=dict(budget) if isinstance(budget, dict) else {},
                    stages=("discovery", "fingerprint", "test", "verify", "triage", "report"),
                    tasks=(),
                    coverage_intent=(),
                    assumptions=("awaiting_fingerprint",),
                )
            budget = plan_row.budget if isinstance(plan_row.budget, dict) else {}
            stages = tuple(plan_row.stages) if isinstance(plan_row.stages, list) else ()
            tasks = tuple(plan_row.tasks) if isinstance(plan_row.tasks, list) else ()
            coverage = (
                tuple(plan_row.coverage_intent)
                if isinstance(plan_row.coverage_intent, list)
                else ()
            )
            assumptions = (
                tuple(plan_row.assumptions) if isinstance(plan_row.assumptions, list) else ()
            )
            return ScanPlanResult(
                scan_id=scan_id,
                mode="quick",
                profile=profile,
                plan_version=int(plan_row.plan_version),
                deadline_at=format_created_at_iso_z(plan_row.deadline_at),
                budget=dict(budget),
                stages=stages,
                tasks=tasks,
                coverage_intent=coverage,
                assumptions=assumptions,
            )
    except ResourceNotFoundError:
        raise
    except Exception as exc:
        _logger.exception(
            "mcp.scan.plan_failed",
            extra={"scan_id": scan_id, "tenant_id": tenant_id},
        )
        raise UpstreamServiceError(
            "Failed to read scan plan; please retry later."
        ) from exc


async def get_scan_coverage(*, tenant_id: str, scan_id: str) -> ScanCoverageResult:
    """Return coverage results with reason_code. Tenant-scoped."""
    try:
        async with async_session_factory() as session:
            await set_session_tenant(session, tenant_id)
            scan_query = await session.execute(
                select(Scan).where(
                    cast(Scan.id, String) == scan_id,
                    cast(Scan.tenant_id, String) == tenant_id,
                )
            )
            if scan_query.scalar_one_or_none() is None:
                raise ResourceNotFoundError(
                    f"Scan {scan_id!r} was not found in this tenant scope."
                )
        raw = snapshot_coverage_dicts(scan_id)
        results: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            row = dict(item)
            row.setdefault("reason_code", None)
            results.append(row)
        return ScanCoverageResult(scan_id=scan_id, results=tuple(results))
    except ResourceNotFoundError:
        raise
    except Exception as exc:
        _logger.exception(
            "mcp.scan.coverage_failed",
            extra={"scan_id": scan_id, "tenant_id": tenant_id},
        )
        raise UpstreamServiceError(
            "Failed to read scan coverage; please retry later."
        ) from exc


__all__ = [
    "ScanDispatcher",
    "cancel_scan",
    "enqueue_scan",
    "get_scan_coverage",
    "get_scan_plan",
    "get_scan_status",
    "lab_lease_skips_deep_justification",
    "set_scan_dispatcher",
]
