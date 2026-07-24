"""Async persistence for Intruder attacks + per-request results (WB-P4b).

Tenant isolation is defence-in-depth: the session has
:func:`~src.db.session.set_session_tenant` applied (PostgreSQL RLS) and every
query additionally filters ``tenant_id`` explicitly. User-editable attack
definitions use optimistic locking on ``version``; runner-owned progress
(counters / checkpoint / status) is written without a version bump because it
is not concurrently edited by operators.

Per-request rows are metadata-only (:class:`~src.db.models_web_workbench.
WbIntruderRequest`): no raw request/response bodies are stored inline here (the
attack is high-volume). ``payload_label``/``payload_index`` are *references*
into the signed payload set — never the raw payload value — so an unapproved
payload can never be reconstructed from a result row.

Execution itself is NOT performed here — the mandatory scope/preflight gate
lives in :class:`~src.web_workbench.intruder.service.IntruderService`, which
calls :meth:`IntruderRepository.record_request` to persist each outcome
(forwarded or blocked). This keeps the gate on the send path.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_web_workbench import (
    WbIntruderAttack,
    WbIntruderRequest,
    WebWorkbenchProject,
)

# -- attack lifecycle statuses (kill switch = cancelled) ---------------------
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_PAUSED = "paused"
STATUS_COMPLETED = "completed"
STATUS_CANCELLED = "cancelled"
STATUS_FAILED = "failed"

#: Statuses from which no further requests may be forwarded (terminal or held).
TERMINAL_STATUSES = frozenset({STATUS_COMPLETED, STATUS_CANCELLED, STATUS_FAILED})


class IntruderRepositoryError(Exception):
    """Base class for intruder repository errors."""


class ProjectNotFoundError(IntruderRepositoryError):
    """Target project does not exist for this tenant."""


class AttackNotFoundError(IntruderRepositoryError):
    """Requested attack does not exist for this tenant."""


class AttackNameConflictError(IntruderRepositoryError):
    """An attack with the same name already exists in the project."""


class OptimisticLockError(IntruderRepositoryError):
    """The update's ``expected_version`` did not match the persisted row."""


@dataclass(frozen=True)
class IntruderAttackDTO:
    """Projection of a persisted Intruder attack.

    ``raw_request_template`` is the byte-exact base request with position
    markers (source of truth for generation/replay); it is exposed to the
    runner but never logged.
    """

    id: str
    tenant_id: str
    project_id: str
    name: str
    attack_type: str
    status: str
    raw_request_template: bytes
    positions: list[dict[str, int]] | None
    payload_config: dict[str, Any] | None
    config: dict[str, Any] | None
    checkpoint: dict[str, Any] | None
    requests_total: int
    requests_completed: int
    findings_total: int
    error_reason: str | None
    version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class IntruderRequestDTO:
    """Metadata-only projection of one recorded attack request."""

    id: str
    tenant_id: str
    project_id: str
    attack_id: str
    request_index: int
    payload_label: str | None
    payload_index: int | None
    forward_outcome: str
    block_reason: str | None
    status_code: int | None
    response_length: int | None
    response_time_ms: int | None
    response_sha256: str | None
    flagged: bool
    error_reason: str | None
    created_at: datetime


def _attack_to_dto(row: WbIntruderAttack) -> IntruderAttackDTO:
    return IntruderAttackDTO(
        id=row.id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        name=row.name,
        attack_type=row.attack_type,
        status=row.status,
        raw_request_template=row.raw_request_template,
        positions=row.positions,
        payload_config=row.payload_config,
        config=row.config,
        checkpoint=row.checkpoint,
        requests_total=row.requests_total,
        requests_completed=row.requests_completed,
        findings_total=row.findings_total,
        error_reason=row.error_reason,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _request_to_dto(row: WbIntruderRequest) -> IntruderRequestDTO:
    return IntruderRequestDTO(
        id=row.id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        attack_id=row.attack_id,
        request_index=row.request_index,
        payload_label=row.payload_label,
        payload_index=row.payload_index,
        forward_outcome=row.forward_outcome,
        block_reason=row.block_reason,
        status_code=row.status_code,
        response_length=row.response_length,
        response_time_ms=row.response_time_ms,
        response_sha256=row.response_sha256,
        flagged=row.flagged,
        error_reason=row.error_reason,
        created_at=row.created_at,
    )


class IntruderRepository:
    """Async CRUD for intruder attacks + append/read of per-request results."""

    async def _project_exists(self, session: AsyncSession, tenant_id: str, project_id: str) -> bool:
        result = await session.execute(
            select(WebWorkbenchProject.id).where(
                WebWorkbenchProject.tenant_id == tenant_id,
                WebWorkbenchProject.id == project_id,
            )
        )
        return result.scalars().first() is not None

    async def _get_attack_row(
        self, session: AsyncSession, tenant_id: str, attack_id: str
    ) -> WbIntruderAttack | None:
        result = await session.execute(
            select(WbIntruderAttack).where(
                WbIntruderAttack.tenant_id == tenant_id,
                WbIntruderAttack.id == attack_id,
            )
        )
        return result.scalars().first()

    # -- attacks -------------------------------------------------------------

    async def create_attack(
        self,
        session: AsyncSession,
        tenant_id: str,
        project_id: str,
        *,
        name: str,
        attack_type: str,
        raw_request_template: bytes,
        positions: list[dict[str, int]] | None = None,
        payload_config: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
        created_by_subject_hash: str | None = None,
    ) -> IntruderAttackDTO:
        if not await self._project_exists(session, tenant_id, project_id):
            raise ProjectNotFoundError(project_id)
        row = WbIntruderAttack(
            tenant_id=tenant_id,
            project_id=project_id,
            name=name,
            attack_type=attack_type,
            status=STATUS_QUEUED,
            raw_request_template=raw_request_template,
            positions=positions,
            payload_config=payload_config,
            config=config,
            created_by_subject_hash=created_by_subject_hash,
            version=1,
        )
        session.add(row)
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise AttackNameConflictError(name) from exc
        await session.refresh(row)
        return _attack_to_dto(row)

    async def get_attack(
        self, session: AsyncSession, tenant_id: str, attack_id: str
    ) -> IntruderAttackDTO | None:
        row = await self._get_attack_row(session, tenant_id, attack_id)
        return _attack_to_dto(row) if row is not None else None

    async def list_attacks(
        self, session: AsyncSession, tenant_id: str, project_id: str
    ) -> list[IntruderAttackDTO]:
        result = await session.execute(
            select(WbIntruderAttack)
            .where(
                WbIntruderAttack.tenant_id == tenant_id,
                WbIntruderAttack.project_id == project_id,
            )
            .order_by(WbIntruderAttack.created_at, WbIntruderAttack.id)
        )
        return [_attack_to_dto(r) for r in result.scalars().all()]

    async def read_status(
        self, session: AsyncSession, tenant_id: str, attack_id: str
    ) -> str | None:
        """Return the current status only (for control polling), or ``None``."""
        result = await session.execute(
            select(WbIntruderAttack.status).where(
                WbIntruderAttack.tenant_id == tenant_id,
                WbIntruderAttack.id == attack_id,
            )
        )
        return result.scalars().first()

    async def set_status(
        self,
        session: AsyncSession,
        tenant_id: str,
        attack_id: str,
        status: str,
        *,
        expected_version: int,
    ) -> IntruderAttackDTO:
        """User-driven status transition with optimistic locking (e.g. cancel)."""
        row = await self._get_attack_row(session, tenant_id, attack_id)
        if row is None:
            raise AttackNotFoundError(attack_id)
        if row.version != expected_version:
            raise OptimisticLockError(attack_id)
        row.status = status
        row.version = row.version + 1
        await session.flush()
        await session.refresh(row)
        return _attack_to_dto(row)

    async def save_progress(
        self,
        session: AsyncSession,
        tenant_id: str,
        attack_id: str,
        *,
        status: str | None = None,
        requests_total: int | None = None,
        requests_completed: int | None = None,
        findings_total: int | None = None,
        checkpoint: dict[str, Any] | None = None,
        error_reason: str | None = None,
    ) -> IntruderAttackDTO:
        """Runner-owned progress write (no version bump — not user-edited).

        Only the supplied fields are updated; ``checkpoint`` is replaced whole.
        """
        row = await self._get_attack_row(session, tenant_id, attack_id)
        if row is None:
            raise AttackNotFoundError(attack_id)
        if status is not None:
            row.status = status
        if requests_total is not None:
            row.requests_total = requests_total
        if requests_completed is not None:
            row.requests_completed = requests_completed
        if findings_total is not None:
            row.findings_total = findings_total
        if checkpoint is not None:
            row.checkpoint = checkpoint
        if error_reason is not None:
            row.error_reason = error_reason
        await session.flush()
        await session.refresh(row)
        return _attack_to_dto(row)

    # -- per-request results -------------------------------------------------

    async def record_request(
        self,
        session: AsyncSession,
        tenant_id: str,
        *,
        project_id: str,
        attack_id: str,
        request_index: int,
        forward_outcome: str,
        payload_label: str | None = None,
        payload_index: int | None = None,
        block_reason: str | None = None,
        status_code: int | None = None,
        response_length: int | None = None,
        response_time_ms: int | None = None,
        response_sha256: str | None = None,
        flagged: bool = False,
        error_reason: str | None = None,
    ) -> IntruderRequestDTO:
        """Append one recorded request outcome (forwarded, blocked or errored)."""
        row = WbIntruderRequest(
            tenant_id=tenant_id,
            project_id=project_id,
            attack_id=attack_id,
            request_index=request_index,
            payload_label=payload_label,
            payload_index=payload_index,
            forward_outcome=forward_outcome,
            block_reason=block_reason,
            status_code=status_code,
            response_length=response_length,
            response_time_ms=response_time_ms,
            response_sha256=response_sha256,
            flagged=flagged,
            error_reason=error_reason,
        )
        session.add(row)
        await session.flush()
        await session.refresh(row)
        return _request_to_dto(row)

    async def list_requests(
        self,
        session: AsyncSession,
        tenant_id: str,
        attack_id: str,
        *,
        flagged_only: bool = False,
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[list[IntruderRequestDTO], int]:
        filters = [
            WbIntruderRequest.tenant_id == tenant_id,
            WbIntruderRequest.attack_id == attack_id,
        ]
        if flagged_only:
            filters.append(WbIntruderRequest.flagged.is_(True))
        total_result = await session.execute(
            select(func.count()).select_from(WbIntruderRequest).where(*filters)
        )
        total = int(total_result.scalar_one())
        result = await session.execute(
            select(WbIntruderRequest)
            .where(*filters)
            .order_by(WbIntruderRequest.request_index)
            .offset(offset)
            .limit(limit)
        )
        items = [_request_to_dto(r) for r in result.scalars().all()]
        return items, total

    async def list_flagged(
        self, session: AsyncSession, tenant_id: str, attack_id: str
    ) -> list[IntruderRequestDTO]:
        """Return every flagged (interesting) request for finding bridging."""
        items, _ = await self.list_requests(
            session, tenant_id, attack_id, flagged_only=True, offset=0, limit=10_000
        )
        return items

    async def count_recorded(self, session: AsyncSession, tenant_id: str, attack_id: str) -> int:
        """Number of already-recorded requests (used to resume idempotently)."""
        result = await session.execute(
            select(func.count())
            .select_from(WbIntruderRequest)
            .where(
                WbIntruderRequest.tenant_id == tenant_id,
                WbIntruderRequest.attack_id == attack_id,
            )
        )
        return int(result.scalar_one())


__all__ = [
    "STATUS_CANCELLED",
    "STATUS_COMPLETED",
    "STATUS_FAILED",
    "STATUS_PAUSED",
    "STATUS_QUEUED",
    "STATUS_RUNNING",
    "TERMINAL_STATUSES",
    "AttackNameConflictError",
    "AttackNotFoundError",
    "IntruderAttackDTO",
    "IntruderRepository",
    "IntruderRepositoryError",
    "IntruderRequestDTO",
    "OptimisticLockError",
    "ProjectNotFoundError",
]
