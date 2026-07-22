"""Async persistence for the Repeater — tabs + replay exchanges (WB-P3b-2).

Tenant isolation is enforced two ways (defence-in-depth): the session has
``set_session_tenant`` applied (PostgreSQL RLS) and every query additionally
filters ``tenant_id`` explicitly. Tab edits use optimistic locking on
``version``. Raw request/response bytes are stored verbatim (byte-exact) and are
never logged.

Replay itself is NOT performed here — the router gates every replay through
:class:`~src.web_workbench.repeater.engine.RepeaterService` and then calls
:meth:`RepeaterRepository.record_exchange` to persist the outcome (forwarded or
blocked). This keeps the mandatory scope/preflight gate on the send path.
"""

from __future__ import annotations

import base64

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_web_workbench import (
    WbRepeaterExchange,
    WbRepeaterTab,
    WebWorkbenchProject,
)
from src.web_workbench.contracts.repeater import (
    RepeaterExchangeDTO,
    RepeaterTabCreate,
    RepeaterTabDTO,
    RepeaterTabUpdate,
)
from src.web_workbench.proxy.transport import HttpMessageError, NormalizedRequest
from src.web_workbench.repeater.engine import ReplayResult


class RepeaterRepositoryError(Exception):
    """Base class for repeater repository errors."""


class ProjectNotFoundError(RepeaterRepositoryError):
    """Target project does not exist for this tenant."""


class TabNotFoundError(RepeaterRepositoryError):
    """Requested tab does not exist for this tenant."""


class ExchangeNotFoundError(RepeaterRepositoryError):
    """Requested exchange does not exist for this tenant."""


class OptimisticLockError(RepeaterRepositoryError):
    """The update's ``expected_version`` did not match the persisted row."""


def _derive_target_metadata(raw_request: bytes) -> tuple[str | None, str | None, int | None]:
    """Best-effort scheme/host/port for display; ``None`` if unparseable."""
    try:
        request = NormalizedRequest.parse(raw_request)
        target, port = request.to_target_spec()
    except HttpMessageError:
        return None, None, None
    url = target.url or ""
    scheme = url.split("://", 1)[0] if "://" in url else None
    host = None
    if scheme is not None:
        rest = url.split("://", 1)[1]
        host = rest.split("/", 1)[0].split(":", 1)[0] or None
    return scheme, host, port


def _tab_to_dto(row: WbRepeaterTab) -> RepeaterTabDTO:
    return RepeaterTabDTO(
        id=row.id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        name=row.name,
        scheme=row.scheme,
        host=row.host,
        port=row.port,
        raw_request_base64=base64.b64encode(row.raw_request).decode("ascii"),
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _exchange_to_dto(row: WbRepeaterExchange, *, include_raw: bool) -> RepeaterExchangeDTO:
    def _b64(value: bytes | None) -> str | None:
        if not include_raw or value is None:
            return None
        return base64.b64encode(value).decode("ascii")

    return RepeaterExchangeDTO(
        id=row.id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        tab_id=row.tab_id,
        forward_outcome=row.forward_outcome,
        block_reason=row.block_reason,
        status_code=row.status_code,
        response_size=row.response_size,
        truncated=row.truncated,
        duration_ms=row.duration_ms,
        raw_request_base64=_b64(row.raw_request),
        raw_response_base64=_b64(row.raw_response),
        created_at=row.created_at,
    )


class RepeaterRepository:
    """Async CRUD for repeater tabs + append/read of replay exchanges."""

    # -- tabs ----------------------------------------------------------------

    async def _project_exists(self, session: AsyncSession, tenant_id: str, project_id: str) -> bool:
        result = await session.execute(
            select(WebWorkbenchProject.id).where(
                WebWorkbenchProject.tenant_id == tenant_id,
                WebWorkbenchProject.id == project_id,
            )
        )
        return result.scalars().first() is not None

    async def create_tab(
        self,
        session: AsyncSession,
        tenant_id: str,
        project_id: str,
        data: RepeaterTabCreate,
        *,
        raw_request: bytes,
    ) -> RepeaterTabDTO:
        if not await self._project_exists(session, tenant_id, project_id):
            raise ProjectNotFoundError(project_id)
        scheme, host, port = _derive_target_metadata(raw_request)
        row = WbRepeaterTab(
            tenant_id=tenant_id,
            project_id=project_id,
            name=data.name,
            raw_request=raw_request,
            scheme=scheme,
            host=host,
            port=port,
            version=1,
        )
        session.add(row)
        await session.flush()
        await session.refresh(row)
        return _tab_to_dto(row)

    async def list_tabs(
        self, session: AsyncSession, tenant_id: str, project_id: str
    ) -> list[RepeaterTabDTO]:
        result = await session.execute(
            select(WbRepeaterTab)
            .where(
                WbRepeaterTab.tenant_id == tenant_id,
                WbRepeaterTab.project_id == project_id,
            )
            .order_by(WbRepeaterTab.created_at, WbRepeaterTab.id)
        )
        return [_tab_to_dto(r) for r in result.scalars().all()]

    async def _get_tab_row(
        self, session: AsyncSession, tenant_id: str, tab_id: str
    ) -> WbRepeaterTab | None:
        result = await session.execute(
            select(WbRepeaterTab).where(
                WbRepeaterTab.tenant_id == tenant_id,
                WbRepeaterTab.id == tab_id,
            )
        )
        return result.scalars().first()

    async def get_tab(
        self, session: AsyncSession, tenant_id: str, tab_id: str
    ) -> RepeaterTabDTO | None:
        row = await self._get_tab_row(session, tenant_id, tab_id)
        return _tab_to_dto(row) if row is not None else None

    async def update_tab(
        self,
        session: AsyncSession,
        tenant_id: str,
        tab_id: str,
        data: RepeaterTabUpdate,
        *,
        raw_request: bytes | None,
    ) -> RepeaterTabDTO:
        row = await self._get_tab_row(session, tenant_id, tab_id)
        if row is None:
            raise TabNotFoundError(tab_id)
        if row.version != data.expected_version:
            raise OptimisticLockError(tab_id)
        if data.name is not None:
            row.name = data.name
        if raw_request is not None:
            row.raw_request = raw_request
            row.scheme, row.host, row.port = _derive_target_metadata(raw_request)
        row.version = row.version + 1
        await session.flush()
        await session.refresh(row)
        return _tab_to_dto(row)

    async def delete_tab(self, session: AsyncSession, tenant_id: str, tab_id: str) -> None:
        row = await self._get_tab_row(session, tenant_id, tab_id)
        if row is None:
            raise TabNotFoundError(tab_id)
        await session.delete(row)
        await session.flush()

    # -- exchanges -----------------------------------------------------------

    async def record_exchange(
        self,
        session: AsyncSession,
        tenant_id: str,
        *,
        project_id: str,
        tab_id: str,
        raw_request: bytes,
        result: ReplayResult,
    ) -> RepeaterExchangeDTO:
        response = result.response
        row = WbRepeaterExchange(
            tenant_id=tenant_id,
            project_id=project_id,
            tab_id=tab_id,
            raw_request=raw_request,
            forward_outcome=str(result.outcome.value),
            block_reason=result.reason,
            status_code=response.status_code if response is not None else None,
            raw_response=response.raw if response is not None else None,
            response_size=len(response.raw) if response is not None else 0,
            truncated=response.truncated if response is not None else False,
            duration_ms=response.duration_ms if response is not None else None,
        )
        session.add(row)
        await session.flush()
        await session.refresh(row)
        return _exchange_to_dto(row, include_raw=True)

    async def list_exchanges(
        self,
        session: AsyncSession,
        tenant_id: str,
        tab_id: str,
        *,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[RepeaterExchangeDTO], int]:
        filters = [
            WbRepeaterExchange.tenant_id == tenant_id,
            WbRepeaterExchange.tab_id == tab_id,
        ]
        total_result = await session.execute(
            select(func.count()).select_from(WbRepeaterExchange).where(*filters)
        )
        total = int(total_result.scalar_one())
        result = await session.execute(
            select(WbRepeaterExchange)
            .where(*filters)
            .order_by(WbRepeaterExchange.created_at.desc(), WbRepeaterExchange.id)
            .offset(offset)
            .limit(limit)
        )
        items = [_exchange_to_dto(r, include_raw=False) for r in result.scalars().all()]
        return items, total

    async def get_exchange(
        self, session: AsyncSession, tenant_id: str, exchange_id: str
    ) -> RepeaterExchangeDTO | None:
        result = await session.execute(
            select(WbRepeaterExchange).where(
                WbRepeaterExchange.tenant_id == tenant_id,
                WbRepeaterExchange.id == exchange_id,
            )
        )
        row = result.scalars().first()
        return _exchange_to_dto(row, include_raw=True) if row is not None else None


__all__ = [
    "ExchangeNotFoundError",
    "OptimisticLockError",
    "ProjectNotFoundError",
    "RepeaterRepository",
    "RepeaterRepositoryError",
    "TabNotFoundError",
]
