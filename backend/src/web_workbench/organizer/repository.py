"""Async persistence for the Organizer — collections + items (WB-P3c).

Tenant isolation is enforced two ways (defence-in-depth): the session has
``set_session_tenant`` applied (PostgreSQL RLS) and every query additionally
filters ``tenant_id`` explicitly. Concurrent edits use optimistic locking on
``version``. Saved raw bytes are stored verbatim (byte-exact) and never logged.
"""

from __future__ import annotations

import base64

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_web_workbench import (
    WbOrganizerCollection,
    WbOrganizerItem,
    WebWorkbenchProject,
)
from src.web_workbench.contracts.organizer import (
    OrganizerCollectionCreate,
    OrganizerCollectionDTO,
    OrganizerCollectionUpdate,
    OrganizerItemCreate,
    OrganizerItemDTO,
    OrganizerItemUpdate,
)


class OrganizerRepositoryError(Exception):
    """Base class for organizer repository errors."""


class ProjectNotFoundError(OrganizerRepositoryError):
    """Target project does not exist for this tenant."""


class CollectionNotFoundError(OrganizerRepositoryError):
    """Requested collection does not exist for this tenant."""


class CollectionNameConflictError(OrganizerRepositoryError):
    """A collection with the same name already exists in the project."""


class ItemNotFoundError(OrganizerRepositoryError):
    """Requested item does not exist for this tenant."""


class OptimisticLockError(OrganizerRepositoryError):
    """The update's ``expected_version`` did not match the persisted row."""


def _collection_to_dto(row: WbOrganizerCollection) -> OrganizerCollectionDTO:
    return OrganizerCollectionDTO(
        id=row.id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        name=row.name,
        description=row.description,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _item_to_dto(row: WbOrganizerItem, *, include_raw: bool) -> OrganizerItemDTO:
    def _b64(value: bytes | None) -> str | None:
        if not include_raw or value is None:
            return None
        return base64.b64encode(value).decode("ascii")

    return OrganizerItemDTO(
        id=row.id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        collection_id=row.collection_id,
        title=row.title,
        method=row.method,
        host=row.host,
        url=row.url,
        notes=row.notes,
        tags=tuple(row.tags or ()),
        has_raw_request=row.raw_request is not None,
        has_raw_response=row.raw_response is not None,
        raw_request_base64=_b64(row.raw_request),
        raw_response_base64=_b64(row.raw_response),
        source_message_id=row.source_message_id,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class OrganizerRepository:
    """Async CRUD + search for organizer collections and items."""

    # -- collections ---------------------------------------------------------

    async def _project_exists(self, session: AsyncSession, tenant_id: str, project_id: str) -> bool:
        result = await session.execute(
            select(WebWorkbenchProject.id).where(
                WebWorkbenchProject.tenant_id == tenant_id,
                WebWorkbenchProject.id == project_id,
            )
        )
        return result.scalars().first() is not None

    async def create_collection(
        self,
        session: AsyncSession,
        tenant_id: str,
        project_id: str,
        data: OrganizerCollectionCreate,
    ) -> OrganizerCollectionDTO:
        if not await self._project_exists(session, tenant_id, project_id):
            raise ProjectNotFoundError(project_id)
        row = WbOrganizerCollection(
            tenant_id=tenant_id,
            project_id=project_id,
            name=data.name,
            description=data.description,
            version=1,
        )
        session.add(row)
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise CollectionNameConflictError(data.name) from exc
        await session.refresh(row)
        return _collection_to_dto(row)

    async def list_collections(
        self, session: AsyncSession, tenant_id: str, project_id: str
    ) -> list[OrganizerCollectionDTO]:
        result = await session.execute(
            select(WbOrganizerCollection)
            .where(
                WbOrganizerCollection.tenant_id == tenant_id,
                WbOrganizerCollection.project_id == project_id,
            )
            .order_by(WbOrganizerCollection.created_at, WbOrganizerCollection.id)
        )
        return [_collection_to_dto(r) for r in result.scalars().all()]

    async def _get_collection_row(
        self, session: AsyncSession, tenant_id: str, collection_id: str
    ) -> WbOrganizerCollection | None:
        result = await session.execute(
            select(WbOrganizerCollection).where(
                WbOrganizerCollection.tenant_id == tenant_id,
                WbOrganizerCollection.id == collection_id,
            )
        )
        return result.scalars().first()

    async def get_collection(
        self, session: AsyncSession, tenant_id: str, collection_id: str
    ) -> OrganizerCollectionDTO | None:
        row = await self._get_collection_row(session, tenant_id, collection_id)
        return _collection_to_dto(row) if row is not None else None

    async def update_collection(
        self,
        session: AsyncSession,
        tenant_id: str,
        collection_id: str,
        data: OrganizerCollectionUpdate,
    ) -> OrganizerCollectionDTO:
        row = await self._get_collection_row(session, tenant_id, collection_id)
        if row is None:
            raise CollectionNotFoundError(collection_id)
        if row.version != data.expected_version:
            raise OptimisticLockError(collection_id)
        if data.name is not None:
            row.name = data.name
        if data.description is not None:
            row.description = data.description
        row.version = row.version + 1
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise CollectionNameConflictError(data.name or collection_id) from exc
        await session.refresh(row)
        return _collection_to_dto(row)

    async def delete_collection(
        self, session: AsyncSession, tenant_id: str, collection_id: str
    ) -> None:
        row = await self._get_collection_row(session, tenant_id, collection_id)
        if row is None:
            raise CollectionNotFoundError(collection_id)
        await session.delete(row)
        await session.flush()

    # -- items ---------------------------------------------------------------

    async def create_item(
        self,
        session: AsyncSession,
        tenant_id: str,
        collection_id: str,
        data: OrganizerItemCreate,
        *,
        raw_request: bytes | None,
        raw_response: bytes | None,
    ) -> OrganizerItemDTO:
        collection = await self._get_collection_row(session, tenant_id, collection_id)
        if collection is None:
            raise CollectionNotFoundError(collection_id)
        tags = list(data.normalized_tags())
        row = WbOrganizerItem(
            tenant_id=tenant_id,
            project_id=collection.project_id,
            collection_id=collection_id,
            title=data.title,
            method=data.method,
            host=data.host,
            url=data.url,
            notes=data.notes,
            tags=tags or None,
            raw_request=raw_request,
            raw_response=raw_response,
            source_message_id=data.source_message_id,
            version=1,
        )
        session.add(row)
        await session.flush()
        await session.refresh(row)
        return _item_to_dto(row, include_raw=True)

    async def list_items(
        self,
        session: AsyncSession,
        tenant_id: str,
        project_id: str,
        *,
        collection_id: str | None = None,
        host: str | None = None,
        tag: str | None = None,
        query: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[OrganizerItemDTO], int]:
        filters = [
            WbOrganizerItem.tenant_id == tenant_id,
            WbOrganizerItem.project_id == project_id,
        ]
        if collection_id is not None:
            filters.append(WbOrganizerItem.collection_id == collection_id)
        if host is not None:
            filters.append(WbOrganizerItem.host == host)
        if tag is not None:
            filters.append(WbOrganizerItem.tags.contains([tag]))
        if query:
            filters.append(WbOrganizerItem.title.ilike(f"%{query}%"))

        total_result = await session.execute(
            select(func.count()).select_from(WbOrganizerItem).where(*filters)
        )
        total = int(total_result.scalar_one())

        result = await session.execute(
            select(WbOrganizerItem)
            .where(*filters)
            .order_by(WbOrganizerItem.created_at.desc(), WbOrganizerItem.id)
            .offset(offset)
            .limit(limit)
        )
        items = [_item_to_dto(r, include_raw=False) for r in result.scalars().all()]
        return items, total

    async def _get_item_row(
        self, session: AsyncSession, tenant_id: str, item_id: str
    ) -> WbOrganizerItem | None:
        result = await session.execute(
            select(WbOrganizerItem).where(
                WbOrganizerItem.tenant_id == tenant_id,
                WbOrganizerItem.id == item_id,
            )
        )
        return result.scalars().first()

    async def get_item(
        self, session: AsyncSession, tenant_id: str, item_id: str
    ) -> OrganizerItemDTO | None:
        row = await self._get_item_row(session, tenant_id, item_id)
        return _item_to_dto(row, include_raw=True) if row is not None else None

    async def update_item(
        self,
        session: AsyncSession,
        tenant_id: str,
        item_id: str,
        data: OrganizerItemUpdate,
    ) -> OrganizerItemDTO:
        row = await self._get_item_row(session, tenant_id, item_id)
        if row is None:
            raise ItemNotFoundError(item_id)
        if row.version != data.expected_version:
            raise OptimisticLockError(item_id)
        if data.title is not None:
            row.title = data.title
        if data.notes is not None:
            row.notes = data.notes
        if data.tags is not None:
            seen: dict[str, None] = {}
            for tag in data.tags:
                trimmed = tag.strip()[:64]
                if trimmed:
                    seen.setdefault(trimmed, None)
            row.tags = list(seen) or None
        row.version = row.version + 1
        await session.flush()
        await session.refresh(row)
        return _item_to_dto(row, include_raw=True)

    async def delete_item(self, session: AsyncSession, tenant_id: str, item_id: str) -> None:
        row = await self._get_item_row(session, tenant_id, item_id)
        if row is None:
            raise ItemNotFoundError(item_id)
        await session.delete(row)
        await session.flush()


async def purge_project_organizer(session: AsyncSession, tenant_id: str, project_id: str) -> None:
    """Delete all organizer rows for a project (items cascade via collections)."""
    await session.execute(
        delete(WbOrganizerCollection).where(
            WbOrganizerCollection.tenant_id == tenant_id,
            WbOrganizerCollection.project_id == project_id,
        )
    )


__all__ = [
    "CollectionNameConflictError",
    "CollectionNotFoundError",
    "ItemNotFoundError",
    "OptimisticLockError",
    "OrganizerRepository",
    "OrganizerRepositoryError",
    "ProjectNotFoundError",
    "purge_project_organizer",
]
