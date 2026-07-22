"""Web Workbench Organizer endpoints — collections + items (WB-P3c).

Versioned under ``/api/v1/wb`` (contract in ``docs/api-contracts.md``). Every
request is tenant-scoped (RLS via ``set_session_tenant`` + explicit filters).
Writes use optimistic locking. Saved raw bytes travel as base64 and are returned
only by the single-item GET. Errors never leak internals.
"""

from __future__ import annotations

import base64
import binascii
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.routers.web_workbench.projects import tenant_session
from src.web_workbench.contracts.organizer import (
    OrganizerCollectionCreate,
    OrganizerCollectionDTO,
    OrganizerCollectionUpdate,
    OrganizerItemCreate,
    OrganizerItemDTO,
    OrganizerItemListResponse,
    OrganizerItemUpdate,
)
from src.web_workbench.organizer.repository import (
    CollectionNameConflictError,
    CollectionNotFoundError,
    ItemNotFoundError,
    OptimisticLockError,
    OrganizerRepository,
    ProjectNotFoundError,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/wb", tags=["web-workbench-organizer"])

_repository = OrganizerRepository()

_Ctx = Annotated[tuple[AsyncSession, str], Depends(tenant_session)]


def _decode_b64(value: str | None, field: str) -> bytes | None:
    if value is None:
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"{field} is not valid base64") from exc


# -- collections -------------------------------------------------------------


@router.post(
    "/projects/{project_id}/organizer/collections",
    response_model=OrganizerCollectionDTO,
    status_code=201,
)
async def create_collection(
    project_id: str, body: OrganizerCollectionCreate, ctx: _Ctx
) -> OrganizerCollectionDTO:
    session, tenant_id = ctx
    try:
        return await _repository.create_collection(session, tenant_id, project_id, body)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    except CollectionNameConflictError as exc:
        raise HTTPException(status_code=409, detail="collection name already exists") from exc


@router.get(
    "/projects/{project_id}/organizer/collections",
    response_model=list[OrganizerCollectionDTO],
)
async def list_collections(project_id: str, ctx: _Ctx) -> list[OrganizerCollectionDTO]:
    session, tenant_id = ctx
    return await _repository.list_collections(session, tenant_id, project_id)


@router.get("/organizer/collections/{collection_id}", response_model=OrganizerCollectionDTO)
async def get_collection(collection_id: str, ctx: _Ctx) -> OrganizerCollectionDTO:
    session, tenant_id = ctx
    collection = await _repository.get_collection(session, tenant_id, collection_id)
    if collection is None:
        raise HTTPException(status_code=404, detail="collection not found")
    return collection


@router.patch("/organizer/collections/{collection_id}", response_model=OrganizerCollectionDTO)
async def update_collection(
    collection_id: str, body: OrganizerCollectionUpdate, ctx: _Ctx
) -> OrganizerCollectionDTO:
    session, tenant_id = ctx
    try:
        return await _repository.update_collection(session, tenant_id, collection_id, body)
    except CollectionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="collection not found") from exc
    except OptimisticLockError as exc:
        raise HTTPException(status_code=409, detail="version conflict; reload and retry") from exc
    except CollectionNameConflictError as exc:
        raise HTTPException(status_code=409, detail="collection name already exists") from exc


@router.delete("/organizer/collections/{collection_id}", status_code=204)
async def delete_collection(collection_id: str, ctx: _Ctx) -> None:
    session, tenant_id = ctx
    try:
        await _repository.delete_collection(session, tenant_id, collection_id)
    except CollectionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="collection not found") from exc


# -- items -------------------------------------------------------------------


@router.post(
    "/organizer/collections/{collection_id}/items",
    response_model=OrganizerItemDTO,
    status_code=201,
)
async def create_item(collection_id: str, body: OrganizerItemCreate, ctx: _Ctx) -> OrganizerItemDTO:
    session, tenant_id = ctx
    raw_request = _decode_b64(body.raw_request_base64, "raw_request_base64")
    raw_response = _decode_b64(body.raw_response_base64, "raw_response_base64")
    try:
        return await _repository.create_item(
            session,
            tenant_id,
            collection_id,
            body,
            raw_request=raw_request,
            raw_response=raw_response,
        )
    except CollectionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="collection not found") from exc


@router.get("/projects/{project_id}/organizer/items", response_model=OrganizerItemListResponse)
async def list_items(
    project_id: str,
    ctx: _Ctx,
    collection_id: str | None = Query(None, max_length=36),
    host: str | None = Query(None, max_length=255),
    tag: str | None = Query(None, max_length=64),
    q: str | None = Query(None, max_length=256),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> OrganizerItemListResponse:
    session, tenant_id = ctx
    items, total = await _repository.list_items(
        session,
        tenant_id,
        project_id,
        collection_id=collection_id,
        host=host,
        tag=tag,
        query=q,
        offset=offset,
        limit=limit,
    )
    return OrganizerItemListResponse(items=tuple(items), total=total, offset=offset, limit=limit)


@router.get("/organizer/items/{item_id}", response_model=OrganizerItemDTO)
async def get_item(item_id: str, ctx: _Ctx) -> OrganizerItemDTO:
    session, tenant_id = ctx
    item = await _repository.get_item(session, tenant_id, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="item not found")
    return item


@router.patch("/organizer/items/{item_id}", response_model=OrganizerItemDTO)
async def update_item(item_id: str, body: OrganizerItemUpdate, ctx: _Ctx) -> OrganizerItemDTO:
    session, tenant_id = ctx
    try:
        return await _repository.update_item(session, tenant_id, item_id, body)
    except ItemNotFoundError as exc:
        raise HTTPException(status_code=404, detail="item not found") from exc
    except OptimisticLockError as exc:
        raise HTTPException(status_code=409, detail="version conflict; reload and retry") from exc


@router.delete("/organizer/items/{item_id}", status_code=204)
async def delete_item(item_id: str, ctx: _Ctx) -> None:
    session, tenant_id = ctx
    try:
        await _repository.delete_item(session, tenant_id, item_id)
    except ItemNotFoundError as exc:
        raise HTTPException(status_code=404, detail="item not found") from exc


__all__ = ["router"]
