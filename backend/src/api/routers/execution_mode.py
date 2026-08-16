"""API — engagement execution mode + LAB scope/lease."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr
from sqlalchemy.exc import IntegrityError

from src.execution_mode.boundary_verifier import LabBoundaryVerifier
from src.execution_mode.lab_lease import LabExecutionLease, LabLeaseService
from src.execution_mode.lab_scope import LabScopeManifest
from src.execution_mode.mode import (
    ExecutionMode,
    ExecutionModeImmutableError,
    assert_mode_immutable,
    parse_execution_mode,
)
from src.execution_mode.repository import (
    InMemoryExecutionModeRepository,
    get_execution_mode_repository,
    set_execution_mode_repository,
    strip_lease_storage_meta,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/engagements", tags=["execution-mode"])


class SetExecutionModeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: StrictStr
    force_before_execution: StrictBool = False


class LabScopeCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_ids: list[StrictStr] = Field(default_factory=list)
    cidrs: list[StrictStr] = Field(default_factory=list)
    dns_suffixes: list[StrictStr] = Field(default_factory=list)
    k8s_namespace: StrictStr | None = None
    vm_network_ids: list[StrictStr] = Field(default_factory=list)
    internet_attached: StrictBool = False
    capture_full: StrictBool = True
    resource_limits: dict[str, Any] | None = None
    expires_in_hours: int = Field(default=8, ge=1, le=168)
    signing_secret: StrictStr | None = None


class LabLeaseCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: StrictStr = Field(min_length=1, max_length=2048)
    asset_id: StrictStr | None = None
    k8s_namespace: StrictStr | None = None
    vm_network_id: StrictStr | None = None
    kill_switch_cleared: StrictBool = True


def _tenant_from_header(x_tenant_id: str | None = Header(default=None, alias="X-Tenant-Id")) -> str:
    if not x_tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="tenant_required")
    return x_tenant_id


def _lease_from_payload(payload: dict[str, Any]) -> LabExecutionLease | None:
    try:
        fields = set(LabExecutionLease.model_fields)
        cleaned = {k: v for k, v in strip_lease_storage_meta(payload).items() if k in fields}
        return LabExecutionLease.from_storage_dict(cleaned)
    except (TypeError, ValueError, KeyError):
        logger.warning(
            "lab_lease_lookup_invalid",
            extra={"event": "lab_lease_lookup_invalid"},
        )
        return None


def _http_not_found_from_integrity(_exc: IntegrityError) -> HTTPException:
    logger.warning(
        "execution_mode_fk_missing",
        extra={"event": "execution_mode_fk_missing"},
    )
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")


async def lookup_usable_lease(lease_id: str | None) -> LabExecutionLease | None:
    """Return an active, unexpired lease or None. Used by LAB mutating APIs."""
    if not lease_id:
        return None
    repo = get_execution_mode_repository()
    payload = await repo.get_lease_by_idempotency_key(lease_id)
    if not isinstance(payload, dict):
        return None
    lease = _lease_from_payload(payload)
    if lease is None or not lease.is_usable():
        return None
    return lease


@router.get("/{engagement_id}/execution-mode")
async def get_execution_mode(
    engagement_id: str,
    tenant_id: str = Depends(_tenant_from_header),
) -> dict[str, Any]:
    repo = get_execution_mode_repository()
    row = await repo.get_execution_mode(tenant_id=tenant_id, engagement_id=engagement_id)
    if row is None:
        return {
            "engagement_id": engagement_id,
            "tenant_id": tenant_id,
            "mode": ExecutionMode.PRODUCTION.value,
            "first_execution_at": None,
        }
    if row["tenant_id"] != tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
    return row


@router.post("/{engagement_id}/execution-mode")
async def set_execution_mode(
    engagement_id: str,
    body: SetExecutionModeRequest,
    tenant_id: str = Depends(_tenant_from_header),
) -> dict[str, Any]:
    repo = get_execution_mode_repository()
    existing = await repo.get_execution_mode(tenant_id=tenant_id, engagement_id=engagement_id)
    current = parse_execution_mode(existing["mode"] if existing else None)
    has_started = bool(existing and existing.get("first_execution_at"))
    try:
        mode = assert_mode_immutable(
            current,
            body.mode,
            has_started_execution=has_started and not body.force_before_execution,
        )
    except ExecutionModeImmutableError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    try:
        return await repo.upsert_execution_mode(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            mode=mode.value,
            first_execution_at=existing.get("first_execution_at") if existing else None,
        )
    except IntegrityError as exc:
        raise _http_not_found_from_integrity(exc) from exc


@router.post("/{engagement_id}/lab-scope", status_code=status.HTTP_201_CREATED)
async def create_lab_scope(
    engagement_id: str,
    body: LabScopeCreateRequest,
    tenant_id: str = Depends(_tenant_from_header),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
) -> dict[str, Any]:
    repo = get_execution_mode_repository()
    mode_row = await repo.get_execution_mode(tenant_id=tenant_id, engagement_id=engagement_id)
    mode = parse_execution_mode(mode_row["mode"] if mode_row else ExecutionMode.LAB_UNRESTRICTED)
    if mode is not ExecutionMode.LAB_UNRESTRICTED:
        if mode_row and mode_row.get("first_execution_at"):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="cannot_attach_lab_scope_to_started_production_engagement",
            )
        try:
            mode_row = await repo.upsert_execution_mode(
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                mode=ExecutionMode.LAB_UNRESTRICTED.value,
                first_execution_at=None,
            )
        except IntegrityError as exc:
            raise _http_not_found_from_integrity(exc) from exc

    expires_at = datetime.now(tz=UTC) + timedelta(hours=body.expires_in_hours)
    manifest = LabScopeManifest(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        asset_ids=tuple(body.asset_ids),
        cidrs=tuple(body.cidrs),
        dns_suffixes=tuple(body.dns_suffixes),
        k8s_namespace=body.k8s_namespace,
        vm_network_ids=tuple(body.vm_network_ids),
        internet_attached=body.internet_attached,
        capture_full=body.capture_full,
        resource_limits=body.resource_limits,
        expires_at=expires_at,
        created_by=x_user_id or "system",
    )
    if body.signing_secret:
        manifest = manifest.sign(body.signing_secret)

    try:
        await repo.save_manifest(manifest)
    except IntegrityError as exc:
        raise _http_not_found_from_integrity(exc) from exc
    logger.info(
        "lab_scope_created",
        extra={
            "event": "lab_scope_created",
            "manifest_id": manifest.manifest_id,
            "engagement_id": engagement_id,
            "tenant_id": tenant_id,
        },
    )
    return manifest.to_storage_dict()


@router.post("/{engagement_id}/lab-lease", status_code=status.HTTP_201_CREATED)
async def create_lab_lease(
    engagement_id: str,
    body: LabLeaseCreateRequest,
    tenant_id: str = Depends(_tenant_from_header),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> dict[str, Any]:
    repo = get_execution_mode_repository()
    if idempotency_key:
        cached = await repo.get_lease_by_idempotency_key(idempotency_key)
        if isinstance(cached, dict):
            response = strip_lease_storage_meta(cached)
            response["trace_id"] = str(uuid4())
            return response

    manifests = await repo.list_active_manifests(tenant_id=tenant_id, engagement_id=engagement_id)
    if not manifests:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="lab_scope_not_found")
    manifest = max(manifests, key=lambda m: m.created_at)

    verdict = LabBoundaryVerifier().verify(
        body.target,
        manifest,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        asset_id=body.asset_id,
        k8s_namespace=body.k8s_namespace or manifest.k8s_namespace,
        vm_network_id=body.vm_network_id,
    )
    if not verdict.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "deny_code": verdict.deny_code or "DENY_OUTSIDE_LAB",
                "reason": verdict.reason,
            },
        )

    try:
        lease = LabLeaseService().issue(
            manifest,
            boundary_proof=verdict.proof,
            kill_switch_cleared=body.kill_switch_cleared,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    payload = lease.to_storage_dict()
    if idempotency_key:
        payload["_idempotency_key"] = idempotency_key
    try:
        await repo.save_lease(lease.lease_id, payload)
    except IntegrityError as exc:
        raise _http_not_found_from_integrity(exc) from exc
    logger.info(
        "lab_lease_issued",
        extra={
            "event": "lab_lease_issued",
            "lease_id": lease.lease_id,
            "engagement_id": engagement_id,
            "tenant_id": tenant_id,
            "requires_approval": False,
        },
    )
    response = strip_lease_storage_meta(payload)
    response["trace_id"] = str(uuid4())
    return response


def _reset_stores_for_tests() -> None:
    """Isolate API contract tests with a fresh in-memory repository."""
    set_execution_mode_repository(InMemoryExecutionModeRepository())
