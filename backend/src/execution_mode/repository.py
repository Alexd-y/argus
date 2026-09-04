"""Persistence for execution mode, LAB manifests, and leases."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.db.session import async_session_factory, set_session_tenant
from src.execution_mode.lab_lease import LabExecutionLease, LabLeaseStatus
from src.execution_mode.lab_scope import LabScopeManifest
from src.execution_mode.mode import ExecutionMode
from src.execution_mode.models import (
    EngagementExecutionModeRow,
    LabExecutionLeaseRow,
    LabScopeManifestRow,
)


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _mode_row_to_api(row: EngagementExecutionModeRow) -> dict[str, Any]:
    return {
        "engagement_id": row.engagement_id,
        "tenant_id": row.tenant_id,
        "mode": row.mode,
        "first_execution_at": row.first_execution_at,
    }


def _manifest_row_to_domain(row: LabScopeManifestRow) -> LabScopeManifest:
    payload = dict(row.payload)
    payload["manifest_id"] = row.id
    if row.signature is not None:
        payload["signature"] = row.signature
    if "capture_full" not in payload:
        payload["capture_full"] = row.capture_full
    if "expires_at" not in payload:
        payload["expires_at"] = row.expires_at
    if "created_by" not in payload:
        payload["created_by"] = row.created_by
    return LabScopeManifest.from_storage_dict(payload)


def _manifest_to_row(manifest: LabScopeManifest) -> LabScopeManifestRow:
    storage = manifest.to_storage_dict()
    signature = storage.pop("signature", None)
    storage.pop("manifest_id", None)
    return LabScopeManifestRow(
        id=manifest.manifest_id,
        tenant_id=manifest.tenant_id,
        engagement_id=manifest.engagement_id,
        mode=manifest.mode.value,
        payload=storage,
        signature=signature,
        capture_full=manifest.capture_full,
        expires_at=manifest.expires_at,
        created_by=manifest.created_by,
        created_at=manifest.created_at,
    )


def _lease_to_row(lease: LabExecutionLease, payload: dict[str, Any]) -> LabExecutionLeaseRow:
    return LabExecutionLeaseRow(
        id=lease.lease_id,
        tenant_id=lease.tenant_id,
        engagement_id=lease.engagement_id,
        manifest_id=lease.manifest_id,
        mode=lease.mode.value,
        status=lease.status.value,
        boundary_proof=lease.boundary_proof,
        capture_full=lease.capture_full,
        k8s_namespace=lease.k8s_namespace,
        payload=payload,
        issued_at=lease.issued_at,
        expires_at=lease.expires_at,
    )


@runtime_checkable
class ExecutionModeRepository(Protocol):
    """Persistence contract for execution mode + LAB scope/lease."""

    async def get_execution_mode(
        self, *, tenant_id: str, engagement_id: str
    ) -> dict[str, Any] | None: ...

    async def upsert_execution_mode(
        self,
        *,
        tenant_id: str,
        engagement_id: str,
        mode: str,
        first_execution_at: datetime | None = None,
    ) -> dict[str, Any]: ...

    async def mark_first_execution(
        self, *, tenant_id: str, engagement_id: str
    ) -> dict[str, Any]: ...

    async def save_manifest(self, manifest: LabScopeManifest) -> None: ...

    async def list_active_manifests(
        self, *, tenant_id: str, engagement_id: str
    ) -> list[LabScopeManifest]: ...

    async def get_lease_by_idempotency_key(self, key: str) -> dict[str, Any] | None: ...

    async def save_lease(self, key: str, payload: dict[str, Any]) -> None: ...

    async def revoke_active_lab_leases_for_tenant(self, tenant_id: str) -> int: ...

    async def revoke_all_active_lab_leases(self) -> int: ...

    async def reset(self) -> None: ...


_LEASE_NON_DOMAIN_KEYS: frozenset[str] = frozenset({"_idempotency_key", "trace_id"})


def strip_lease_storage_meta(payload: dict[str, Any]) -> dict[str, Any]:
    """Drop repository-only / response-only keys before domain parse or API return."""
    cleaned = dict(payload)
    for key in _LEASE_NON_DOMAIN_KEYS:
        cleaned.pop(key, None)
    return cleaned


def lease_payload_for_domain(payload: dict[str, Any]) -> dict[str, Any]:
    """Keep only ``LabExecutionLease`` fields so extra=forbid validation succeeds."""
    fields = set(LabExecutionLease.model_fields)
    return {k: v for k, v in strip_lease_storage_meta(payload).items() if k in fields}


def _lease_row_to_payload(row: LabExecutionLeaseRow) -> dict[str, Any]:
    payload = dict(row.payload or {})
    payload.setdefault("lease_id", row.id)
    payload.setdefault("tenant_id", row.tenant_id)
    payload.setdefault("engagement_id", row.engagement_id)
    payload.setdefault("manifest_id", row.manifest_id)
    payload.setdefault("mode", row.mode)
    payload.setdefault("status", row.status)
    payload.setdefault("boundary_proof", row.boundary_proof)
    payload.setdefault("capture_full", row.capture_full)
    payload.setdefault("k8s_namespace", row.k8s_namespace)
    if row.issued_at is not None:
        payload.setdefault("issued_at", row.issued_at)
    payload.setdefault("expires_at", row.expires_at)
    return payload


def _revoke_lease_payload(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Return updated lease payload when active; ``None`` when no revoke needed."""
    try:
        lease = LabExecutionLease.from_storage_dict(strip_lease_storage_meta(payload))
    except (TypeError, ValueError):
        return None
    if lease.status is not LabLeaseStatus.ACTIVE:
        return None
    revoked = lease.revoke(reason=LabLeaseStatus.KILL_SWITCHED)
    updated = revoked.to_storage_dict()
    if "_idempotency_key" in payload:
        updated["_idempotency_key"] = payload["_idempotency_key"]
    return updated


class InMemoryExecutionModeRepository:
    """In-memory repository for unit tests and API smoke without DB."""

    def __init__(self) -> None:
        self._modes: dict[str, dict[str, Any]] = {}
        self._manifests: dict[str, LabScopeManifest] = {}
        self._leases: dict[str, dict[str, Any]] = {}

    async def get_execution_mode(
        self, *, tenant_id: str, engagement_id: str
    ) -> dict[str, Any] | None:
        row = self._modes.get(engagement_id)
        if row is None or row["tenant_id"] != tenant_id:
            return None
        return dict(row)

    async def upsert_execution_mode(
        self,
        *,
        tenant_id: str,
        engagement_id: str,
        mode: str,
        first_execution_at: datetime | None = None,
    ) -> dict[str, Any]:
        existing = self._modes.get(engagement_id)
        row = {
            "engagement_id": engagement_id,
            "tenant_id": tenant_id,
            "mode": mode,
            "first_execution_at": (
                first_execution_at
                if first_execution_at is not None
                else (existing.get("first_execution_at") if existing else None)
            ),
        }
        self._modes[engagement_id] = row
        return dict(row)

    async def mark_first_execution(
        self, *, tenant_id: str, engagement_id: str
    ) -> dict[str, Any]:
        existing = await self.get_execution_mode(tenant_id=tenant_id, engagement_id=engagement_id)
        if existing and existing.get("first_execution_at"):
            return existing
        mode = existing["mode"] if existing else ExecutionMode.PRODUCTION.value
        return await self.upsert_execution_mode(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            mode=mode,
            first_execution_at=_utcnow(),
        )

    async def save_manifest(self, manifest: LabScopeManifest) -> None:
        self._manifests[manifest.manifest_id] = manifest

    async def list_active_manifests(
        self, *, tenant_id: str, engagement_id: str
    ) -> list[LabScopeManifest]:
        return [
            manifest
            for manifest in self._manifests.values()
            if manifest.engagement_id == engagement_id
            and manifest.tenant_id == tenant_id
            and not manifest.is_expired()
        ]

    async def get_lease_by_idempotency_key(self, key: str) -> dict[str, Any] | None:
        payload = self._leases.get(key)
        if payload is not None:
            return dict(payload)
        for candidate in self._leases.values():
            if candidate.get("_idempotency_key") == key or candidate.get("lease_id") == key:
                return dict(candidate)
        return None

    async def save_lease(self, key: str, payload: dict[str, Any]) -> None:
        stored = dict(payload)
        stored.pop("trace_id", None)
        lease = LabExecutionLease.from_storage_dict(lease_payload_for_domain(stored))
        if key != lease.lease_id:
            stored["_idempotency_key"] = key
        else:
            stored.setdefault("_idempotency_key", payload.get("_idempotency_key") or key)
        self._leases[lease.lease_id] = stored

    async def revoke_active_lab_leases_for_tenant(self, tenant_id: str) -> int:
        revoked_count = 0
        for key, payload in list(self._leases.items()):
            if payload.get("tenant_id") != tenant_id:
                continue
            updated = _revoke_lease_payload(payload)
            if updated is None:
                continue
            self._leases[key] = updated
            revoked_count += 1
        return revoked_count

    async def revoke_all_active_lab_leases(self) -> int:
        revoked_count = 0
        for key, payload in list(self._leases.items()):
            updated = _revoke_lease_payload(payload)
            if updated is None:
                continue
            self._leases[key] = updated
            revoked_count += 1
        return revoked_count

    async def reset(self) -> None:
        self._modes.clear()
        self._manifests.clear()
        self._leases.clear()


class SqlAlchemyExecutionModeRepository:
    """PostgreSQL/SQLite persistence via SQLAlchemy async session."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        self._session_factory = session_factory or async_session_factory

    async def get_execution_mode(
        self, *, tenant_id: str, engagement_id: str
    ) -> dict[str, Any] | None:
        async with self._session_factory() as session:
            await set_session_tenant(session, tenant_id)
            result = await session.execute(
                select(EngagementExecutionModeRow).where(
                    EngagementExecutionModeRow.engagement_id == engagement_id,
                    EngagementExecutionModeRow.tenant_id == tenant_id,
                )
            )
            row = result.scalar_one_or_none()
            if row is None:
                return None
            return _mode_row_to_api(row)

    async def upsert_execution_mode(
        self,
        *,
        tenant_id: str,
        engagement_id: str,
        mode: str,
        first_execution_at: datetime | None = None,
    ) -> dict[str, Any]:
        async with self._session_factory() as session:
            await set_session_tenant(session, tenant_id)
            result = await session.execute(
                select(EngagementExecutionModeRow).where(
                    EngagementExecutionModeRow.engagement_id == engagement_id,
                )
            )
            row = result.scalar_one_or_none()
            if row is None:
                row = EngagementExecutionModeRow(
                    engagement_id=engagement_id,
                    tenant_id=tenant_id,
                    mode=mode,
                    first_execution_at=first_execution_at,
                )
                session.add(row)
            else:
                row.tenant_id = tenant_id
                row.mode = mode
                if first_execution_at is not None:
                    row.first_execution_at = first_execution_at
            await session.commit()
            await session.refresh(row)
            return _mode_row_to_api(row)

    async def mark_first_execution(
        self, *, tenant_id: str, engagement_id: str
    ) -> dict[str, Any]:
        async with self._session_factory() as session:
            await set_session_tenant(session, tenant_id)
            result = await session.execute(
                select(EngagementExecutionModeRow).where(
                    EngagementExecutionModeRow.engagement_id == engagement_id,
                )
            )
            row = result.scalar_one_or_none()
            if row is None:
                row = EngagementExecutionModeRow(
                    engagement_id=engagement_id,
                    tenant_id=tenant_id,
                    mode=ExecutionMode.PRODUCTION.value,
                    first_execution_at=_utcnow(),
                )
                session.add(row)
            elif row.first_execution_at is None:
                row.first_execution_at = _utcnow()
            await session.commit()
            await session.refresh(row)
            return _mode_row_to_api(row)

    async def save_manifest(self, manifest: LabScopeManifest) -> None:
        async with self._session_factory() as session:
            await set_session_tenant(session, manifest.tenant_id)
            session.add(_manifest_to_row(manifest))
            await session.commit()

    async def list_active_manifests(
        self, *, tenant_id: str, engagement_id: str
    ) -> list[LabScopeManifest]:
        async with self._session_factory() as session:
            await set_session_tenant(session, tenant_id)
            result = await session.execute(
                select(LabScopeManifestRow).where(
                    LabScopeManifestRow.tenant_id == tenant_id,
                    LabScopeManifestRow.engagement_id == engagement_id,
                    LabScopeManifestRow.revoked_at.is_(None),
                )
            )
            manifests = [_manifest_row_to_domain(row) for row in result.scalars().all()]
            return [manifest for manifest in manifests if not manifest.is_expired()]

    async def get_lease_by_idempotency_key(self, key: str) -> dict[str, Any] | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(LabExecutionLeaseRow).where(LabExecutionLeaseRow.id == key)
            )
            row = result.scalar_one_or_none()
            if row is not None:
                return _lease_row_to_payload(row)
            result = await session.execute(select(LabExecutionLeaseRow))
            for candidate in result.scalars().all():
                payload = _lease_row_to_payload(candidate)
                if payload.get("_idempotency_key") == key or payload.get("lease_id") == key:
                    return payload
            return None

    async def save_lease(self, key: str, payload: dict[str, Any]) -> None:
        lease = LabExecutionLease.from_storage_dict(lease_payload_for_domain(payload))
        stored = dict(payload)
        stored.pop("trace_id", None)
        existing_idem = stored.get("_idempotency_key")
        if key != lease.lease_id or not existing_idem:
            stored["_idempotency_key"] = key
        async with self._session_factory() as session:
            await set_session_tenant(session, lease.tenant_id)
            result = await session.execute(
                select(LabExecutionLeaseRow).where(LabExecutionLeaseRow.id == lease.lease_id)
            )
            row = result.scalar_one_or_none()
            if row is None:
                session.add(_lease_to_row(lease, stored))
            else:
                row.status = lease.status.value
                row.payload = stored
                row.capture_full = lease.capture_full
                row.k8s_namespace = lease.k8s_namespace
                row.expires_at = lease.expires_at
                if lease.status is LabLeaseStatus.REVOKED or lease.status is LabLeaseStatus.KILL_SWITCHED:
                    row.revoked_at = row.revoked_at or _utcnow()
                    row.revoke_reason = lease.status.value
            await session.commit()

    async def revoke_active_lab_leases_for_tenant(self, tenant_id: str) -> int:
        async with self._session_factory() as session:
            await set_session_tenant(session, tenant_id)
            result = await session.execute(
                select(LabExecutionLeaseRow).where(
                    LabExecutionLeaseRow.tenant_id == tenant_id,
                    LabExecutionLeaseRow.status == LabLeaseStatus.ACTIVE.value,
                )
            )
            rows = list(result.scalars().all())
            revoked_count = 0
            for row in rows:
                payload = dict(row.payload or {})
                payload.setdefault("lease_id", row.id)
                payload.setdefault("tenant_id", row.tenant_id)
                payload.setdefault("engagement_id", row.engagement_id)
                payload.setdefault("manifest_id", row.manifest_id)
                payload.setdefault("status", row.status)
                updated = _revoke_lease_payload(payload)
                if updated is None:
                    continue
                row.status = LabLeaseStatus.KILL_SWITCHED.value
                row.payload = updated
                row.revoke_reason = LabLeaseStatus.KILL_SWITCHED.value
                row.revoked_at = _utcnow()
                revoked_count += 1
            if revoked_count:
                await session.commit()
            return revoked_count

    async def revoke_all_active_lab_leases(self) -> int:
        async with self._session_factory() as session:
            result = await session.execute(
                select(LabExecutionLeaseRow).where(
                    LabExecutionLeaseRow.status == LabLeaseStatus.ACTIVE.value,
                )
            )
            rows = list(result.scalars().all())
            revoked_count = 0
            for row in rows:
                await set_session_tenant(session, row.tenant_id)
                payload = dict(row.payload or {})
                payload.setdefault("lease_id", row.id)
                payload.setdefault("tenant_id", row.tenant_id)
                payload.setdefault("engagement_id", row.engagement_id)
                payload.setdefault("manifest_id", row.manifest_id)
                payload.setdefault("status", row.status)
                updated = _revoke_lease_payload(payload)
                if updated is None:
                    continue
                row.status = LabLeaseStatus.KILL_SWITCHED.value
                row.payload = updated
                row.revoke_reason = LabLeaseStatus.KILL_SWITCHED.value
                row.revoked_at = _utcnow()
                revoked_count += 1
            if revoked_count:
                await session.commit()
            return revoked_count

    async def reset(self) -> None:
        """No-op for DB-backed repository (tests use in-memory)."""


_default_repository: ExecutionModeRepository = SqlAlchemyExecutionModeRepository()


def get_execution_mode_repository() -> ExecutionModeRepository:
    return _default_repository


def set_execution_mode_repository(repo: ExecutionModeRepository) -> None:
    global _default_repository
    _default_repository = repo


async def load_lease_scope_storage(
    session: AsyncSession,
    *,
    tenant_id: str,
    lab_lease_id: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Load ``(lab_lease, lab_scope_manifest)`` storage dicts for scan options.

    The worker's phase preflight resolves the LAB lease ONLY from scan options
    (it is passed no DB ``lease_lookup``); a deep scan must therefore carry the
    serialized lease + manifest in its options, otherwise every phase fails
    closed with ``lab_lease_required``. ``session`` must already have the tenant
    bound. Returns ``(None, None)`` when the lease row is absent.
    """
    lease_row = (
        await session.execute(
            select(LabExecutionLeaseRow).where(
                LabExecutionLeaseRow.id == str(lab_lease_id),
                LabExecutionLeaseRow.tenant_id == str(tenant_id),
            )
        )
    ).scalar_one_or_none()
    if lease_row is None:
        return None, None

    lease_dict = LabExecutionLease.from_storage_dict(
        lease_payload_for_domain(_lease_row_to_payload(lease_row))
    ).to_storage_dict()

    manifest_dict: dict[str, Any] | None = None
    if lease_row.manifest_id:
        manifest_row = (
            await session.execute(
                select(LabScopeManifestRow).where(
                    LabScopeManifestRow.id == str(lease_row.manifest_id),
                    LabScopeManifestRow.tenant_id == str(tenant_id),
                )
            )
        ).scalar_one_or_none()
        if manifest_row is not None:
            manifest_dict = _manifest_row_to_domain(manifest_row).to_storage_dict()

    return lease_dict, manifest_dict


__all__ = [
    "ExecutionModeRepository",
    "InMemoryExecutionModeRepository",
    "SqlAlchemyExecutionModeRepository",
    "get_execution_mode_repository",
    "lease_payload_for_domain",
    "load_lease_scope_storage",
    "set_execution_mode_repository",
    "strip_lease_storage_meta",
]
