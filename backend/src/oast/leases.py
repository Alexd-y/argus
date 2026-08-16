"""OAST lease persistence and service layer (Stage E).

Wraps the existing :mod:`src.oast.provisioner` without modifying its contracts.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Final
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictStr, model_validator
from typing_extensions import Self

from src.oast.correlator import InteractionKind, OASTInteraction as CorrelatorInteraction
from src.oast.provisioner import (
    InternalOASTProvisioner,
    OASTProvisioner,
    OASTToken,
    OASTUnavailableError,
)

_logger = logging.getLogger(__name__)

_DEFAULT_LEASE_TTL: Final[timedelta] = timedelta(minutes=30)


class OastLeaseStatus(StrEnum):
    """Lifecycle status for a scan-bound OAST lease."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class OastLease(BaseModel):
    """Scan-scoped OAST lease backed by a provisioner token."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(min_length=1, max_length=36)
    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    engagement_id: StrictStr = Field(min_length=1, max_length=36)
    scan_id: StrictStr = Field(min_length=1, max_length=36)
    token_id: StrictStr = Field(min_length=1, max_length=36)
    subdomain: StrictStr
    path_token: StrictStr
    status: OastLeaseStatus = OastLeaseStatus.ACTIVE
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None

    @model_validator(mode="after")
    def _validate_times(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("lease timestamps must be timezone-aware")
        return self

    @classmethod
    def from_token(
        cls,
        *,
        lease_id: str,
        engagement_id: str,
        token: OASTToken,
    ) -> OastLease:
        return cls(
            id=lease_id,
            tenant_id=str(token.tenant_id),
            engagement_id=engagement_id,
            scan_id=str(token.scan_id),
            token_id=str(token.id),
            subdomain=token.subdomain,
            path_token=token.path_token,
            issued_at=token.created_at,
            expires_at=token.expires_at,
        )


class OastInteraction(BaseModel):
    """Persisted OAST interaction correlated to a lease."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(min_length=1, max_length=36)
    lease_id: StrictStr = Field(min_length=1, max_length=36)
    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    token_id: StrictStr = Field(min_length=1, max_length=36)
    kind: InteractionKind
    received_at: datetime
    source_ip: StrictStr
    raw_request_hash: StrictStr = Field(min_length=64, max_length=64)
    metadata: dict[StrictStr, StrictStr] = Field(default_factory=dict)

    @classmethod
    def from_correlator(
        cls,
        *,
        lease_id: str,
        tenant_id: str,
        interaction: CorrelatorInteraction,
    ) -> OastInteraction:
        return cls(
            id=str(interaction.id),
            lease_id=lease_id,
            tenant_id=tenant_id,
            token_id=str(interaction.token_id),
            kind=interaction.kind,
            received_at=interaction.received_at,
            source_ip=interaction.source_ip,
            raw_request_hash=interaction.raw_request_hash,
            metadata=dict(interaction.metadata),
        )


class OastLeaseService:
    """Issue leases via the provisioner and record correlated interactions."""

    def __init__(self, provisioner: OASTProvisioner) -> None:
        self._provisioner = provisioner
        self._leases: dict[str, OastLease] = {}
        self._interactions: dict[str, list[OastInteraction]] = {}

    @property
    def provisioner(self) -> OASTProvisioner:
        return self._provisioner

    def issue_lease(
        self,
        *,
        tenant_id: str,
        engagement_id: str,
        scan_id: str,
        validation_job_id: str | None = None,
        family: str | None = None,
        ttl: timedelta = _DEFAULT_LEASE_TTL,
        lease_id: str | None = None,
    ) -> OastLease:
        token = self._provisioner.issue(
            tenant_id=_parse_uuid(tenant_id, field="tenant_id"),
            scan_id=_parse_uuid(scan_id, field="scan_id"),
            validation_job_id=(
                _parse_uuid(validation_job_id, field="validation_job_id")
                if validation_job_id
                else None
            ),
            family=family,
            ttl=ttl,
        )
        lease = OastLease.from_token(
            lease_id=lease_id or str(uuid4()),
            engagement_id=engagement_id,
            token=token,
        )
        self._leases[lease.id] = lease
        self._interactions.setdefault(lease.id, [])
        _logger.info(
            "oast.lease.issued",
            extra={
                "lease_id": lease.id,
                "tenant_id": lease.tenant_id,
                "scan_id": lease.scan_id,
                "token_id": lease.token_id,
            },
        )
        return lease

    def get_lease(self, lease_id: str) -> OastLease | None:
        lease = self._leases.get(lease_id)
        if lease is None:
            return None
        return self._refresh_status(lease)

    def revoke_lease(self, lease_id: str) -> OastLease:
        lease = self._leases.get(lease_id)
        if lease is None:
            raise KeyError(f"unknown oast lease: {lease_id}")
        self._provisioner.revoke(UUID(lease.token_id))
        revoked = lease.model_copy(
            update={
                "status": OastLeaseStatus.REVOKED,
                "revoked_at": datetime.now(tz=timezone.utc),
            }
        )
        self._leases[lease_id] = revoked
        return revoked

    def record_interaction(
        self,
        *,
        lease_id: str,
        interaction: CorrelatorInteraction | OastInteraction,
    ) -> OastInteraction:
        lease = self._leases.get(lease_id)
        if lease is None:
            raise KeyError(f"unknown oast lease: {lease_id}")
        if isinstance(interaction, OastInteraction):
            stored = interaction
        else:
            stored = OastInteraction.from_correlator(
                lease_id=lease_id,
                tenant_id=lease.tenant_id,
                interaction=interaction,
            )
        if stored.tenant_id != lease.tenant_id:
            raise ValueError("interaction tenant does not match lease tenant")
        bucket = self._interactions.setdefault(lease_id, [])
        if not any(existing.id == stored.id for existing in bucket):
            bucket.append(stored)
        return stored

    def list_interactions(self, lease_id: str) -> tuple[OastInteraction, ...]:
        return tuple(self._interactions.get(lease_id, ()))

    def _refresh_status(self, lease: OastLease) -> OastLease:
        now = datetime.now(tz=timezone.utc)
        if lease.status is OastLeaseStatus.REVOKED:
            return lease
        if now >= lease.expires_at:
            expired = lease.model_copy(update={"status": OastLeaseStatus.EXPIRED})
            self._leases[lease.id] = expired
            return expired
        if not self._provisioner.is_active(UUID(lease.token_id)):
            expired = lease.model_copy(update={"status": OastLeaseStatus.EXPIRED})
            self._leases[lease.id] = expired
            return expired
        return lease


def _parse_uuid(value: str, *, field: str) -> UUID:
    try:
        return UUID(str(value).strip())
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid UUID") from exc


def build_default_oast_lease_service(
    *,
    base_domain: str = "oast.argus.local",
) -> OastLeaseService:
    """Construct an in-memory lease service for development/tests."""
    try:
        provisioner: OASTProvisioner = InternalOASTProvisioner(base_domain=base_domain)
    except Exception as exc:
        raise OASTUnavailableError("failed to initialize internal OAST provisioner") from exc
    return OastLeaseService(provisioner)


__all__ = [
    "OastInteraction",
    "OastLease",
    "OastLeaseService",
    "OastLeaseStatus",
    "build_default_oast_lease_service",
]
