"""Lab execution lease — one-shot boundary verification then allow-all."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

from src.execution_mode.lab_scope import LabScopeManifest
from src.execution_mode.mode import ExecutionMode


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class LabLeaseStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    KILL_SWITCHED = "kill_switched"


class PolicyDecisionLab(BaseModel):
    """Allow-all policy outcome for verified LAB lease (master prompt §2.5)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: Literal["allow", "deny"] = "allow"
    requires_approval: StrictBool = False
    allowed_tools: Literal["*"] | tuple[str, ...] = "*"
    allowed_actions: Literal["*"] | tuple[str, ...] = "*"
    allowed_protocols: Literal["*"] | tuple[str, ...] = "*"
    allowed_payloads: Literal["*"] | tuple[str, ...] = "*"
    budget: Literal["unlimited"] | dict[str, Any] = "unlimited"
    reason: StrictStr = "verified_lab_unrestricted"
    deny_code: StrictStr | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"


LAB_ALLOW_ALL: Final[PolicyDecisionLab] = PolicyDecisionLab()


class LabExecutionLease(BaseModel):
    """Execution lease issued after boundary verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    lease_id: StrictStr = Field(default_factory=lambda: str(uuid4()), min_length=1, max_length=36)
    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    engagement_id: StrictStr = Field(min_length=1, max_length=36)
    manifest_id: StrictStr = Field(min_length=1, max_length=36)
    mode: ExecutionMode = ExecutionMode.LAB_UNRESTRICTED
    status: LabLeaseStatus = LabLeaseStatus.ACTIVE
    issued_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime
    capture_full: StrictBool = False
    k8s_namespace: StrictStr | None = None
    vm_network_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    boundary_proof: StrictStr = Field(min_length=1, max_length=128)
    kill_switch_cleared: StrictBool = True
    policy: PolicyDecisionLab = LAB_ALLOW_ALL

    def is_usable(self, *, now: datetime | None = None) -> bool:
        ref = now or _utcnow()
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=UTC)
        if self.status is not LabLeaseStatus.ACTIVE:
            return False
        if not self.kill_switch_cleared:
            return False
        return ref < self.expires_at

    def revoke(self, *, reason: LabLeaseStatus = LabLeaseStatus.REVOKED) -> LabExecutionLease:
        if reason is LabLeaseStatus.ACTIVE:
            raise ValueError("cannot_revoke_to_active")
        return self.model_copy(update={"status": reason})

    def to_storage_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_storage_dict(cls, raw: dict[str, Any]) -> LabExecutionLease:
        return cls.model_validate(raw)


class LabLeaseService:
    """Create and validate LAB leases from verified manifests."""

    DEFAULT_TTL = timedelta(hours=8)

    def issue(
        self,
        manifest: LabScopeManifest,
        *,
        boundary_proof: str,
        kill_switch_cleared: bool = True,
        ttl: timedelta | None = None,
        now: datetime | None = None,
    ) -> LabExecutionLease:
        ref = now or _utcnow()
        if manifest.mode is not ExecutionMode.LAB_UNRESTRICTED:
            raise ValueError("lease_requires_lab_unrestricted_manifest")
        if manifest.is_expired(now=ref):
            raise ValueError("lab_scope_manifest_expired")
        if not kill_switch_cleared:
            raise ValueError("lab_lease_kill_switch_active")
        if not boundary_proof:
            raise ValueError("lab_lease_missing_boundary_proof")

        lease_ttl = ttl or self.DEFAULT_TTL
        expires = min(manifest.expires_at, ref + lease_ttl)
        return LabExecutionLease(
            tenant_id=manifest.tenant_id,
            engagement_id=manifest.engagement_id,
            manifest_id=manifest.manifest_id,
            expires_at=expires,
            capture_full=manifest.capture_full,
            k8s_namespace=manifest.k8s_namespace,
            vm_network_ids=manifest.vm_network_ids,
            boundary_proof=boundary_proof,
            kill_switch_cleared=kill_switch_cleared,
            policy=LAB_ALLOW_ALL,
        )

    def decision_for_lease(self, lease: LabExecutionLease | None) -> PolicyDecisionLab:
        """Return allow-all for usable lease; deny otherwise."""
        if lease is None or not lease.is_usable():
            return PolicyDecisionLab(
                outcome="deny",
                requires_approval=True,
                allowed_tools=(),
                allowed_actions=(),
                allowed_protocols=(),
                allowed_payloads=(),
                budget={},
                reason="lab_lease_invalid_or_expired",
                deny_code="DENY_LAB_LEASE",
            )
        return LAB_ALLOW_ALL
