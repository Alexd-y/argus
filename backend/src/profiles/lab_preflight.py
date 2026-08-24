"""LAB lease preflight validation for the ``deep`` scan profile.

The pure core (:func:`evaluate_lab_lease`) works on plain view objects so it is
fully unit-testable without a database. :func:`preflight_lab_lease` is the
async DB-backed wrapper used by the API layer.

Order of checks (Design §7):
1. engagement_id present            → lab_engagement_required
2. lab_lease_id present             → lab_lease_required
3. lease exists                     → lab_lease_required
4. lease.tenant matches            → lab_lease_tenant_mismatch
5. lease.engagement matches        → lab_engagement_required
6. lease not revoked               → lab_lease_revoked
7. lease not expired               → lab_lease_expired
8. scope manifest present + valid  → lab_scope_required
9. target inside scope             → target_out_of_lab_scope
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlparse

from src.core.structured_events import (
    EVENT_LAB_LEASE_PREFLIGHT_ALLOWED,
    EVENT_LAB_LEASE_PREFLIGHT_DENIED,
    emit_event,
)
from src.profiles.errors import (
    LabEngagementRequiredError,
    LabLeaseError,
    LabLeaseExpiredError,
    LabLeaseRequiredError,
    LabLeaseRevokedError,
    LabLeaseTenantMismatchError,
    LabScopeRequiredError,
    TargetOutOfLabScopeError,
)

logger = logging.getLogger(__name__)

_REVOKED_STATUSES = frozenset({"revoked", "kill_switched"})


@dataclass(frozen=True, slots=True)
class LeaseView:
    """Minimal lease projection for scope/lease validation."""

    lease_id: str
    tenant_id: str
    engagement_id: str
    manifest_id: str
    status: str
    expires_at: datetime
    revoked_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ScopeView:
    """Minimal scope-manifest projection for target boundary validation."""

    manifest_id: str
    tenant_id: str
    engagement_id: str
    expires_at: datetime
    revoked_at: datetime | None = None
    asset_ids: tuple[str, ...] = field(default_factory=tuple)
    cidrs: tuple[str, ...] = field(default_factory=tuple)
    dns_suffixes: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class LabPreflightResult:
    """Outcome of a successful preflight — safe to persist on a checkpoint."""

    lease_id: str
    engagement_id: str
    manifest_id: str
    expires_at: datetime
    boundary_proof_present: bool = True


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _extract_host(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="")
    host = parsed.hostname or ""
    if host:
        return host.lower()
    # Fallback: strip path/port manually.
    cleaned = raw.split("/")[0].split(":")[0]
    return cleaned.lower()


def _host_matches_asset(host: str, target: str, asset_ids: tuple[str, ...]) -> bool:
    normalized_target = (target or "").strip().rstrip("/").lower()
    for asset in asset_ids:
        a = (asset or "").strip().lower()
        if not a:
            continue
        a_host = _extract_host(a)
        if host and a_host and host == a_host:
            return True
        if a in {host, normalized_target}:
            return True
    return False


def _host_matches_suffix(host: str, dns_suffixes: tuple[str, ...]) -> bool:
    for suffix in dns_suffixes:
        s = (suffix or "").strip().lstrip(".").lower()
        if not s:
            continue
        if host == s or host.endswith("." + s):
            return True
    return False


def _host_matches_cidr(host: str, cidrs: tuple[str, ...]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    for cidr in cidrs:
        c = (cidr or "").strip()
        if not c:
            continue
        try:
            if ip in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def target_in_scope(target: str, scope: ScopeView) -> bool:
    """Return True if ``target`` falls inside the LAB scope boundary."""
    host = _extract_host(target)
    if not host:
        return False
    return (
        _host_matches_asset(host, target, scope.asset_ids)
        or _host_matches_suffix(host, scope.dns_suffixes)
        or _host_matches_cidr(host, scope.cidrs)
    )


def _evaluate_lab_lease_core(
    *,
    tenant_id: str,
    engagement_id: str | None,
    lab_lease_id: str | None,
    target: str,
    lease: LeaseView | None,
    scope: ScopeView | None,
    now: datetime | None = None,
) -> LabPreflightResult:
    """Pure LAB lease/scope validation. Raises typed :class:`LabLeaseError`."""
    ref = _aware(now or datetime.now(UTC))

    if not engagement_id or not str(engagement_id).strip():
        raise LabEngagementRequiredError(
            "Deep profile requires an engagement_id",
            details={"required_action": "select_engagement"},
        )
    if not lab_lease_id or not str(lab_lease_id).strip():
        raise LabLeaseRequiredError(
            "Deep profile requires a valid lab_lease_id",
            details={
                "engagement_id": engagement_id,
                "required_action": "issue_or_select_lab_lease",
            },
        )
    if lease is None:
        raise LabLeaseRequiredError(
            "Lab lease not found",
            details={
                "engagement_id": engagement_id,
                "lab_lease_id": lab_lease_id,
                "required_action": "issue_or_select_lab_lease",
            },
        )
    if lease.tenant_id != tenant_id:
        raise LabLeaseTenantMismatchError(
            "Lab lease belongs to a different tenant",
            details={"lab_lease_id": lab_lease_id},
        )
    if lease.engagement_id != engagement_id:
        raise LabEngagementRequiredError(
            "Lab lease is not bound to the requested engagement",
            details={"engagement_id": engagement_id, "lab_lease_id": lab_lease_id},
        )
    if lease.revoked_at is not None or lease.status.strip().lower() in _REVOKED_STATUSES:
        raise LabLeaseRevokedError(
            "Lab lease has been revoked",
            details={"lab_lease_id": lab_lease_id},
        )
    if _aware(lease.expires_at) <= ref or lease.status.strip().lower() == "expired":
        raise LabLeaseExpiredError(
            "Lab lease has expired",
            details={"lab_lease_id": lab_lease_id, "expires_at": _aware(lease.expires_at).isoformat()},
        )
    if scope is None:
        raise LabScopeRequiredError(
            "Lab scope manifest is missing or invalid",
            details={"engagement_id": engagement_id, "manifest_id": lease.manifest_id},
        )
    if scope.revoked_at is not None or _aware(scope.expires_at) <= ref:
        raise LabScopeRequiredError(
            "Lab scope manifest has expired or been revoked",
            details={"engagement_id": engagement_id, "manifest_id": scope.manifest_id},
        )
    if not target_in_scope(target, scope):
        raise TargetOutOfLabScopeError(
            "Target is outside the authorized LAB scope",
            details={"target": target, "manifest_id": scope.manifest_id},
        )

    emit_event(
        EVENT_LAB_LEASE_PREFLIGHT_ALLOWED,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        scan_profile="deep",
        lab_lease_id=lab_lease_id,
    )
    return LabPreflightResult(
        lease_id=lease.lease_id,
        engagement_id=engagement_id,
        manifest_id=lease.manifest_id,
        expires_at=_aware(lease.expires_at),
    )


def evaluate_lab_lease(
    *,
    tenant_id: str,
    engagement_id: str | None,
    lab_lease_id: str | None,
    target: str,
    lease: LeaseView | None,
    scope: ScopeView | None,
    now: datetime | None = None,
) -> LabPreflightResult:
    """LAB lease/scope validation with a denied-event on any failure (R13)."""
    try:
        return _evaluate_lab_lease_core(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            lab_lease_id=lab_lease_id,
            target=target,
            lease=lease,
            scope=scope,
            now=now,
        )
    except LabLeaseError as exc:
        emit_event(
            EVENT_LAB_LEASE_PREFLIGHT_DENIED,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            scan_profile="deep",
            reason_code=exc.code,
            level=logging.WARNING,
        )
        raise


async def preflight_lab_lease(
    session,
    *,
    tenant_id: str,
    engagement_id: str | None,
    lab_lease_id: str | None,
    target: str,
    now: datetime | None = None,
) -> LabPreflightResult:
    """DB-backed LAB preflight. Fetches lease + scope rows, then validates.

    ``session`` is an ``AsyncSession`` with the tenant already set.
    """
    from sqlalchemy import String, cast, select

    from src.execution_mode.models import LabExecutionLeaseRow, LabScopeManifestRow

    # Early cheap checks before DB round-trips.
    if not engagement_id or not str(engagement_id).strip():
        raise LabEngagementRequiredError(
            "Deep profile requires an engagement_id",
            details={"required_action": "select_engagement"},
        )
    if not lab_lease_id or not str(lab_lease_id).strip():
        raise LabLeaseRequiredError(
            "Deep profile requires a valid lab_lease_id",
            details={"engagement_id": engagement_id, "required_action": "issue_or_select_lab_lease"},
        )

    lease_row = (
        await session.execute(
            select(LabExecutionLeaseRow).where(
                cast(LabExecutionLeaseRow.id, String) == str(lab_lease_id),
                cast(LabExecutionLeaseRow.tenant_id, String) == str(tenant_id),
            )
        )
    ).scalar_one_or_none()

    lease_view: LeaseView | None = None
    scope_view: ScopeView | None = None
    if lease_row is not None:
        lease_view = LeaseView(
            lease_id=lease_row.id,
            tenant_id=lease_row.tenant_id,
            engagement_id=lease_row.engagement_id,
            manifest_id=lease_row.manifest_id,
            status=lease_row.status,
            expires_at=lease_row.expires_at,
            revoked_at=lease_row.revoked_at,
        )
        scope_row = (
            await session.execute(
                select(LabScopeManifestRow).where(
                    cast(LabScopeManifestRow.id, String) == str(lease_row.manifest_id),
                    cast(LabScopeManifestRow.tenant_id, String) == str(tenant_id),
                )
            )
        ).scalar_one_or_none()
        if scope_row is not None:
            payload = scope_row.payload if isinstance(scope_row.payload, dict) else {}
            scope_view = ScopeView(
                manifest_id=scope_row.id,
                tenant_id=scope_row.tenant_id,
                engagement_id=scope_row.engagement_id,
                expires_at=scope_row.expires_at,
                revoked_at=scope_row.revoked_at,
                asset_ids=tuple(payload.get("asset_ids", []) or []),
                cidrs=tuple(payload.get("cidrs", []) or []),
                dns_suffixes=tuple(payload.get("dns_suffixes", []) or []),
            )

    return evaluate_lab_lease(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        lab_lease_id=lab_lease_id,
        target=target,
        lease=lease_view,
        scope=scope_view,
        now=now,
    )


__all__ = [
    "LabPreflightResult",
    "LeaseView",
    "ScopeView",
    "evaluate_lab_lease",
    "preflight_lab_lease",
    "target_in_scope",
]
