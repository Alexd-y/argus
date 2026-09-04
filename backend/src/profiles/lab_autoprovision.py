"""Server-side auto-provisioning of a target-scoped LAB lease for the deep profile.

Full Surface (``scan_profile=deep``) is self-service. Instead of requiring an
operator to pre-create an engagement + scope manifest + lab lease, the backend
provisions a minimal, **target-scoped** ``lab_unrestricted`` lease on demand when
a deep scan arrives without ``engagement_id``/``lab_lease_id``.

Safety properties:
- The scope manifest is bounded to the requested target host only (exact DNS name
  / IP), so aggressive exploitation stays confined to that target.
- The lease is short-lived (``DEEP_PROFILE_AUTOPROVISION_TTL_HOURS``) and is still
  validated by the normal :func:`preflight_lab_lease` path afterwards — this module
  never bypasses boundary verification, it only creates rows that pass it.

The engagement/manifest/lease rows are persisted through the DB-backed
``SqlAlchemyExecutionModeRepository`` (each in its own committed transaction), so
they are visible to the create-scan session's preflight read.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

from src.core.config import settings
from src.db.models import Tenant
from src.db.models_recon import Engagement
from src.db.session import async_session_factory, set_session_tenant
from src.execution_mode.boundary_verifier import LabBoundaryVerifier
from src.execution_mode.lab_lease import LabLeaseService
from src.execution_mode.lab_scope import LabScopeManifest
from src.execution_mode.mode import ExecutionMode
from src.execution_mode.repository import get_execution_mode_repository
from src.profiles.errors import LabScopeRequiredError

logger = logging.getLogger(__name__)

_CREATED_BY = "auto-provision"


def _extract_host(target: str) -> str:
    """Return the bare host (lowercased, no scheme/port/path) for ``target``."""
    raw = (target or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="")
    host = parsed.hostname or ""
    if host:
        return host.lower()
    return raw.split("/", 1)[0].split(":", 1)[0].lower()


def _target_scope(target: str) -> dict[str, list[str]]:
    """Build a minimal scope (asset_ids/cidrs/dns_suffixes) bounded to ``target``.

    - Hostname → ``dns_suffixes=[host]`` (exact match only) + ``asset_ids``.
    - IP address → ``cidrs=[ip/32|ip/128]`` + ``dns_suffixes=[ip]`` + ``asset_ids``.
    Both the boundary verifier and lease preflight accept exact host equality via
    ``dns_suffixes``, so this scope is enough while staying confined to the target.
    """
    host = _extract_host(target)
    if not host:
        raise LabScopeRequiredError(
            "Cannot auto-provision lab lease: empty target host",
            details={"target": target},
        )

    normalized_target = (target or "").strip().rstrip("/").lower()
    asset_ids = sorted({host, normalized_target})
    cidrs: list[str] = []
    try:
        ip = ipaddress.ip_address(host)
        cidrs.append(f"{ip}/{ip.max_prefixlen}")
    except ValueError:
        pass

    return {
        "asset_ids": asset_ids,
        "cidrs": cidrs,
        "dns_suffixes": [host],
    }


async def _ensure_tenant(tenant_id: str) -> None:
    """Best-effort ensure the tenant row exists (deep scans may be first activity)."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        from sqlalchemy import String, cast, select

        existing = (
            await session.execute(select(Tenant).where(cast(Tenant.id, String) == tenant_id))
        ).scalar_one_or_none()
        if existing is None:
            session.add(Tenant(id=tenant_id, name="default"))
            await session.commit()


async def _create_engagement(tenant_id: str, host: str) -> str:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        engagement = Engagement(
            tenant_id=tenant_id,
            name=f"Full Surface (auto) — {host}",
            description="Auto-provisioned engagement for a Full Surface (deep) scan.",
            status="active",
            environment="production",
            started_at=datetime.now(UTC),
        )
        session.add(engagement)
        await session.commit()
        await session.refresh(engagement)
        return engagement.id


async def autoprovision_deep_lab_lease(
    *,
    tenant_id: str,
    target: str,
    ttl_hours: int | None = None,
) -> tuple[str, str]:
    """Provision engagement + scope manifest + lab lease bounded to ``target``.

    Returns ``(engagement_id, lab_lease_id)``. Raises a typed ``LabLeaseError`` on
    boundary failure (rendered by the profile error handler in the API layer).
    """
    hours = int(ttl_hours if ttl_hours is not None else settings.deep_profile_autoprovision_ttl_hours)
    host = _extract_host(target)
    scope = _target_scope(target)
    repo = get_execution_mode_repository()

    await _ensure_tenant(tenant_id)
    engagement_id = await _create_engagement(tenant_id, host)

    # Bind the engagement to lab_unrestricted before attaching scope/lease.
    await repo.upsert_execution_mode(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        mode=ExecutionMode.LAB_UNRESTRICTED.value,
        first_execution_at=None,
    )

    expires_at = datetime.now(UTC) + timedelta(hours=hours)
    manifest = LabScopeManifest(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        asset_ids=tuple(scope["asset_ids"]),
        cidrs=tuple(scope["cidrs"]),
        dns_suffixes=tuple(scope["dns_suffixes"]),
        internet_attached=True,
        capture_full=True,
        expires_at=expires_at,
        created_by=_CREATED_BY,
    )
    await repo.save_manifest(manifest)

    verdict = LabBoundaryVerifier().verify(
        target,
        manifest,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
    )
    if not verdict.allowed:
        # Should not happen — scope is derived from the target. Surface as scope error.
        raise LabScopeRequiredError(
            "Auto-provisioned lab scope does not cover the target",
            details={
                "target": target,
                "manifest_id": manifest.manifest_id,
                "deny_code": verdict.deny_code or "DENY_OUTSIDE_LAB",
            },
        )

    lease = LabLeaseService().issue(
        manifest,
        boundary_proof=verdict.proof,
        ttl=timedelta(hours=hours),
    )
    await repo.save_lease(lease.lease_id, lease.to_storage_dict())

    logger.info(
        "deep_profile_lab_lease_autoprovisioned",
        extra={
            "event": "deep_profile_lab_lease_autoprovisioned",
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
            "lab_lease_id": lease.lease_id,
            "manifest_id": manifest.manifest_id,
            "target_host": host,
            "expires_at": expires_at.isoformat(),
        },
    )
    return engagement_id, lease.lease_id


__all__ = ["autoprovision_deep_lab_lease"]
