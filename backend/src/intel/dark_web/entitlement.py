"""Server-side DWM entitlement resolution — FAIL CLOSED.

DWM is a paid capability (Asgard/Valhalla). Entitlement is resolved from the
tenant's paid ``Subscription`` / ``ScanQuota`` tier, never from client-supplied
scan options (those are attacker-controllable). When entitlement cannot be
established, the tenant is treated as NOT entitled (deny).

An operator allowlist (``settings.dark_web_entitled_tenants``: comma-separated
tenant ids, or ``*`` for all) grants DWM in dev or to tenants without a paid
Subscription row.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import String, cast, select

from src.core.config import settings

logger = logging.getLogger(__name__)

#: Plan / tier strings that do NOT grant DWM.
_FREE_PLANS = {"", "free", "none", "trial", "basic"}


def _allowlisted(tenant_id: str) -> bool:
    raw = (getattr(settings, "dark_web_entitled_tenants", None) or "").strip()
    if not raw:
        return False
    entries = {e.strip() for e in raw.split(",") if e.strip()}
    return "*" in entries or tenant_id in entries


async def tenant_has_dwm_entitlement(session: Any, tenant_id: str) -> bool:
    """True iff the tenant is entitled to Dark Web Monitoring. Fail-closed."""

    if not tenant_id:
        return False
    if _allowlisted(tenant_id):
        return True
    if session is None:
        return False

    try:
        from src.db.models import ScanQuota, Subscription

        # Active, non-expired, paid subscription?
        sub_rows = (
            (
                await session.execute(
                    select(Subscription)
                    .where(cast(Subscription.tenant_id, String) == tenant_id)
                    .order_by(Subscription.created_at.desc().nullslast())
                )
            )
            .scalars()
            .all()
        )
        now = datetime.now(tz=UTC)
        for sub in sub_rows:
            plan = (sub.plan or "").strip().lower()
            status = (sub.status or "").strip().lower()
            if plan in _FREE_PLANS:
                continue
            if status not in ("active", "trialing", "past_due", ""):
                continue
            if sub.valid_until is not None and sub.valid_until < now:
                continue
            return True

        # Paid ScanQuota tier?
        quota = (
            (
                await session.execute(
                    select(ScanQuota).where(cast(ScanQuota.tenant_id, String) == tenant_id)
                )
            )
            .scalars()
            .first()
        )
        if quota is not None and (quota.tier or "").strip().lower() not in _FREE_PLANS:
            return True
    except Exception:  # noqa: BLE001 - any resolution error -> deny (fail closed)
        logger.warning("dwm_entitlement_resolution_failed", extra={"tenant_id": tenant_id})
        return False

    return False


__all__ = ["tenant_has_dwm_entitlement"]
