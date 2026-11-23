"""Fail-closed governance scope enforcement for the scan pipeline (WP D).

This is the single seam that binds the pure gate
(:func:`src.governance.engagement.assert_in_scope`) to a persisted governance
engagement. It is deliberately **separate** from ARGUS's existing recon-campaign
``engagement_id`` (``src.db.models_recon.Engagement``): the scan pipeline must key
governance enforcement off its own ``governance_engagement_id`` so that attaching
the gate never retroactively denies a scan that merely carries a recon engagement.

Semantics:

* **No governance engagement attached** → no-op (unchanged behavior).
* **Attached** → fail-closed: an unknown id, a cross-tenant id, a revoked
  engagement, an out-of-window time, or an out-of-scope target/action all raise
  :class:`~src.governance.engagement.ScopeViolation`.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from src.governance import stores
from src.governance.engagement import ScopeViolation, assert_in_scope

__all__ = ["enforce_engagement_scope"]


async def enforce_engagement_scope(
    session: AsyncSession,
    *,
    governance_engagement_id: str | None,
    tenant_id: str,
    target: str,
    action: str,
    now: datetime | None = None,
) -> None:
    """Enforce the governance engagement scope, fail-closed.

    Returns ``None`` when permitted (or when no governance engagement is
    attached); raises :class:`ScopeViolation` otherwise.
    """
    if not governance_engagement_id:
        # Governance scope is not in use for this scan — preserve existing behavior.
        return None

    row = await stores.get_engagement(session, governance_engagement_id)
    if row is None:
        raise ScopeViolation(
            f"governance engagement {governance_engagement_id!r} not found — fail-closed deny"
        )
    if row.tenant_id != tenant_id:
        raise ScopeViolation(
            f"governance engagement {governance_engagement_id!r} belongs to another tenant — deny"
        )

    engagement = stores.engagement_row_to_dataclass(row)
    assert_in_scope(target, action, engagement, tenant_id=tenant_id, now=now)
    return None
