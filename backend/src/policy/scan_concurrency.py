"""Scan concurrency guard — limit overlapping scans per tenant.

A tenant may have up to ``SCAN_MAX_CONCURRENT`` (default 3) active scans at
the same time. Active statuses are ``queued``, ``running``, and
``awaiting_approval``. Any attempt to start a scan that would exceed the
limit raises :class:`ScanConcurrencyError`.

The check is DB-based (``SELECT … WHERE status IN active_statuses``)
inside the same transaction that creates the new scan row, so it is
naturally serialisable under PostgreSQL's default READ COMMITTED isolation.

Fail-open on query errors: if the DB is unreachable we log a warning and
allow the scan to proceed — a degraded UX is better than blocking all scans
during a transient outage.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.models import Scan

logger = logging.getLogger(__name__)

_ACTIVE_STATUSES: frozenset[str] = frozenset(
    {"queued", "running", "awaiting_approval"}
)

_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {"completed", "failed", "cancelled"}
)

_DEFAULT_MAX_CONCURRENT: int = 3


class ScanConcurrencyError(Exception):
    """Raised when a tenant has reached the concurrent scan limit."""

    def __init__(
        self,
        tenant_id: str,
        active_count: int,
        max_concurrent: int,
    ) -> None:
        self.tenant_id = tenant_id
        self.active_count = active_count
        self.max_concurrent = max_concurrent
        super().__init__(
            f"Tenant {tenant_id} already has {active_count} active scan(s), "
            f"which meets the concurrency limit ({max_concurrent}). "
            f"Wait for a scan to finish before starting a new one."
        )


async def check_scan_concurrency(
    session: AsyncSession,
    tenant_id: str,
    *,
    fail_open: bool = True,
    max_concurrent: int | None = None,
) -> None:
    """Raise :class:`ScanConcurrencyError` if *tenant_id* has too many active scans.

    Parameters
    ----------
    session:
        An async SA session with RLS already set (``set_session_tenant``).
        The query is executed inside the caller's transaction so the check
        is consistent with the subsequent ``INSERT``.
    tenant_id:
        The tenant to check.
    fail_open:
        When ``True`` (the default), DB query errors are logged and the
        check is skipped so the caller can proceed. When ``False``, DB
        errors are re-raised. Production should keep the default — a
        transient DB blip must not hard-block scan creation.
    max_concurrent:
        Override the maximum allowed concurrent scans. Defaults to
        ``settings.scan_max_concurrent`` (env: ``SCAN_MAX_CONCURRENT``).
    """
    limit = max_concurrent or settings.scan_max_concurrent or _DEFAULT_MAX_CONCURRENT

    try:
        stmt = (
            select(func.count())
            .select_from(Scan)
            .where(
                cast(Scan.tenant_id, String) == tenant_id,
                Scan.status.in_(_ACTIVE_STATUSES),
            )
        )
        result = await session.execute(stmt)
        active_count = result.scalar_one()
    except Exception:
        if fail_open:
            logger.warning(
                "scan_concurrency.check_failed_fail_open",
                extra={
                    "event": "argus.scan_concurrency.check_failed",
                    "tenant_id_hash": _safe_hash(tenant_id),
                },
                exc_info=True,
            )
            return
        raise

    if active_count >= limit:
        raise ScanConcurrencyError(
            tenant_id=tenant_id,
            active_count=active_count,
            max_concurrent=limit,
        )


def _safe_hash(value: str) -> str:
    """Non-reversible hash for audit logs — mirrors kill_switch pattern."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]