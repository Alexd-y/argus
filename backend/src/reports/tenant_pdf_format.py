"""Tenant-scoped resolver for ``Tenant.pdf_archival_format`` (B6-T02 / T48 / D-4).

Why a dedicated module
----------------------
``backend/src/reports/generators.py`` is a *pure* rendering layer — it must
stay free of database imports so it can be unit-tested with a hand-built
:class:`~src.reports.generators.ReportData` and stubbed PDF backends. The
report-pipeline / report-service / FastAPI router layers, on the other hand,
already own an :class:`~sqlalchemy.ext.asyncio.AsyncSession` *and* a known
``tenant_id``, so they are the right place to fetch the per-tenant
PDF-archival flag and pass it down to ``generate_pdf``.

This module exists to give those three call sites a single, async, lightweight
helper. The helper always returns one of the closed-taxonomy literals
(``"standard"`` | ``"pdfa-2u"``) — never ``None`` — so production callers
can pass the result directly to :func:`generators.generate_pdf` without
re-introducing the ``REPORT_PDFA_MODE`` env override on the production path
(B6-T02 constraint: "No leak of ``REPORT_PDFA_MODE`` env into production
paths").

Edge cases that fall back to the default ``"standard"``:

1. Empty / missing ``tenant_id`` (defensive — should never happen).
2. Tenant row deleted between auth and report rendering (race).
3. Alembic 029 not yet applied (legacy DB) — the column lookup raises and
   we log a warning then fall back so PDF generation stays available.

Security
~~~~~~~~
* The query is always ``tenant_id``-bounded; we never trust external input
  for the ``WHERE`` clause.
* We project a single column instead of loading the full :class:`Tenant`
  row to keep the per-render hot path cheap and to avoid leaking
  unrelated tenant config into the renderer's logs / spans.
"""

from __future__ import annotations

import logging

from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.observability import tenant_hash
from src.db.models import (
    PDF_ARCHIVAL_FORMAT_DEFAULT,
    PDF_ARCHIVAL_FORMAT_VALUES,
    Tenant,
)

logger = logging.getLogger(__name__)


async def resolve_tenant_pdf_archival_format(
    session: AsyncSession,
    tenant_id: str,
) -> str:
    """Return the per-tenant ``pdf_archival_format`` (defaults to ``"standard"``).

    Always returns a member of :data:`PDF_ARCHIVAL_FORMAT_VALUES` so the
    caller can hand the result straight to :func:`generators.generate_pdf`
    without re-enabling the legacy ``REPORT_PDFA_MODE`` env path.
    """
    if not tenant_id:
        return PDF_ARCHIVAL_FORMAT_DEFAULT
    try:
        result = await session.execute(
            select(Tenant.pdf_archival_format).where(
                cast(Tenant.id, String) == tenant_id
            )
        )
        value = result.scalar_one_or_none()
    except Exception as exc:  # noqa: BLE001 — never break PDF rendering on lookup.
        logger.warning(
            "tenant_pdf_archival_format_lookup_failed",
            extra={
                "event": "argus.report.tenant_pdf_archival_format_lookup_failed",
                "tenant_hash": tenant_hash(tenant_id),
                "error_type": type(exc).__name__,
            },
        )
        return PDF_ARCHIVAL_FORMAT_DEFAULT

    if value is None or value not in PDF_ARCHIVAL_FORMAT_VALUES:
        return PDF_ARCHIVAL_FORMAT_DEFAULT
    return str(value)
