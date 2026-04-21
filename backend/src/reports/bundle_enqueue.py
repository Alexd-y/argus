"""Shared enqueue logic for tier×format report bundles (API + post-scan hook)."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas import DEFAULT_GENERATE_ALL_FORMATS
from src.db.models import Report as ReportModel
from src.db.models import Scan

logger = logging.getLogger(__name__)

GENERATE_ALL_REPORT_TIERS: tuple[str, ...] = ("midgard", "asgard", "valhalla")

# Scan.options key — idempotency for automatic generate-all after successful scan completion.
POST_SCAN_GENERATE_ALL_BUNDLE_OPTION_KEY = "_argus_post_scan_generate_all_bundle_id"


async def enqueue_generate_all_bundle(
    session: AsyncSession,
    tenant_id: str,
    scan_id: str,
    formats: list[str],
    *,
    set_post_scan_idempotency_flag: bool = False,
) -> tuple[str, list[str]] | None:
    """
    Create one Report row per (tier × format), same ordering as POST .../generate-all.

    When ``set_post_scan_idempotency_flag`` is True, sets ``Scan.options[POST_SCAN_GENERATE_ALL_BUNDLE_OPTION_KEY]``
    to the new ``bundle_id`` so a second completion pass does not enqueue duplicates.

    Returns ``(bundle_id, report_ids)`` or ``None`` if scan not found / idempotency skip.
    """
    result = await session.execute(
        select(Scan).where(
            cast(Scan.id, String) == scan_id,
            cast(Scan.tenant_id, String) == tenant_id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        return None

    opts: dict[str, Any] = dict(scan.options or {})
    if set_post_scan_idempotency_flag and opts.get(POST_SCAN_GENERATE_ALL_BUNDLE_OPTION_KEY):
        return None

    bundle_id = str(uuid.uuid4())
    if set_post_scan_idempotency_flag:
        opts[POST_SCAN_GENERATE_ALL_BUNDLE_OPTION_KEY] = bundle_id
        scan.options = opts

    report_ids: list[str] = []
    meta_extra = "post_scan_complete" if set_post_scan_idempotency_flag else None
    for tier in GENERATE_ALL_REPORT_TIERS:
        for fmt in formats:
            rid = str(uuid.uuid4())
            report_ids.append(rid)
            md: dict[str, Any] = {"bundle_id": bundle_id, "generate_all": True}
            if meta_extra:
                md["source"] = meta_extra
            session.add(
                ReportModel(
                    id=rid,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    target=scan.target_url,
                    tier=tier,
                    generation_status="pending",
                    requested_formats=[fmt],
                    summary={},
                    technologies=None,
                    report_metadata=md,
                )
            )
    return bundle_id, report_ids


def schedule_generate_all_reports_task_safe(
    tenant_id: str,
    scan_id: str,
    bundle_id: str,
    report_ids: list[str],
) -> None:
    """Fire-and-forget Celery task; logs structured error without leaking internals."""
    try:
        from src.tasks import generate_all_reports_task

        generate_all_reports_task.delay(tenant_id, scan_id, bundle_id, report_ids)
    except Exception:
        logger.exception(
            "post_scan_generate_all_schedule_failed",
            extra={
                "event": "post_scan_generate_all_schedule_failed",
                "scan_id": scan_id,
                "tenant_id": tenant_id,
                "bundle_id": bundle_id,
            },
        )


def default_post_scan_generate_all_formats() -> list[str]:
    """Formats for automatic post-scan bundle (must match generate-all API default)."""
    return list(DEFAULT_GENERATE_ALL_FORMATS)
