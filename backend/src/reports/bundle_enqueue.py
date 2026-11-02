"""Shared enqueue logic for tier×format report bundles (API + post-scan hook)."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy import String, cast, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas import DEFAULT_GENERATE_ALL_FORMATS
from src.core.config import settings
from src.db.models import Report as ReportModel
from src.db.models import Scan

logger = logging.getLogger(__name__)


async def _gc_prior_reports(session: AsyncSession, tenant_id: str, scan_id: str) -> int:
    """Delete the scan's PRIOR report rows + their MinIO objects before a new bundle.

    Idempotency/GC (§1): each generate-all created a fresh set of rows/objects and
    never removed the old ones, so a scan accumulated N report_ids per tier and N×
    objects. Keep only the newest bundle. Best-effort on storage; the reports.id FK
    is ON DELETE SET NULL, so dropping rows is safe. Gated by report_gc_enabled.
    """
    if not getattr(settings, "report_gc_enabled", True):
        return 0
    rows = (
        await session.execute(
            select(ReportModel.id, ReportModel.tier).where(
                cast(ReportModel.scan_id, String) == scan_id,
                cast(ReportModel.tenant_id, String) == tenant_id,
            )
        )
    ).all()
    if not rows:
        return 0
    try:
        from src.storage.s3 import _get_client

        client = _get_client()
        bucket = getattr(settings, "reports_bucket", "argus-reports") or "argus-reports"
        for rid, tier in rows:
            prefix = f"{tenant_id}/{scan_id}/reports/{tier}/{rid}"
            listed = client.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", [])
            for obj in listed:
                with __import__("contextlib").suppress(Exception):
                    client.delete_object(Bucket=bucket, Key=obj["Key"])
    except Exception:  # noqa: BLE001 — storage GC is best-effort; row GC still proceeds
        logger.warning(
            "report_gc_object_delete_failed",
            extra={"event": "report_gc_object_delete_failed", "scan_id": scan_id},
        )
    await session.execute(
        delete(ReportModel).where(
            cast(ReportModel.scan_id, String) == scan_id,
            cast(ReportModel.tenant_id, String) == tenant_id,
        )
    )
    logger.info(
        "report_gc_prior_bundle",
        extra={"event": "report_gc_prior_bundle", "scan_id": scan_id, "removed": len(rows)},
    )
    return len(rows)

GENERATE_ALL_REPORT_TIERS: tuple[str, ...] = ("midgard", "asgard", "valhalla")

# Scan.options key — idempotency for automatic generate-all after successful scan completion.
POST_SCAN_GENERATE_ALL_BUNDLE_OPTION_KEY = "_argus_post_scan_generate_all_bundle_id"


def _scan_skips_valhalla_tier(scan: Scan) -> bool:
    """Quick scans skip the active-injection assessment phase, so the Valhalla
    tier (``provable findings only``) always fails ``validate_report_data`` for
    injection findings (``xss_finding_but_injection_not_assessed`` /
    ``sqli_finding_but_injection_not_assessed``). Enqueuing it produces guaranteed
    ``generation_status='failed'`` rows and error-log noise for no artifact, so
    skip it for quick scans and let asgard/midgard represent the results.
    """
    for attr in ("execution_mode", "scan_profile", "scan_mode"):
        if str(getattr(scan, attr, "") or "").strip().lower() == "quick":
            return True
    return False


def report_tiers_for_scan(scan: Scan) -> tuple[str, ...]:
    """Tier set to generate for ``scan`` (drops Valhalla for quick scans)."""
    if _scan_skips_valhalla_tier(scan):
        return tuple(t for t in GENERATE_ALL_REPORT_TIERS if t != "valhalla")
    return GENERATE_ALL_REPORT_TIERS


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

    # GC prior bundles for this scan so report rows/objects do not accumulate (×N).
    await _gc_prior_reports(session, tenant_id, scan_id)

    bundle_id = str(uuid.uuid4())
    if set_post_scan_idempotency_flag:
        opts[POST_SCAN_GENERATE_ALL_BUNDLE_OPTION_KEY] = bundle_id
        scan.options = opts

    report_ids: list[str] = []
    meta_extra = "post_scan_complete" if set_post_scan_idempotency_flag else None
    for tier in report_tiers_for_scan(scan):
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
