"""Shared enqueue logic for tier×format report bundles (API + post-scan hook)."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy import String, cast, delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas import DEFAULT_GENERATE_ALL_FORMATS
from src.core.config import settings
from src.db.models import ArtifactLedger as ArtifactLedgerModel
from src.db.models import Finding as FindingModel
from src.db.models import Report as ReportModel
from src.db.models import ReportObject as ReportObjectModel
from src.db.models import ReportShareLink as ReportShareLinkModel
from src.db.models import Scan

logger = logging.getLogger(__name__)


# generation_status values that mean a report is still being produced. GC must
# never touch one — deleting an in-flight report orphans its in-progress artifacts
# and races a concurrent bundle. Only terminal rows are GC candidates.
_NON_TERMINAL_STATUSES: frozenset[str] = frozenset({"pending", "processing", "queued"})


def _select_gc_targets(rows: list[tuple[str, Any, Any, Any, Any]]) -> list[str]:
    """Pick the report rows that are safe to GC — PURE, so the scoping is testable.

    ``rows`` is ``[(report_id, report_metadata, assigned_to, compliance_tags,
    generation_status), ...]``. A row is a GC target ONLY when ALL hold:

    * it is an auto-generated generate-all *bundle* row (``report_metadata.generate_all
      is True``) — excludes the finalize/base report and single-tier API reports;
    * it is not operator-owned (``assigned_to`` unset) and carries no
      ``compliance_tags`` (operator retention signals);
    * its ``generation_status`` is terminal (not pending/processing/queued) — never
      delete an in-flight report out from under a concurrent generation.

    Share-linked reports and reports that are a parent of another report are excluded
    separately in :func:`_gc_prior_reports` (those need a DB lookup).
    """
    out: list[str] = []
    for rid, md, assigned_to, compliance_tags, generation_status in rows:
        if assigned_to or compliance_tags:
            continue
        if str(generation_status or "").strip().lower() in _NON_TERMINAL_STATUSES:
            continue
        if isinstance(md, dict) and md.get("generate_all") is True:
            out.append(str(rid))
    return out


def _delete_report_objects_best_effort(object_keys: list[str], scan_id: str) -> None:
    """Delete prior-bundle MinIO objects. Best-effort, per-key logged, never raises."""
    if not object_keys:
        return
    try:
        from src.storage.s3 import _get_client

        client = _get_client()
        bucket = settings.minio_reports_bucket
    except Exception:  # noqa: BLE001 — storage unavailable; row GC already done
        logger.warning(
            "report_gc_storage_unavailable",
            extra={"event": "report_gc_storage_unavailable", "scan_id": scan_id},
        )
        return
    for key in object_keys:
        if not key:
            continue
        try:
            client.delete_object(Bucket=bucket, Key=key)
        except Exception:  # noqa: BLE001 — one object failing must not abort the rest
            logger.warning(
                "report_gc_object_delete_failed",
                extra={
                    "event": "report_gc_object_delete_failed",
                    "scan_id": scan_id,
                    "object_key": key,
                },
            )


async def _gc_prior_reports(session: AsyncSession, tenant_id: str, scan_id: str) -> int:
    """GC the scan's PRIOR generate-all bundle reports before a new bundle is created.

    Idempotency/GC (§1): each generate-all created a fresh set of rows/objects and
    never removed the old ones, so a scan accumulated N report_ids per tier and N×
    MinIO objects. Keep only the newest bundle.

    SAFETY — ``findings.report_id`` and ``artifact_ledger.report_id`` are
    ``ON DELETE CASCADE`` (NOT set-null), so a blanket report delete would destroy
    the scan's findings and artifact accounting. We therefore (1) scope the delete to
    auto-bundle rows only (:func:`_select_gc_targets`), (2) NULL those scan-scoped FK
    references first so they survive, then (3) delete the report rows (``report_objects``
    cascade away with them). MinIO objects are removed best-effort, after the row delete
    is flushed, with per-key logging. Gated by ``report_gc_enabled``.
    """
    if not getattr(settings, "report_gc_enabled", True):
        return 0
    rows = (
        await session.execute(
            select(
                ReportModel.id,
                ReportModel.report_metadata,
                ReportModel.assigned_to,
                ReportModel.compliance_tags,
                ReportModel.generation_status,
            ).where(
                cast(ReportModel.scan_id, String) == scan_id,
                cast(ReportModel.tenant_id, String) == tenant_id,
            )
        )
    ).all()
    ids = _select_gc_targets([(r[0], r[1], r[2], r[3], r[4]) for r in rows])
    if not ids:
        return 0

    # Exclude reports an operator can still reach: an existing share link (its token
    # URL would 404 after delete) or a report that is the parent of another report.
    # Both FK-CASCADE off reports, so they must be protected explicitly.
    shared = set(
        (
            await session.execute(
                select(ReportShareLinkModel.report_id).where(
                    ReportShareLinkModel.report_id.in_(ids),
                    cast(ReportShareLinkModel.tenant_id, String) == tenant_id,
                )
            )
        )
        .scalars()
        .all()
    )
    parents = set(
        (
            await session.execute(
                select(ReportModel.parent_report_id).where(
                    ReportModel.parent_report_id.in_(ids),
                    cast(ReportModel.tenant_id, String) == tenant_id,
                )
            )
        )
        .scalars()
        .all()
    )
    ids = [rid for rid in ids if rid not in shared and rid not in parents]
    if not ids:
        return 0

    # Capture the MinIO keys of the doomed reports BEFORE deleting (report_objects
    # rows cascade away with the report row, so this must happen first).
    object_keys = list(
        (
            await session.execute(
                select(ReportObjectModel.object_key).where(
                    ReportObjectModel.report_id.in_(ids),
                    cast(ReportObjectModel.tenant_id, String) == tenant_id,
                )
            )
        )
        .scalars()
        .all()
    )

    # Preserve scan-scoped data that FK-CASCADEs off reports: null the refs first.
    await session.execute(
        update(FindingModel)
        .where(
            FindingModel.report_id.in_(ids),
            cast(FindingModel.tenant_id, String) == tenant_id,
        )
        .values(report_id=None)
    )
    await session.execute(
        update(ArtifactLedgerModel)
        .where(
            ArtifactLedgerModel.report_id.in_(ids),
            cast(ArtifactLedgerModel.tenant_id, String) == tenant_id,
        )
        .values(report_id=None)
    )

    await session.execute(delete(ReportModel).where(ReportModel.id.in_(ids)))
    await session.flush()
    _delete_report_objects_best_effort(object_keys, scan_id)
    logger.info(
        "report_gc_prior_bundle",
        extra={"event": "report_gc_prior_bundle", "scan_id": scan_id, "removed": len(ids)},
    )
    return len(ids)


GENERATE_ALL_REPORT_TIERS: tuple[str, ...] = ("midgard", "asgard", "valhalla")

# The Valhalla tier is delivered as ONE report per format in EXACTLY these four
# formats (provable-report contract): json / pdf / xml / html — never csv or md,
# so a scan never shows duplicate/extra Valhalla artifacts. Other tiers keep
# whatever formats the caller asked for.
VALHALLA_REPORT_FORMATS: tuple[str, ...] = ("json", "pdf", "xml", "html")

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
        # ONE report row per tier, carrying ALL its formats in requested_formats —
        # the pipeline renders every requested format from a single row, so a scan
        # ends with exactly one report_id per tier instead of one per (tier×format).
        # Valhalla is pinned to its four-format contract (json/pdf/xml/html);
        # dict.fromkeys dedups while preserving order for the other tiers.
        tier_formats = (
            list(VALHALLA_REPORT_FORMATS) if tier == "valhalla" else list(dict.fromkeys(formats))
        )
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
                requested_formats=tier_formats,
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
