"""RPT-006 — Full report generation: ReportGenerator context, render, MinIO, ReportObject rows."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable
from typing import Any

import jinja2
from sqlalchemy import String, cast, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Finding, Report, ReportObject
from src.reports.generators import (
    VALHALLA_SECTIONS_CSV_FORMAT,
    generate_csv,
    generate_html,
    generate_json,
    generate_pdf,
    generate_valhalla_sections_csv,
)
from src.reports.report_data_validation import (
    log_report_validation_failure,
    report_validation_failure_payload,
    validate_report_data,
)
from src.services.reporting import ReportGenerator

logger = logging.getLogger(__name__)

class ReportGenerationError(Exception):
    """Raised when the report generation pipeline encounters a recoverable failure."""


REPORT_FORMAT_SET: frozenset[str] = frozenset({"pdf", "html", "json", "csv"})
DEFAULT_REPORT_FORMATS: tuple[str, ...] = ("html", "json", "csv", "pdf")

CONTENT_TYPES: dict[str, str] = {
    "pdf": "application/pdf",
    "html": "text/html; charset=utf-8",
    "json": "application/json; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    VALHALLA_SECTIONS_CSV_FORMAT: "text/csv; charset=utf-8",
}



def safe_report_task_error_message(exc: BaseException, max_len: int = 480) -> str:
    """Short operator-facing message; no tracebacks."""
    name = type(exc).__name__
    msg = str(exc).strip()
    if not msg:
        return name[:max_len]
    combined = f"{name}: {msg}"
    return combined[:max_len]


def normalize_generation_formats(
    explicit: list[str] | None,
    requested_formats: list[Any] | dict[str, Any] | str | None,
) -> list[str]:
    """Resolve format list from task args or Report.requested_formats JSONB."""
    if explicit is not None and len(explicit) > 0:
        out = [str(x).lower().strip() for x in explicit if str(x).lower().strip() in REPORT_FORMAT_SET]
        return out if out else list(DEFAULT_REPORT_FORMATS)

    if requested_formats is None:
        return list(DEFAULT_REPORT_FORMATS)

    raw: list[Any]
    if isinstance(requested_formats, str):
        raw = [requested_formats]
    elif isinstance(requested_formats, dict):
        inner = requested_formats.get("formats")
        raw = list(inner) if isinstance(inner, list) else []
        if not raw and requested_formats:
            raw = [k for k in requested_formats if str(k).lower() in REPORT_FORMAT_SET]
    else:
        raw = list(requested_formats)

    out = [str(x).lower().strip() for x in raw if str(x).lower().strip() in REPORT_FORMAT_SET]
    return out if out else list(DEFAULT_REPORT_FORMATS)


async def resolve_scan_id_for_report(
    session: AsyncSession,
    report_id: str,
    report: Report,
    scan_id_hint: str | None,
) -> str | None:
    """Effective scan_id for MinIO paths and ReportObject (FK)."""
    if report.scan_id:
        return str(report.scan_id)
    if scan_id_hint:
        return str(scan_id_hint).strip() or None
    r = await session.execute(
        select(Finding.scan_id).where(cast(Finding.report_id, String) == report_id).limit(1)
    )
    row = r.first()
    if row and row[0] is not None:
        return str(row[0])
    return None


async def _upsert_report_object(
    session: AsyncSession,
    *,
    tenant_id: str,
    scan_id: str,
    report_id: str,
    fmt: str,
    object_key: str,
    size_bytes: int,
) -> None:
    """One row per (report_id, format): overwrite object_key and size."""
    result = await session.execute(
        select(ReportObject).where(
            cast(ReportObject.report_id, String) == report_id,
            ReportObject.format == fmt,
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        existing.object_key = object_key
        existing.size_bytes = size_bytes
        existing.scan_id = scan_id
        existing.tenant_id = tenant_id
    else:
        session.add(
            ReportObject(
                tenant_id=tenant_id,
                scan_id=scan_id,
                report_id=report_id,
                format=fmt,
                object_key=object_key,
                size_bytes=size_bytes,
            )
        )


async def run_generate_report_pipeline(
    session: AsyncSession,
    *,
    report_id: str,
    tenant_id: str,
    scan_id_hint: str | None,
    formats: list[str] | None,
    include_minio: bool = True,
    redis_client: Any | None = None,
    upload_fn: Callable[..., str | None] | None = None,  # (tenant_id, scan_id, tier, report_id, fmt, data, *, content_type)
    ensure_bucket_fn: Callable[[], bool] | None = None,
    generator_cls: type[ReportGenerator] = ReportGenerator,
) -> dict[str, Any]:
    """
    Set Report.generation_status processing → ready|failed; render formats; upload; upsert ReportObject.
    """
    from src.core.redis_client import get_redis
    from src.reports.storage import ensure_bucket
    from src.storage.s3 import upload_report_artifact as default_upload_report

    def _default_upload(
        tenant_id: str,
        scan_id: str,
        tier: str,
        report_id: str,
        fmt: str,
        data: bytes,
        *,
        content_type: str,
    ) -> str | None:
        return default_upload_report(
            tenant_id,
            scan_id,
            tier,
            report_id,
            fmt,
            data,
            content_type=content_type,
        )

    upload = upload_fn or _default_upload
    ensure_b = ensure_bucket_fn or ensure_bucket

    ensure_b()

    result = await session.execute(select(Report).where(cast(Report.id, String) == report_id))
    report = result.scalar_one_or_none()
    if not report:
        return {"status": "failed", "report_id": report_id, "error": "Report not found"}

    if str(report.tenant_id) != str(tenant_id):
        return {"status": "failed", "report_id": report_id, "error": "Tenant mismatch"}

    scan_id = await resolve_scan_id_for_report(session, report_id, report, scan_id_hint)
    if not scan_id:
        await session.execute(
            update(Report)
            .where(cast(Report.id, String) == report_id)
            .values(generation_status="failed", last_error_message="Missing scan_id for report storage")
        )
        await session.commit()
        return {"status": "failed", "report_id": report_id, "error": "No scan_id for report"}

    fmt_list = normalize_generation_formats(formats, report.requested_formats)

    await session.execute(
        update(Report)
        .where(cast(Report.id, String) == report_id)
        .values(generation_status="processing", last_error_message=None)
    )
    await session.commit()

    try:
        gen = generator_cls()
        redis = redis_client if redis_client is not None else get_redis()
        built = await gen.build_context(
            session,
            tenant_id,
            scan_id,
            report.tier,
            report_id=report_id,
            include_minio=include_minio,
            sync_ai=True,
            redis_client=redis,
        )
        texts = gen.ai_results_to_text_map(built.ai_section_results)
        report_data = gen.to_generator_report_data(
            built.scan_report_data,
            texts,
            report_id=report_id,
        )

        tier_str = str(report.tier or "midgard")
        validation = validate_report_data(
            report_data,
            tier=tier_str,
            template_context=built.template_context,
        )
        if not validation.ok:
            log_report_validation_failure(
                report_validation_failure_payload(
                    report_id=report_id,
                    tenant_id=tenant_id,
                    tier=tier_str,
                    reason_codes=validation.reason_codes,
                )
            )
            await session.execute(
                update(Report)
                .where(cast(Report.id, String) == report_id)
                .values(
                    generation_status="failed",
                    last_error_message="Report data validation failed",
                )
            )
            await session.commit()
            return {"status": "failed", "report_id": report_id, "error": "validation_failed"}

        generated: dict[str, str] = {}
        for fmt in fmt_list:
            if fmt == "html":
                content = generate_html(
                    report_data,
                    jinja_context=built.template_context,
                    tier=tier_str,
                )
            elif fmt == "pdf":
                content = generate_pdf(
                    report_data,
                    jinja_context=built.template_context,
                    tier=tier_str,
                )
            elif fmt == "json":
                content = generate_json(report_data, jinja_context=built.template_context)
            elif fmt == "csv":
                content = generate_csv(report_data, jinja_context=built.template_context)
            else:
                continue
            key = upload(
                tenant_id,
                scan_id,
                tier_str,
                report_id,
                fmt,
                content,
                content_type=CONTENT_TYPES.get(fmt, "application/octet-stream"),
            )
            if not key:
                raise RuntimeError(f"Upload failed for format {fmt}")
            await _upsert_report_object(
                session,
                tenant_id=tenant_id,
                scan_id=scan_id,
                report_id=report_id,
                fmt=fmt,
                object_key=key,
                size_bytes=len(content),
            )
            generated[fmt] = key
            if fmt == "csv" and tier_str == "valhalla":
                vhl_csv = generate_valhalla_sections_csv(
                    report_data, jinja_context=built.template_context
                )
                vfmt = VALHALLA_SECTIONS_CSV_FORMAT
                vkey = upload(
                    tenant_id,
                    scan_id,
                    tier_str,
                    report_id,
                    vfmt,
                    vhl_csv,
                    content_type=CONTENT_TYPES.get(vfmt, "text/csv; charset=utf-8"),
                )
                if not vkey:
                    raise RuntimeError(f"Upload failed for format {vfmt}")
                await _upsert_report_object(
                    session,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    report_id=report_id,
                    fmt=vfmt,
                    object_key=vkey,
                    size_bytes=len(vhl_csv),
                )
                generated[vfmt] = vkey

        expected_keys = set(fmt_list)
        if tier_str == "valhalla" and "csv" in expected_keys:
            expected_keys.add(VALHALLA_SECTIONS_CSV_FORMAT)
        if set(generated.keys()) != expected_keys:
            missing = expected_keys - set(generated.keys())
            raise RuntimeError(f"Missing outputs: {sorted(missing)}")

        await session.execute(
            update(Report)
            .where(cast(Report.id, String) == report_id)
            .values(generation_status="ready", last_error_message=None)
        )
        await session.commit()

        return {
            "status": "completed",
            "report_id": report_id,
            "formats": list(generated.keys()),
            "object_keys": generated,
        }
    except jinja2.TemplateError as exc:
        logger.error("Report template rendering failed", exc_info=exc)
        err_msg = safe_report_task_error_message(exc)
    except OSError as exc:
        logger.error("Report file I/O failed", exc_info=exc)
        err_msg = safe_report_task_error_message(exc)
    except Exception as exc:
        logger.error("Unexpected report generation failure", exc_info=exc)
        err_msg = safe_report_task_error_message(exc)

    try:
        await session.execute(
            update(Report)
            .where(cast(Report.id, String) == report_id)
            .values(generation_status="failed", last_error_message=err_msg)
        )
        await session.commit()
    except Exception:
        with contextlib.suppress(Exception):
            await session.rollback()
    return {"status": "failed", "report_id": report_id, "error": "generation_failed"}
