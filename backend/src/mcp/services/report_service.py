"""Tenant-scoped report operations consumed by MCP ``report.*`` tools."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import String, cast, select

from src.db.models import Report
from src.db.session import async_session_factory, set_session_tenant
from src.mcp.exceptions import (
    ResourceNotFoundError,
    UpstreamServiceError,
    ValidationError,
)
from src.mcp.schemas.report import (
    ReportDownloadResult,
    ReportFormat,
    ReportGenerateResult,
    ReportTier,
)

_logger = logging.getLogger(__name__)


def _coerce_tier(raw: str | None) -> ReportTier:
    value = (raw or "midgard").lower().strip()
    try:
        return ReportTier(value)
    except ValueError:
        _logger.warning("mcp.report.unknown_tier", extra={"raw": value})
        return ReportTier.MIDGARD


def _ensure_aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


async def request_report_generation(
    *,
    tenant_id: str,
    scan_id: str,
    tier: ReportTier,
    format: ReportFormat,
) -> ReportGenerateResult:
    """Create or upsert a report row and queue background generation.

    The MCP layer only writes the queue metadata — actual rendering happens
    inside the existing report pipeline (see :mod:`src.reports`). The caller
    polls ``report.download`` for the presigned URL once the row reports
    ``generation_status == 'ready'``.
    """
    if not scan_id:
        raise ValidationError("scan_id is required.")
    try:
        async with async_session_factory() as session:
            await set_session_tenant(session, tenant_id)
            existing = await session.execute(
                select(Report).where(
                    cast(Report.scan_id, String) == scan_id,
                    cast(Report.tenant_id, String) == tenant_id,
                    Report.tier == tier.value,
                )
            )
            row = existing.scalar_one_or_none()
            if row is None:
                row = Report(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    target="(deferred)",
                    tier=tier.value,
                    generation_status="queued",
                    requested_formats={"formats": [format.value]},
                )
                session.add(row)
            else:
                requested = row.requested_formats or {}
                formats: list[Any]
                if isinstance(requested, dict):
                    formats = [str(item) for item in requested.get("formats", [])]
                elif isinstance(requested, list):
                    formats = [str(item) for item in requested]
                else:
                    formats = []
                if format.value not in formats:
                    formats.append(format.value)
                row.requested_formats = {"formats": formats}
                if row.generation_status not in {"queued", "rendering"}:
                    row.generation_status = "queued"
            await session.commit()
            await session.refresh(row)
            report_id = row.id
            return ReportGenerateResult(
                report_id=str(report_id),
                scan_id=scan_id,
                tier=tier,
                format=format,
                queued=True,
            )
    except (ValidationError, ResourceNotFoundError):
        raise
    except Exception as exc:
        _logger.exception(
            "mcp.report.generate_failed",
            extra={"scan_id": scan_id, "tenant_id": tenant_id, "tier": tier.value},
        )
        raise UpstreamServiceError(
            "Failed to enqueue report generation; please retry later."
        ) from exc


async def get_report_download(
    *,
    tenant_id: str,
    report_id: str,
    format: ReportFormat,
) -> ReportDownloadResult:
    """Return a download envelope for the requested report.

    Notes
    -----
    The MCP server NEVER streams artifact bytes in the JSON-RPC response.
    Callers must follow the presigned URL out-of-band — when the URL is
    ``None`` the report is still being prepared.
    """
    try:
        async with async_session_factory() as session:
            await set_session_tenant(session, tenant_id)
            row = (
                await session.execute(
                    select(Report).where(
                        cast(Report.id, String) == report_id,
                        cast(Report.tenant_id, String) == tenant_id,
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                raise ResourceNotFoundError(
                    f"Report {report_id!r} was not found in this tenant scope."
                )
            metadata = (
                row.report_metadata if isinstance(row.report_metadata, dict) else {}
            )
            sha256 = _extract_sha256(metadata, format)
            presigned = _extract_presigned_url(metadata, format)
            expires_at = _extract_expiry(metadata, format)
            return ReportDownloadResult(
                report_id=report_id,
                format=format,
                presigned_url=presigned,
                sha256=sha256,
                expires_at=_ensure_aware(expires_at),
            )
    except ResourceNotFoundError:
        raise
    except Exception as exc:
        _logger.exception(
            "mcp.report.download_failed",
            extra={"report_id": report_id, "tenant_id": tenant_id},
        )
        raise UpstreamServiceError(
            "Failed to read report metadata; please retry later."
        ) from exc


def _extract_sha256(metadata: dict[str, Any], format: ReportFormat) -> str | None:
    artifacts = metadata.get("artifacts")
    if not isinstance(artifacts, dict):
        return None
    bucket = artifacts.get(format.value)
    if not isinstance(bucket, dict):
        return None
    raw = bucket.get("sha256")
    if isinstance(raw, str) and len(raw) == 64:
        return raw.lower()
    return None


def _extract_presigned_url(
    metadata: dict[str, Any], format: ReportFormat
) -> str | None:
    artifacts = metadata.get("artifacts")
    if not isinstance(artifacts, dict):
        return None
    bucket = artifacts.get(format.value)
    if not isinstance(bucket, dict):
        return None
    raw = bucket.get("presigned_url")
    if isinstance(raw, str) and raw:
        return raw
    return None


def _extract_expiry(metadata: dict[str, Any], format: ReportFormat) -> datetime | None:
    artifacts = metadata.get("artifacts")
    if not isinstance(artifacts, dict):
        return None
    bucket = artifacts.get(format.value)
    if not isinstance(bucket, dict):
        return None
    raw = bucket.get("expires_at")
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


__all__ = [
    "get_report_download",
    "request_report_generation",
]
