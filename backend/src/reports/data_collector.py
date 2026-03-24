"""RPT-003 — Aggregate scan/report inputs for full report generation (DB + MinIO).

Field → report section mapping (downstream generators may subset this model):

- ``scan`` → cover / metadata: target URL, lifecycle (status, phase, progress), options.
- ``report`` (optional) → tier, generation_status, summary counts JSON, technologies list.
- ``timeline`` (``scan_timeline``) → narrative "scan progress" / chronological sections.
- ``phase_inputs`` / ``phase_outputs`` → per-phase contract blocks (orchestration I/O).
- ``findings`` → vulnerabilities / issues tables and severity rollups.
- ``stage1`` (MinIO stage1 bucket) → recon / tech profile / MCP trace / anomalies (HTML §1-style).
- ``stage2`` → threat model, AI TM hypotheses & flows, stage2 inputs (§ threat modeling).
- ``stage3`` → VA normalized tasks, exploitation candidates, evidence gate artifacts (§ VA).
- ``stage4`` → exploitation plan, results, shells, AI exploitation summary (§ exploitation).

Empty stages: lists default empty; ``scan`` is None only if the row is missing (invalid input).
MinIO: each file is optional; failures set ``StageArtifactItem.error`` (``not_found`` vs
``storage_error`` / ``fetch_failed``) and log structured events without bodies, secrets, or stack traces.
``StageArtifactItem.text_preview`` may contain sensitive fragments and is for internal/report pipeline only.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.datetime_format import format_created_at_iso_z

from src.db.models import Finding as FindingModel
from src.db.models import PhaseInput as PhaseInputModel
from src.db.models import PhaseOutput as PhaseOutputModel
from src.db.models import Report as ReportModel
from src.db.models import Scan as ScanModel
from src.db.models import ScanTimeline as ScanTimelineModel
from src.recon.stage_object_download import StageObjectFetchError
from src.recon.stage1_storage import STAGE1_ROOT_FILES, download_stage1_artifact
from src.recon.stage2_storage import STAGE2_ROOT_FILES, download_stage2_artifact
from src.recon.stage3_storage import download_stage3_artifact, get_stage3_root_files
from src.recon.stage4_storage import STAGE4_ROOT_FILES, download_stage4_artifact
from src.storage.s3 import (
    RAW_ARTIFACT_PHASES,
    get_presigned_url_by_key,
    list_scan_artifacts,
)

logger = logging.getLogger(__name__)

_MAX_TEXT_BYTES = 512 * 1024
_MAX_JSON_PARSE_PREVIEW = 2048


class ScanRowData(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    target_id: str | None
    target_url: str
    status: str
    progress: int
    phase: str
    options: dict[str, Any] | None = None
    created_at: Any = None
    updated_at: Any = None


class ReportRowSlice(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    target: str
    scan_id: str | None
    tier: str
    generation_status: str
    template_version: str | None = None
    prompt_version: str | None = None
    summary: dict[str, Any] | None = None
    technologies: list[Any] | None = None
    created_at: Any = None


class TimelineRow(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    phase: str
    order_index: int
    entry: dict[str, Any] | None = None
    created_at: Any = None


class PhaseInputRow(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    phase: str
    input_data: dict[str, Any] | None = None
    created_at: Any = None


class PhaseOutputRow(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    phase: str
    output_data: dict[str, Any] | None = None
    created_at: Any = None


class FindingRow(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    scan_id: str
    report_id: str | None = None
    severity: str
    title: str
    description: str | None = None
    cwe: str | None = None
    cvss: float | None = None
    created_at: Any = None


class RawArtifactItem(BaseModel):
    """Metadata for a single raw artifact stored in MinIO (phase-scoped tool output)."""

    key: str
    phase: str
    artifact_type: str
    size_bytes: int = 0
    last_modified: str | None = None
    url: str | None = None


class StageArtifactItem(BaseModel):
    """Single object from a stage-* artifacts bucket (known filename).

    ``text_preview`` may contain sensitive fragments from scan artifacts; use only inside the
    report generation pipeline, not in user-facing APIs or logs.
    """

    filename: str
    stage: str
    fetched: bool = False
    size_bytes: int | None = None
    json_value: Any | None = None
    text_preview: str | None = None
    error: str | None = None


class StageArtifactsBundle(BaseModel):
    items: list[StageArtifactItem] = Field(default_factory=list)


class ScanReportData(BaseModel):
    """Unified payload for report builders (DB rows + optional MinIO stage blobs)."""

    scan_id: str
    tenant_id: str
    scan: ScanRowData | None = None
    report: ReportRowSlice | None = None
    timeline: list[TimelineRow] = Field(default_factory=list)
    phase_inputs: list[PhaseInputRow] = Field(default_factory=list)
    phase_outputs: list[PhaseOutputRow] = Field(default_factory=list)
    findings: list[FindingRow] = Field(default_factory=list)
    raw_artifacts: list[RawArtifactItem] = Field(default_factory=list)
    stage1: StageArtifactsBundle = Field(default_factory=StageArtifactsBundle)
    stage2: StageArtifactsBundle = Field(default_factory=StageArtifactsBundle)
    stage3: StageArtifactsBundle = Field(default_factory=StageArtifactsBundle)
    stage4: StageArtifactsBundle = Field(default_factory=StageArtifactsBundle)


def _scan_row_from_orm(row: ScanModel) -> ScanRowData:
    return ScanRowData(
        id=row.id,
        tenant_id=row.tenant_id,
        target_id=row.target_id,
        target_url=row.target_url,
        status=row.status,
        progress=row.progress,
        phase=row.phase,
        options=row.options,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _report_row_from_orm(row: ReportModel) -> ReportRowSlice:
    return ReportRowSlice(
        id=row.id,
        tenant_id=row.tenant_id,
        target=row.target,
        scan_id=row.scan_id,
        tier=row.tier,
        generation_status=row.generation_status,
        template_version=row.template_version,
        prompt_version=row.prompt_version,
        summary=row.summary,
        technologies=row.technologies,
        created_at=row.created_at,
    )


def _decode_and_shape_artifact(
    filename: str,
    stage: str,
    raw: bytes,
) -> StageArtifactItem:
    size = len(raw)
    item = StageArtifactItem(filename=filename, stage=stage, fetched=True, size_bytes=size)
    lower = filename.lower()
    if size > _MAX_TEXT_BYTES and not lower.endswith(".json"):
        item.error = "payload_too_large"
        return item
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        item.error = "decode_error"
        return item

    if lower.endswith(".json"):
        try:
            item.json_value = json.loads(text)
        except json.JSONDecodeError:
            item.error = "json_parse_error"
            item.text_preview = text[:_MAX_JSON_PARSE_PREVIEW]
        return item

    if lower.endswith(".jsonl") or lower.endswith(".md") or lower.endswith(".txt"):
        item.text_preview = text if size <= _MAX_TEXT_BYTES else text[:_MAX_TEXT_BYTES]
        if size > _MAX_TEXT_BYTES:
            item.error = "truncated"
        return item

    item.error = "binary_skipped"
    return item


def _fetch_stage_file(
    scan_id: str,
    stage: str,
    filename: str,
    downloader: Any,
) -> StageArtifactItem:
    try:
        raw = downloader(scan_id, filename)
    except ValueError:
        raise
    except StageObjectFetchError as e:
        logger.warning(
            "report_data_collector_stage_fetch_failed",
            extra={
                "component": "report_data_collector",
                "event": "stage_fetch_failed",
                "scan_id": scan_id,
                "stage": stage,
                "artifact": filename,
                "error_code": e.code,
            },
        )
        return StageArtifactItem(
            filename=filename,
            stage=stage,
            fetched=False,
            error=e.code,
        )
    except Exception:
        logger.warning(
            "report_data_collector_stage_fetch_failed",
            extra={
                "component": "report_data_collector",
                "event": "stage_fetch_failed",
                "scan_id": scan_id,
                "stage": stage,
                "artifact": filename,
            },
        )
        return StageArtifactItem(
            filename=filename,
            stage=stage,
            fetched=False,
            error="fetch_failed",
        )

    if raw is None:
        return StageArtifactItem(filename=filename, stage=stage, fetched=False, error="not_found")

    try:
        return _decode_and_shape_artifact(filename, stage, raw)
    except Exception:
        logger.warning(
            "report_data_collector_stage_shape_failed",
            extra={
                "component": "report_data_collector",
                "event": "stage_shape_failed",
                "scan_id": scan_id,
                "stage": stage,
                "artifact": filename,
            },
        )
        return StageArtifactItem(
            filename=filename,
            stage=stage,
            fetched=True,
            size_bytes=len(raw),
            error="shape_failed",
        )


def _parse_phase_from_key(key: str, tenant_id: str, scan_id: str) -> str:
    """Extract phase name from raw artifact key, or 'unknown' if not recognizable."""
    prefix = f"{tenant_id}/{scan_id}/"
    if not key.startswith(prefix):
        return "unknown"
    rest = key[len(prefix):]
    segment = rest.split("/", 1)[0]
    if segment in RAW_ARTIFACT_PHASES:
        return segment
    return "unknown"


def _parse_artifact_type_from_key(key: str) -> str:
    """Extract artifact_type from raw artifact filename ``{ts}_{artifact_type}.{ext}``."""
    basename = key.rsplit("/", 1)[-1] if "/" in key else key
    name_no_ext = basename.rsplit(".", 1)[0] if "." in basename else basename
    parts = name_no_ext.split("_", 2)
    if len(parts) >= 3:
        return parts[2]
    return name_no_ext


def list_raw_artifacts(
    tenant_id: str,
    scan_id: str,
    *,
    presigned_expiry: int = 3600,
) -> list[RawArtifactItem]:
    """List all raw artifacts stored in MinIO for a scan with presigned download URLs.

    Uses ``list_scan_artifacts(raw_only=True)`` from the storage layer;
    failures are non-fatal (returns empty list, logs warning).
    """
    if not (tenant_id or "").strip() or not (scan_id or "").strip():
        return []
    rows = list_scan_artifacts(tenant_id, scan_id, raw_only=True)
    if rows is None:
        logger.warning(
            "raw_artifact_list_unavailable",
            extra={
                "component": "report_data_collector",
                "event": "raw_artifact_list_unavailable",
                "scan_id": scan_id,
            },
        )
        return []
    result: list[RawArtifactItem] = []
    for row in rows:
        key = row.get("key") or ""
        if not key:
            continue
        phase = _parse_phase_from_key(key, tenant_id, scan_id)
        artifact_type = _parse_artifact_type_from_key(key)
        url = get_presigned_url_by_key(key, expires_in=presigned_expiry)
        lm = row.get("last_modified")
        lm_str = format_created_at_iso_z(lm) if lm is not None else None
        result.append(
            RawArtifactItem(
                key=key,
                phase=phase,
                artifact_type=artifact_type,
                size_bytes=int(row.get("size") or 0),
                last_modified=lm_str,
                url=url,
            )
        )
    return result


class ReportDataCollector:
    """Loads PostgreSQL scan graph and optional stage 1–4 MinIO artifacts into ``ScanReportData``."""

    async def collect_async(
        self,
        session: AsyncSession,
        tenant_id: str,
        scan_id: str,
        *,
        report_id: str | None = None,
        include_minio: bool = True,
    ) -> ScanReportData:
        tid = tenant_id
        sid = scan_id

        scan_result = await session.execute(
            select(ScanModel).where(
                cast(ScanModel.id, String) == sid,
                cast(ScanModel.tenant_id, String) == tid,
            )
        )
        scan_orm = scan_result.scalar_one_or_none()
        if not scan_orm:
            logger.warning(
                "report_data_collector_scan_missing",
                extra={
                    "component": "report_data_collector",
                    "event": "scan_not_found",
                    "scan_id": sid,
                },
            )
            return ScanReportData(scan_id=sid, tenant_id=tid, scan=None)

        scan_data = _scan_row_from_orm(scan_orm)

        report_slice: ReportRowSlice | None = None
        if report_id:
            r_result = await session.execute(
                select(ReportModel).where(
                    cast(ReportModel.id, String) == report_id,
                    cast(ReportModel.tenant_id, String) == tid,
                )
            )
            report_orm = r_result.scalar_one_or_none()
            if report_orm:
                report_slice = _report_row_from_orm(report_orm)

        tl_result = await session.execute(
            select(ScanTimelineModel)
            .where(
                cast(ScanTimelineModel.scan_id, String) == sid,
                cast(ScanTimelineModel.tenant_id, String) == tid,
            )
            .order_by(ScanTimelineModel.order_index, ScanTimelineModel.created_at)
        )
        timeline = [
            TimelineRow(
                phase=row.phase or "",
                order_index=row.order_index or 0,
                entry=row.entry,
                created_at=row.created_at,
            )
            for row in tl_result.scalars().all()
        ]

        pi_result = await session.execute(
            select(PhaseInputModel)
            .where(
                cast(PhaseInputModel.scan_id, String) == sid,
                cast(PhaseInputModel.tenant_id, String) == tid,
            )
            .order_by(PhaseInputModel.created_at)
        )
        phase_inputs = [
            PhaseInputRow(phase=row.phase or "", input_data=row.input_data, created_at=row.created_at)
            for row in pi_result.scalars().all()
        ]

        po_result = await session.execute(
            select(PhaseOutputModel)
            .where(
                cast(PhaseOutputModel.scan_id, String) == sid,
                cast(PhaseOutputModel.tenant_id, String) == tid,
            )
            .order_by(PhaseOutputModel.created_at)
        )
        phase_outputs = [
            PhaseOutputRow(phase=row.phase or "", output_data=row.output_data, created_at=row.created_at)
            for row in po_result.scalars().all()
        ]

        f_result = await session.execute(
            select(FindingModel).where(
                cast(FindingModel.scan_id, String) == sid,
                cast(FindingModel.tenant_id, String) == tid,
            )
        )
        findings = [
            FindingRow(
                id=row.id,
                tenant_id=row.tenant_id,
                scan_id=row.scan_id,
                report_id=row.report_id,
                severity=row.severity,
                title=row.title,
                description=row.description,
                cwe=row.cwe,
                cvss=row.cvss,
                created_at=row.created_at,
            )
            for row in f_result.scalars().all()
        ]

        s1 = StageArtifactsBundle()
        s2 = StageArtifactsBundle()
        s3 = StageArtifactsBundle()
        s4 = StageArtifactsBundle()
        raw_arts: list[RawArtifactItem] = []

        if include_minio:
            for fn in STAGE1_ROOT_FILES:
                s1.items.append(_fetch_stage_file(sid, "stage1", fn, download_stage1_artifact))
            for fn in STAGE2_ROOT_FILES:
                s2.items.append(_fetch_stage_file(sid, "stage2", fn, download_stage2_artifact))
            for fn in get_stage3_root_files():
                s3.items.append(_fetch_stage_file(sid, "stage3", fn, download_stage3_artifact))
            for fn in STAGE4_ROOT_FILES:
                s4.items.append(_fetch_stage_file(sid, "stage4", fn, download_stage4_artifact))
            raw_arts = list_raw_artifacts(tid, sid)

        out = ScanReportData(
            scan_id=sid,
            tenant_id=tid,
            scan=scan_data,
            report=report_slice,
            timeline=timeline,
            phase_inputs=phase_inputs,
            phase_outputs=phase_outputs,
            findings=findings,
            raw_artifacts=raw_arts,
            stage1=s1,
            stage2=s2,
            stage3=s3,
            stage4=s4,
        )
        logger.info(
            "report_data_collector_done",
            extra={
                "component": "report_data_collector",
                "event": "collect_complete",
                "scan_id": sid,
                "timeline_n": len(timeline),
                "phase_inputs_n": len(phase_inputs),
                "phase_outputs_n": len(phase_outputs),
                "findings_n": len(findings),
                "raw_artifacts_n": len(raw_arts),
                "stage1_n": len(s1.items),
                "stage2_n": len(s2.items),
                "stage3_n": len(s3.items),
                "stage4_n": len(s4.items),
            },
        )
        return out
