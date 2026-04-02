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
- ``valhalla_context`` → VHL-001 Valhalla template blocks (robots/sitemap, tech table, TLS, headers, deps, phases).
- ``hibp_pwned_password_summary`` → агрегат HIBP Pwned Passwords (opt-in), одна форма для AI/Jinja/JSON.

Empty stages: lists default empty; ``scan`` is None only if the row is missing (invalid input).
MinIO: each file is optional; failures set ``StageArtifactItem.error`` (``not_found`` vs
``storage_error`` / ``fetch_failed``) and log structured events without bodies, secrets, or stack traces.
``StageArtifactItem.text_preview`` may contain sensitive fragments and is for internal/report pipeline only.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.datetime_format import format_created_at_iso_z
from src.owasp.owasp_loader import get_owasp_category_info
from src.owasp_top10_2025 import (
    OWASP_TOP10_2025_CATEGORY_IDS,
    OWASP_TOP10_2025_CATEGORY_TITLES,
    parse_owasp_category,
)

from src.db.models import Finding as FindingModel
from src.db.models import PhaseInput as PhaseInputModel
from src.db.models import PhaseOutput as PhaseOutputModel
from src.db.models import Report as ReportModel
from src.db.models import Scan as ScanModel
from src.db.models import ScanTimeline as ScanTimelineModel
from src.db.models import ToolRun as ToolRunModel
from src.recon.stage_object_download import StageObjectFetchError
from src.recon.stage1_storage import STAGE1_ROOT_FILES, download_stage1_artifact
from src.recon.stage2_storage import STAGE2_ROOT_FILES, download_stage2_artifact
from src.recon.stage3_storage import download_stage3_artifact, get_stage3_root_files
from src.recon.stage4_storage import STAGE4_ROOT_FILES, download_stage4_artifact
from src.data_sources.hibp_pwned_passwords import summarize_pwned_passwords_for_report
from src.storage.s3 import (
    RAW_ARTIFACT_PHASES,
    get_presigned_url_by_key,
    list_scan_artifacts,
)
from src.reports.valhalla_report_context import (
    OutdatedComponentRow,
    RobotsSitemapMergedSummaryModel,
    SecurityHeadersAnalysisModel,
    SslTlsAnalysisModel,
    TechStackStructuredModel,
    ValhallaReportContext,
    build_valhalla_report_context,
    derive_exploit_available_flag,
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


class ToolRunRow(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tool_name: str
    status: str
    started_at: Any = None
    finished_at: Any = None


def _first_sentence(text: str) -> str:
    t = (text or "").strip()
    if not t:
        return ""
    for sep in ".!?":
        idx = t.find(sep)
        if idx > 0:
            return t[: idx + 1].strip()
    return t


def _truncate_plain(text: str, max_len: int) -> str:
    t = (text or "").strip()
    if len(t) <= max_len:
        return t
    return t[: max_len - 1].rstrip() + "…"


def _owasp_description_from_loader_info(info: dict[str, Any]) -> str:
    ex = (info.get("example_attack") or "").strip()
    if ex:
        return ex
    hf = (info.get("how_to_find") or "").strip()
    return _first_sentence(hf) if hf else ""


class OwaspCategorySummaryEntry(BaseModel):
    """Per A01–A10 template payload (OWASP-002): RU title, short description, optional fix tooltip."""

    category_id: str
    has_findings: bool
    title_ru: str
    description: str
    how_to_fix_short: str | None = None


def owasp_counts_from_finding_rows(findings: list[FindingRow]) -> dict[str, int]:
    counts: dict[str, int] = {cid: 0 for cid in OWASP_TOP10_2025_CATEGORY_IDS}
    for f in findings:
        raw = f.owasp_category
        cat = parse_owasp_category(raw.strip()) if isinstance(raw, str) and raw.strip() else None
        if cat is not None:
            counts[cat] = counts.get(cat, 0) + 1
    return counts


def severity_histogram_from_severity_strings(severities: Iterable[str | None]) -> dict[str, int]:
    """Histogram over raw severity labels (lowercased). Empty label → ``unknown`` (AI / diagnostics)."""
    hist: dict[str, int] = {}
    for raw in severities:
        s = (raw or "").strip().lower()
        if not s:
            s = "unknown"
        hist[s] = hist.get(s, 0) + 1
    return hist


def executive_severity_totals_from_severity_strings(
    severities: Iterable[str | None],
) -> dict[str, int]:
    """Top-5 buckets used in executive table and ``ReportSummary`` (``informational`` → ``info``)."""
    totals = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    alias = {"informational": "info"}
    for raw in severities:
        s = (raw or "").strip().lower()
        if not s:
            continue
        s = alias.get(s, s)
        if s in totals:
            totals[s] += 1
    return totals


def severity_histogram_from_finding_rows(findings: list[FindingRow]) -> dict[str, int]:
    return severity_histogram_from_severity_strings(f.severity for f in findings)


def executive_severity_totals_from_finding_rows(findings: list[FindingRow]) -> dict[str, int]:
    return executive_severity_totals_from_severity_strings(f.severity for f in findings)


def build_owasp_summary_from_counts(counts: dict[str, int]) -> dict[str, OwaspCategorySummaryEntry]:
    """Aggregate OWASP rows for templates from finding counts + RU JSON (OWASP-002)."""
    out: dict[str, OwaspCategorySummaryEntry] = {}
    for cid in OWASP_TOP10_2025_CATEGORY_IDS:
        n = int(counts.get(cid, 0))
        info = get_owasp_category_info(cid)
        title_ru = (info.get("title_ru") or "").strip() or OWASP_TOP10_2025_CATEGORY_TITLES.get(cid, cid)
        desc = _owasp_description_from_loader_info(info)
        if not desc:
            desc = OWASP_TOP10_2025_CATEGORY_TITLES.get(cid, "")
        htf = (info.get("how_to_fix") or "").strip()
        htf_short = _truncate_plain(htf, 200) if htf else None
        out[cid] = OwaspCategorySummaryEntry(
            category_id=cid,
            has_findings=n > 0,
            title_ru=title_ru,
            description=desc,
            how_to_fix_short=htf_short,
        )
    return out


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
    owasp_category: str | None = None
    proof_of_concept: dict[str, Any] | None = None
    confidence: str = "likely"
    evidence_type: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    reproducible_steps: str | None = None
    applicability_notes: str | None = None
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
    owasp_summary: dict[str, OwaspCategorySummaryEntry] = Field(default_factory=dict)
    valhalla_context: ValhallaReportContext = Field(default_factory=ValhallaReportContext)
    #: VHQ-001: WhatWeb JSON/NDJSON + recon/nmap → ``TechStackStructuredModel``; same object as ``valhalla_context.tech_stack_structured``.
    tech_stack: TechStackStructuredModel | None = None
    #: VDF — зеркала блоков Valhalla для экспорта / AI без повторного разбора артефактов.
    ssl_tls_analysis: SslTlsAnalysisModel | None = None
    security_headers_analysis: SecurityHeadersAnalysisModel | None = None
    outdated_components_table: list[OutdatedComponentRow] = Field(default_factory=list)
    leaked_emails_masked: list[str] = Field(default_factory=list)
    robots_sitemap_analysis: RobotsSitemapMergedSummaryModel | None = None
    tool_runs: list[ToolRunRow] = Field(default_factory=list)
    #: HIBP Pwned Passwords aggregate (opt-in); same dict as AI payload and Valhalla appendix.
    hibp_pwned_password_summary: dict[str, Any] | None = None


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


def _stage1_json_dict(bundle: StageArtifactsBundle, filename: str) -> dict[str, Any] | None:
    for it in bundle.items:
        if it.filename != filename:
            continue
        jv = it.json_value
        if isinstance(jv, dict):
            return jv
    return None


def _stage1_json_list(bundle: StageArtifactsBundle, filename: str) -> list[dict[str, Any]] | None:
    for it in bundle.items:
        if it.filename != filename:
            continue
        jv = it.json_value
        if isinstance(jv, list):
            return [x for x in jv if isinstance(x, dict)]
    return None


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
            return ScanReportData(
                scan_id=sid,
                tenant_id=tid,
                scan=None,
                valhalla_context=ValhallaReportContext(),
                tech_stack=None,
                tool_runs=[],
            )

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

        tr_result = await session.execute(
            select(ToolRunModel)
            .where(
                cast(ToolRunModel.scan_id, String) == sid,
                cast(ToolRunModel.tenant_id, String) == tid,
            )
            .order_by(ToolRunModel.started_at.asc().nullsfirst(), ToolRunModel.id.asc())
        )
        tr_orm_rows = list(tr_result.scalars().all())
        tool_runs = [
            ToolRunRow(
                id=row.id,
                tool_name=row.tool_name or "",
                status=row.status or "",
                started_at=row.started_at,
                finished_at=row.finished_at,
            )
            for row in tr_orm_rows
        ]
        tool_run_rows: list[tuple[str, dict[str, Any] | None]] = [
            (
                str(row.tool_name or "").strip(),
                row.input_params if isinstance(row.input_params, dict) else None,
            )
            for row in tr_orm_rows
            if str(row.tool_name or "").strip()
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
                owasp_category=getattr(row, "owasp_category", None),
                proof_of_concept=(
                    row.proof_of_concept if isinstance(getattr(row, "proof_of_concept", None), dict) else None
                ),
                confidence=str(getattr(row, "confidence", None) or "likely")[:20],
                evidence_type=getattr(row, "evidence_type", None),
                evidence_refs=(
                    [str(x)[:500] for x in getattr(row, "evidence_refs", [])[:64] if x is not None]
                    if isinstance(getattr(row, "evidence_refs", None), list)
                    else []
                ),
                reproducible_steps=getattr(row, "reproducible_steps", None),
                applicability_notes=getattr(row, "applicability_notes", None),
                created_at=row.created_at,
            )
            for row in f_result.scalars().all()
        ]

        owasp_summary = build_owasp_summary_from_counts(owasp_counts_from_finding_rows(findings))

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

        recon_json = _stage1_json_dict(s1, "recon_results.json")
        tech_profile_json = _stage1_json_list(s1, "tech_profile.json")
        anomalies_json = _stage1_json_dict(s1, "anomalies_structured.json")
        raw_key_tuples = [(a.key, a.phase) for a in raw_arts]
        raw_artifact_type_list = [a.artifact_type for a in raw_arts if (a.artifact_type or "").strip()]
        findings_payload: list[dict[str, Any]] = []
        for f in findings:
            row = f.model_dump(mode="json")
            row["intel"] = {"exploit_available": derive_exploit_available_flag(row)}
            findings_payload.append(row)
        phase_out_tuples = [(r.phase or "", r.output_data) for r in phase_outputs]
        phase_in_tuples = [(r.phase or "", r.input_data) for r in phase_inputs]
        report_tech_list: list[str] | None = None
        if report_slice and report_slice.technologies:
            report_tech_list = [str(x) for x in report_slice.technologies]

        tool_run_status_tuples: list[tuple[str, str]] = [
            (str(row.tool_name or "").strip(), str(row.status or "").strip())
            for row in tr_orm_rows
            if str(row.tool_name or "").strip()
        ]
        valhalla_ctx = build_valhalla_report_context(
            tenant_id=tid,
            scan_id=sid,
            recon_results=recon_json,
            tech_profile=tech_profile_json,
            anomalies_structured=anomalies_json,
            raw_artifact_keys=raw_key_tuples,
            phase_outputs=phase_out_tuples,
            phase_inputs=phase_in_tuples,
            findings=findings_payload,
            report_technologies=report_tech_list,
            fetch_raw_bodies=include_minio,
            tool_runs=tool_run_rows,
            raw_artifact_types=raw_artifact_type_list or None,
            trivy_enabled=bool(settings.trivy_enabled),
            harvester_enabled=bool(settings.harvester_enabled),
            tool_run_summaries=tool_run_status_tuples or None,
        )

        exploit_dump: dict[str, Any] | None = None
        for row in phase_outputs:
            if (row.phase or "").lower() == "exploitation" and isinstance(row.output_data, dict):
                exploit_dump = row.output_data
                break
        hibp_pwned_password_summary: dict[str, Any] | None = None
        if exploit_dump is not None:
            hibp_pwned_password_summary = await summarize_pwned_passwords_for_report(
                exploit_dump,
                max_checks=5,
            )

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
            owasp_summary=owasp_summary,
            valhalla_context=valhalla_ctx,
            tech_stack=valhalla_ctx.tech_stack_structured,
            ssl_tls_analysis=valhalla_ctx.ssl_tls_analysis,
            security_headers_analysis=valhalla_ctx.security_headers_analysis,
            outdated_components_table=list(valhalla_ctx.outdated_components or []),
            leaked_emails_masked=list(valhalla_ctx.leaked_emails or []),
            robots_sitemap_analysis=valhalla_ctx.robots_sitemap_merged,
            tool_runs=tool_runs,
            hibp_pwned_password_summary=hibp_pwned_password_summary,
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
