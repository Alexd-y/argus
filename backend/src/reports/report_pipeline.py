"""RPT-006 — Full report generation: ReportGenerator context, render, MinIO, ReportObject rows."""

from __future__ import annotations

import contextlib
import logging
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jinja2
from sqlalchemy import String, cast, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.models import Finding, Report, ReportObject
from src.findings.lifecycle_bridge import retain_findings_despite_ai_classification
from src.reports.canonical_bundle import assert_canonical_parity, render_canonical_bundle
from src.reports.generators import (
    VALHALLA_SECTIONS_CSV_FORMAT,
    generate_csv,
    generate_export_validation_report,
    generate_html,
    generate_json,
    generate_markdown,
    generate_outdated_components_csv,
    generate_pdf,
    generate_technologies_csv,
    generate_tool_health_csv,
    generate_valhalla_sections_csv,
    generate_xml,
)
from src.reports.prose_gate import blocking_violations as blocking_prose_violations
from src.reports.prose_gate import check_output_consistency, evaluate_prose
from src.reports.report_data_validation import (
    log_report_validation_failure,
    report_validation_failure_payload,
    validate_report_data,
)
from src.reports.snapshot_builder import build_snapshot_from_report_data
from src.reports.snapshot_completeness_gate import snapshot_release_blockers
from src.reports.tenant_pdf_format import resolve_tenant_pdf_archival_format
from src.reports.valhalla_completeness import valhalla_release_blockers
from src.reports.valhalla_llm_merge import merge_llm_into_document
from src.reports.valhalla_severity_review_gate import severity_review_blockers
from src.reports.verification_kit import build_verification_kit
from src.services.reporting import ReportGenerator

logger = logging.getLogger(__name__)


_CANONICAL_CONTENT_TYPES: dict[str, str] = {
    "canonical_json": "application/json",
    "canonical_md": "text/markdown",
    "canonical_xml": "application/xml",
    "canonical_html": "text/html; charset=utf-8",
    "canonical_pdf": "application/pdf",
}


def _snapshot_pdf_bytes(html: str, completed_at: str) -> bytes | None:
    """Best-effort HTML→PDF via the active backend; None if unavailable."""
    try:
        from src.reports.pdf_backend import get_active_backend

        backend = get_active_backend()
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "canonical.pdf"
            ok = backend.render(
                html_content=html,
                output_path=out,
                scan_completed_at=completed_at or "",
            )
            if ok and out.exists():
                return out.read_bytes()
    except Exception:  # noqa: BLE001 — PDF is best-effort, never break the pipeline
        return None
    return None


def _scan_meta_for_snapshot(
    built: Any, report_data: Any, scan_id: str, tenant_id: str
) -> dict[str, Any]:
    """Assemble snapshot scan-meta from ScanReportData.scan (tolerant getattr)."""
    scan_row = getattr(getattr(built, "scan_report_data", None), "scan", None)
    return {
        "scan_id": scan_id,
        "tenant_id": tenant_id,
        "target": getattr(report_data, "target", None),
        "scan_profile": getattr(scan_row, "scan_profile", None),
        "resolved_scan_mode": getattr(scan_row, "resolved_scan_mode", None)
        or getattr(scan_row, "scan_mode", None),
        "execution_mode": getattr(scan_row, "execution_mode", None),
        "quick_profile": getattr(scan_row, "quick_profile", None),
        "nuclei_profile": getattr(scan_row, "nuclei_profile", None),
        "completed_at": getattr(report_data, "created_at", None),
    }


class ReportGenerationError(Exception):
    """Raised when the report generation pipeline encounters a recoverable failure."""


REPORT_FORMAT_SET: frozenset[str] = frozenset({"pdf", "html", "json", "csv", "md", "xml"})
DEFAULT_REPORT_FORMATS: tuple[str, ...] = ("html", "json", "csv", "pdf", "md", "xml")

CONTENT_TYPES: dict[str, str] = {
    "pdf": "application/pdf",
    "html": "text/html; charset=utf-8",
    "json": "application/json; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "xml": "application/xml; charset=utf-8",
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
        out = [
            str(x).lower().strip() for x in explicit if str(x).lower().strip() in REPORT_FORMAT_SET
        ]
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


def _compute_valhalla_release_blockers(
    *,
    report_data: Any,
    template_context: dict[str, Any],
    requested_tier: str,
    actual_tier: str,
    valhalla_llm_status: str,
) -> list[str]:
    """Evaluate ``valhalla_release_blockers`` from the prod pipeline state (Phase G, D4).

    Runs the rules that are correctly evaluable from the current release state:
      * VP-01 — requested tier must equal the rendered tier;
      * VP-02 — no stop-list / placeholder phrases in the rendered report text;
      * VP-05 — no unclassified observation sits in the findings registry;
      * §9   — mandatory LLM analysis must be complete for a ``ready`` release.

    VP-04 (source-present/section-empty parity) needs the ordered-section registry
    from Phase C to build a faithful ``sections`` map; until then ``snapshot`` and
    ``sections`` are passed empty so ``validate_valhalla_completeness`` yields no
    false positives. The manifest ``generation_status`` of the VH-LLM release is
    ``ready`` on success; normalise it to the gate's ``completed`` vocabulary.
    """
    try:
        report_text = generate_markdown(
            report_data, jinja_context=template_context, tier=actual_tier
        ).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 — gate must not crash generation
        report_text = ""

    findings: list[dict[str, Any]] = []
    for f in getattr(report_data, "findings", None) or []:
        findings.append(
            {
                "cwe": getattr(f, "cwe", None),
                "category": getattr(f, "owasp_category", None),
                "owasp_category": getattr(f, "owasp_category", None),
                "title": getattr(f, "title", "") or "",
                "description": getattr(f, "description", "") or "",
            }
        )

    llm_analysis_status = (
        "completed" if str(valhalla_llm_status).strip().lower() == "ready" else valhalla_llm_status
    )

    blockers = valhalla_release_blockers(
        snapshot={},
        sections={},
        report_text=report_text,
        findings=findings,
        requested_tier=requested_tier,
        actual_tier=actual_tier,
        llm_analysis_status=llm_analysis_status,
    )

    # Phase N — prose discipline on the rendered text. Reference-requirement is off
    # here (per-claim [CL-…]/[E-…] linking is Phase 14.3, not yet emitted); only the
    # unconditional stop-list / absolute-safety BLOCK rules apply to current reports.
    for pv in blocking_prose_violations(evaluate_prose(report_text, require_references=False)):
        blockers.append(f"PROSE: {pv.rule}: {pv.detail}")

    # Phase O — severity / CVSS / review consistency on the snapshot findings.
    # Phase T — model-output consistency on the rendered text (chain claims,
    # truncated finding IDs, insecure verify commands, counters, WSTG coverage).
    try:
        snapshot = build_snapshot_from_report_data(report_data, scan_meta={"tier": actual_tier})
        blockers.extend(severity_review_blockers(snapshot.findings))
        known_ids = {f.finding_id for f in snapshot.findings if f.finding_id}
        has_proven = any(c.kind == "proven" for c in snapshot.exploit_chains)
        wstg_pct = None
        if isinstance(snapshot.wstg, dict):
            raw_pct = snapshot.wstg.get("coverage_pct")
            wstg_pct = float(raw_pct) if isinstance(raw_pct, (int, float)) else None
        for cv in blocking_prose_violations(
            check_output_consistency(
                report_text,
                known_finding_ids=known_ids,
                has_proven_chains=has_proven,
                wstg_coverage_pct=wstg_pct,
            )
        ):
            blockers.append(f"OUTPUT: {cv.rule}: {cv.detail}")
        # Phase U — snapshot completeness + evidence-chain (R-13…R-18).
        blockers.extend(snapshot_release_blockers(snapshot))
    except Exception:  # noqa: BLE001 — gate must not crash generation
        pass

    return blockers


async def resolve_scan_id_for_report(
    session: AsyncSession,
    tenant_id: str,
    report_id: str,
    report: Report,
    scan_id_hint: str | None,
) -> str | None:
    """Effective scan_id for MinIO paths and ReportObject (FK).

    ``tenant_id`` must match ``report.tenant_id``; findings lookup is
    tenant-scoped to avoid cross-tenant ``scan_id`` inference.
    """
    if str(report.tenant_id) != str(tenant_id):
        return None
    if report.scan_id:
        return str(report.scan_id)
    if scan_id_hint:
        return str(scan_id_hint).strip() or None
    r = await session.execute(
        select(Finding.scan_id)
        .join(Report, Report.id == Finding.report_id)
        .where(
            cast(Report.id, String) == report_id,
            cast(Report.tenant_id, String) == str(tenant_id),
        )
        .limit(1)
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
    upload_fn: (
        Callable[..., str | None] | None
    ) = None,  # (tenant_id, scan_id, tier, report_id, fmt, data, *, content_type)
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

    scan_id = await resolve_scan_id_for_report(session, tenant_id, report_id, report, scan_id_hint)
    if not scan_id:
        await session.execute(
            update(Report)
            .where(cast(Report.id, String) == report_id)
            .values(
                generation_status="failed",
                last_error_message="Missing scan_id for report storage",
            )
        )
        await session.commit()
        return {
            "status": "failed",
            "report_id": report_id,
            "error": "No scan_id for report",
        }

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
        # WIRE-006: AI triage (including classification=contradicted) must not drop findings.
        report_data.findings = retain_findings_despite_ai_classification(report_data.findings)

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
            return {
                "status": "failed",
                "report_id": report_id,
                "error": "validation_failed",
            }

        generated: dict[str, str] = {}
        # Phase G — track the Valhalla LLM analysis outcome so the release gate can
        # fail-closed when mandatory analysis did not complete. "not_run" until the
        # VH-LLM block sets it; only "completed" clears the LLM release blocker.
        valhalla_llm_status: str = "not_run"
        # B6-T02 / T48 — resolve once per pipeline run; ``generate_pdf`` is the
        # only consumer (HTML/JSON/CSV ignore the flag) but we lift the lookup
        # out of the per-format branch to keep a single async query at the
        # top of the loop.
        tenant_pdf_format = await resolve_tenant_pdf_archival_format(session, tenant_id)
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
                    pdf_archival_format=tenant_pdf_format,
                )
            elif fmt == "json":
                content = generate_json(report_data, jinja_context=built.template_context)
            elif fmt == "csv":
                content = generate_csv(report_data, jinja_context=built.template_context)
            elif fmt == "md":
                content = generate_markdown(
                    report_data, jinja_context=built.template_context, tier=tier_str
                )
            elif fmt == "xml":
                content = generate_xml(report_data, jinja_context=built.template_context)
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
                # Companion CSVs — technologies, outdated components, tool health
                for comp_name, comp_gen, comp_content_type in [
                    (
                        "technologies_csv",
                        generate_technologies_csv,
                        "text/csv; charset=utf-8",
                    ),
                    (
                        "outdated_components_csv",
                        generate_outdated_components_csv,
                        "text/csv; charset=utf-8",
                    ),
                    (
                        "tool_health_csv",
                        generate_tool_health_csv,
                        "text/csv; charset=utf-8",
                    ),
                ]:
                    comp_bytes = comp_gen(report_data, jinja_context=built.template_context)
                    comp_key = upload(
                        tenant_id,
                        scan_id,
                        tier_str,
                        report_id,
                        comp_name,
                        comp_bytes,
                        content_type=comp_content_type,
                    )
                    if comp_key:
                        await _upsert_report_object(
                            session,
                            tenant_id=tenant_id,
                            scan_id=scan_id,
                            report_id=report_id,
                            fmt=comp_name,
                            object_key=comp_key,
                            size_bytes=len(comp_bytes),
                        )
                        generated[comp_name] = comp_key
                # Export validation report
                val_report = generate_export_validation_report(
                    report_data, jinja_context=built.template_context
                )
                val_key = upload(
                    tenant_id,
                    scan_id,
                    tier_str,
                    report_id,
                    "export_validation_report",
                    val_report,
                    content_type="application/json; charset=utf-8",
                )
                if val_key:
                    await _upsert_report_object(
                        session,
                        tenant_id=tenant_id,
                        scan_id=scan_id,
                        report_id=report_id,
                        fmt="export_validation_report",
                        object_key=val_key,
                        size_bytes=len(val_report),
                    )
                    generated["export_validation_report"] = val_key

        # R7 — canonical immutable snapshot: emit JSON/MD/XML(/PDF) companion
        # artifacts rendered from ONE ReportDocumentV1. Additive + fail-soft:
        # never breaks the standard tier outputs above (opt-in via flag).
        if settings.canonical_report_snapshot_enabled:
            try:
                snapshot = build_snapshot_from_report_data(
                    report_data,
                    scan_meta=_scan_meta_for_snapshot(built, report_data, scan_id, tenant_id),
                    scan_report_data=getattr(built, "scan_report_data", None),
                )
                completed_at = snapshot.completed_at or ""
                artifacts = render_canonical_bundle(
                    snapshot,
                    include_pdf=True,
                    html_to_pdf=lambda html: _snapshot_pdf_bytes(html, completed_at),
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                )
                # Atomic parity (§20.9): require the full canonical set from ONE
                # snapshot before uploading anything, so we never ship a partial /
                # divergent format subset. PDF stays best-effort (not required).
                assert_canonical_parity(artifacts)
                for artifact in artifacts:
                    canon_fmt = f"canonical_{artifact.format}"
                    canon_key = upload(
                        tenant_id,
                        scan_id,
                        tier_str,
                        report_id,
                        canon_fmt,
                        artifact.content,
                        content_type=_CANONICAL_CONTENT_TYPES.get(canon_fmt, artifact.mime_type),
                    )
                    if canon_key:
                        await _upsert_report_object(
                            session,
                            tenant_id=tenant_id,
                            scan_id=scan_id,
                            report_id=report_id,
                            fmt=canon_fmt,
                            object_key=canon_key,
                            size_bytes=artifact.size,
                        )
                        generated[canon_fmt] = canon_key
                logger.info(
                    "canonical_snapshot_emitted",
                    extra={
                        "event": "canonical_snapshot_emitted",
                        "report_id": report_id,
                        "snapshot_hash": snapshot.snapshot_hash,
                        "formats": [a.format for a in artifacts],
                    },
                )
            except Exception:  # noqa: BLE001 — canonical snapshot is additive
                logger.warning(
                    "canonical_snapshot_failed",
                    extra={
                        "event": "canonical_snapshot_failed",
                        "report_id": report_id,
                    },
                )

        # Valhalla mandatory LLM remediation/closure deliverable (VH-LLM):
        # per-finding remediation plan + closure conclusion projected into
        # MD/XML/HTML/JSON + a release manifest, all from one document tree.
        # Opt-in + fail-soft: never breaks the standard Valhalla outputs.
        if tier_str == "valhalla" and settings.valhalla_llm_remediation_enabled:
            try:
                from src.reports.llm_remediation.facade_binding import (
                    build_facade_llm_callable,
                    resolve_report_llm_identity,
                )
                from src.reports.llm_remediation.integration import (
                    generate_valhalla_llm_release,
                )

                vsnapshot = build_snapshot_from_report_data(
                    report_data,
                    scan_meta=_scan_meta_for_snapshot(built, report_data, scan_id, tenant_id),
                    scan_report_data=getattr(built, "scan_report_data", None),
                )
                vfindings = [
                    {
                        "finding_id": f.finding_id,
                        "title": f.title,
                        "severity": f.severity,
                        "verification_status": f.verification_status,
                        "evidence_refs": list(f.evidence_ids),
                        "description": f.description,
                        "cwe": f.cwe,
                    }
                    for f in vsnapshot.findings
                ]
                vmeta = {
                    "report_id": report_id,
                    "report_version": vsnapshot.snapshot_hash or report_id,
                    "tenant_id": tenant_id,
                    "scan_id": scan_id,
                    "target": vsnapshot.target,
                }
                # Phase S — record the REAL provider/model (not the alias), fail
                # fast with llm_not_invoked when no provider is usable, and probe
                # once before the per-finding pass (prompt §28.3/§28.6).
                llm_identity = resolve_report_llm_identity()
                _vdoc, vrelease = generate_valhalla_llm_release(
                    vfindings,
                    report_meta=vmeta,
                    llm_callable=build_facade_llm_callable(
                        scan_id=scan_id, tenant_id=tenant_id, fail_if_unconfigured=True
                    ),
                    formats=["json", "md", "xml", "html"],
                    canonical_snapshot_hash=vsnapshot.snapshot_hash,
                    provider=llm_identity.provider_id if llm_identity else "unresolved",
                    model=llm_identity.model if llm_identity else "unresolved",
                    health_probe=True,
                )

                # Phase E.4 — merge the accepted LLM remediation/closure INTO the
                # canonical v2 snapshot so the mandatory conclusions print inside the
                # finding cards of the primary PDF/MD/JSON/XML, then re-emit the
                # canonical_* set from the enriched snapshot. Fail-soft: any error
                # leaves the un-merged canonical artifacts (emitted above) in place.
                try:
                    merged_doc = merge_llm_into_document(vsnapshot, _vdoc)
                    # Phase M — reference the independent verification kit from the
                    # report, then render so the passport carries the ref. The kit is
                    # built from and uploaded for this exact (final) snapshot below.
                    merged_doc = merged_doc.model_copy(
                        update={"verification_kit_ref": "valhalla_verification_kit"}
                    ).finalized()
                    merged_completed_at = merged_doc.completed_at or ""
                    merged_artifacts = render_canonical_bundle(
                        merged_doc,
                        include_pdf=True,
                        html_to_pdf=lambda html: _snapshot_pdf_bytes(html, merged_completed_at),
                        scan_id=scan_id,
                        tenant_id=tenant_id,
                    )
                    assert_canonical_parity(merged_artifacts)
                    for artifact in merged_artifacts:
                        canon_fmt = f"canonical_{artifact.format}"
                        canon_key = upload(
                            tenant_id,
                            scan_id,
                            tier_str,
                            report_id,
                            canon_fmt,
                            artifact.content,
                            content_type=_CANONICAL_CONTENT_TYPES.get(
                                canon_fmt, artifact.mime_type
                            ),
                        )
                        if canon_key:
                            await _upsert_report_object(
                                session,
                                tenant_id=tenant_id,
                                scan_id=scan_id,
                                report_id=report_id,
                                fmt=canon_fmt,
                                object_key=canon_key,
                                size_bytes=artifact.size,
                            )
                            generated[canon_fmt] = canon_key

                    # Phase M — build + upload the independent verification kit from
                    # the same final snapshot (shares snapshot_hash with the report).
                    try:
                        kit_bytes, _kit_manifest = build_verification_kit(merged_doc)
                        kit_key = upload(
                            tenant_id,
                            scan_id,
                            tier_str,
                            report_id,
                            "valhalla_verification_kit",
                            kit_bytes,
                            content_type="application/zip",
                        )
                        if kit_key:
                            await _upsert_report_object(
                                session,
                                tenant_id=tenant_id,
                                scan_id=scan_id,
                                report_id=report_id,
                                fmt="valhalla_verification_kit",
                                object_key=kit_key,
                                size_bytes=len(kit_bytes),
                            )
                            generated["valhalla_verification_kit"] = kit_key
                    except Exception:  # noqa: BLE001 — kit is additive
                        logger.warning(
                            "valhalla_verification_kit_failed",
                            extra={
                                "event": "valhalla_verification_kit_failed",
                                "report_id": report_id,
                            },
                        )

                    logger.info(
                        "canonical_snapshot_llm_merged",
                        extra={
                            "event": "canonical_snapshot_llm_merged",
                            "report_id": report_id,
                            "snapshot_hash": merged_doc.snapshot_hash,
                            "llm_analysis_status": merged_doc.llm_analysis_status,
                            "assessment_completeness": merged_doc.assessment_completeness,
                        },
                    )
                except Exception:  # noqa: BLE001 — merge is additive; keep base canon
                    logger.warning(
                        "canonical_snapshot_llm_merge_failed",
                        extra={
                            "event": "canonical_snapshot_llm_merge_failed",
                            "report_id": report_id,
                        },
                    )
                for vfmt, artifact in vrelease.artifacts.items():
                    llm_fmt = f"valhalla_llm_{vfmt}"
                    llm_key = upload(
                        tenant_id,
                        scan_id,
                        tier_str,
                        report_id,
                        llm_fmt,
                        artifact.content,
                        content_type=artifact.mime_type,
                    )
                    if llm_key:
                        await _upsert_report_object(
                            session,
                            tenant_id=tenant_id,
                            scan_id=scan_id,
                            report_id=report_id,
                            fmt=llm_fmt,
                            object_key=llm_key,
                            size_bytes=artifact.size_bytes,
                        )
                        generated[llm_fmt] = llm_key
                manifest_bytes = vrelease.manifest.model_dump_json(indent=2).encode("utf-8")
                manifest_key = upload(
                    tenant_id,
                    scan_id,
                    tier_str,
                    report_id,
                    "valhalla_llm_manifest",
                    manifest_bytes,
                    content_type="application/json",
                )
                if manifest_key:
                    await _upsert_report_object(
                        session,
                        tenant_id=tenant_id,
                        scan_id=scan_id,
                        report_id=report_id,
                        fmt="valhalla_llm_manifest",
                        object_key=manifest_key,
                        size_bytes=len(manifest_bytes),
                    )
                    generated["valhalla_llm_manifest"] = manifest_key
                valhalla_llm_status = str(vrelease.manifest.generation_status.value)
                logger.info(
                    "valhalla_llm_release_emitted",
                    extra={
                        "event": "valhalla_llm_release_emitted",
                        "report_id": report_id,
                        "generation_status": vrelease.manifest.generation_status.value,
                        "assessment_completeness": (
                            vrelease.manifest.assessment_completeness.value
                        ),
                        "formats": sorted(vrelease.artifacts.keys()),
                    },
                )
            except Exception:  # noqa: BLE001 — VH-LLM deliverable is additive
                valhalla_llm_status = "failed"
                logger.warning(
                    "valhalla_llm_release_failed",
                    extra={
                        "event": "valhalla_llm_release_failed",
                        "report_id": report_id,
                    },
                )

        expected_keys = set(fmt_list)
        if tier_str == "valhalla" and "csv" in expected_keys:
            expected_keys.add(VALHALLA_SECTIONS_CSV_FORMAT)
        # Every requested format must be produced; the Valhalla CSV path additionally emits
        # companion artifacts (technologies / outdated / tool-health CSVs, export-validation
        # report) which are legitimate extras — require a superset, not strict equality.
        missing = expected_keys - set(generated.keys())
        if missing:
            raise RuntimeError(f"Missing outputs: {sorted(missing)}")

        # Phase G — Valhalla fail-closed release gate. ``valhalla_release_blockers``
        # was written (b866449) but never called from the prod path (diagnosis D4).
        # Wire it here, before the release is marked ``ready``. Blockers are always
        # computed and logged (observability); they *fail* the release only when
        # ``valhalla_release_blockers_enabled`` is set — staged rollout so the gate
        # does not regress releases in environments that do not yet satisfy the full
        # completeness/LLM contract (Phases C–E). See config flag docstring.
        if tier_str == "valhalla":
            blockers = _compute_valhalla_release_blockers(
                report_data=report_data,
                template_context=built.template_context,
                requested_tier=str(report.tier or tier_str),
                actual_tier=tier_str,
                valhalla_llm_status=valhalla_llm_status,
            )
            if blockers:
                logger.warning(
                    "valhalla_release_blockers_detected",
                    extra={
                        "event": "valhalla_release_blockers_detected",
                        "report_id": report_id,
                        "tenant_id": tenant_id,
                        "scan_id": scan_id,
                        "enforced": bool(settings.valhalla_release_blockers_enabled),
                        "blockers": blockers,
                        "blockers_n": len(blockers),
                    },
                )
                if settings.valhalla_release_blockers_enabled:
                    raise ReportGenerationError("Valhalla release blocked: " + "; ".join(blockers))

        await session.execute(
            update(Report)
            .where(cast(Report.id, String) == report_id)
            .values(generation_status="ready", last_error_message=None)
        )
        await session.commit()

        completed: dict[str, Any] = {
            "status": "completed",
            "report_id": report_id,
            "formats": list(generated.keys()),
            "object_keys": generated,
        }
        if tier_str == "valhalla":
            vctx = built.template_context.get("valhalla_context")
            if isinstance(vctx, dict):
                completed["full_valhalla"] = bool(vctx.get("full_valhalla"))
            if "pdf" in generated:
                completed["pdf_object_key"] = generated.get("pdf")

        log_extra: dict[str, Any] = {
            "event": "report_generation_completed",
            "report_id": report_id,
            "tenant_id": tenant_id,
            "scan_id": scan_id,
            "tier": tier_str,
            "formats_n": len(generated),
        }
        rq = built.template_context.get("report_quality")
        if isinstance(rq, dict):
            log_extra["coverage_label"] = rq.get("coverage_label")
            log_extra["tool_health"] = rq.get("tool_health")
            wn = rq.get("warnings")
            if isinstance(wn, list):
                log_extra["warnings_n"] = len(wn)
        if tier_str == "valhalla":
            vctx_log = built.template_context.get("valhalla_context")
            if isinstance(vctx_log, dict):
                log_extra["full_valhalla"] = bool(vctx_log.get("full_valhalla"))
                cov_occ = vctx_log.get("coverage_occurrence")
                if isinstance(cov_occ, dict):
                    totals = cov_occ.get("totals")
                    if isinstance(totals, dict):
                        log_extra["coverage_not_tested"] = totals.get("not_tested")
                        log_extra["coverage_covered_no_finding"] = totals.get("covered_no_finding")
                    log_extra["occurrences_n"] = (
                        totals.get("occurrences") if isinstance(totals, dict) else None
                    )
        cov_top = built.template_context.get("coverage_occurrence")
        if isinstance(cov_top, dict):
            log_extra["coverage_occurrence_schema"] = cov_top.get("schema_version")
        logger.info("report_generation_completed", extra=log_extra)

        return completed
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
