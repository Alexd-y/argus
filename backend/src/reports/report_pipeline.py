"""RPT-006 — Full report generation: ReportGenerator context, render, MinIO, ReportObject rows."""

from __future__ import annotations

import contextlib
import logging
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jinja2
from pydantic import ValidationError
from sqlalchemy import String, cast, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.models import Finding, Report, ReportObject
from src.findings.lifecycle_bridge import retain_findings_despite_ai_classification
from src.orchestration.scan_policy import registry_versions
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
from src.reports.report_document import ReportDocumentV1, ReportFailure
from src.reports.report_parity import count_findings_in_markdown, finding_count_parity
from src.reports.section_registry import iter_sections
from src.reports.snapshot_builder import build_snapshot_from_report_data
from src.reports.snapshot_completeness_gate import snapshot_release_blockers
from src.reports.tenant_pdf_format import resolve_tenant_pdf_archival_format
from src.reports.valhalla_completeness import (
    REQUIRED_SOURCE_TO_REGISTRY_SECTIONS,
    VALHALLA_REQUIRED_SOURCES,
    valhalla_release_blockers,
)
from src.reports.valhalla_llm_merge import merge_llm_into_document
from src.reports.valhalla_severity_review_gate import severity_review_blockers
from src.reports.verification_kit import build_verification_kit
from src.reports.wstg_coverage import build_test_limitations
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
        # Rendered-but-empty / disabled backend: surface it (RC-17 "no PDF" blocks
        # the Valhalla release, so a silent failure here is a dead end to debug).
        logger.warning(
            "canonical_pdf_unavailable",
            extra={
                "event": "canonical_pdf_unavailable",
                "backend": type(backend).__name__,
            },
        )
    except Exception as exc:  # noqa: BLE001 — PDF is best-effort, never break the pipeline
        logger.warning(
            "canonical_pdf_render_error",
            extra={"event": "canonical_pdf_render_error", "error_type": type(exc).__name__},
        )
        return None
    return None


def _iso_or_none(value: Any) -> str | None:
    """Stringify a timestamp for the snapshot passport (``started_at``/``completed_at``
    are typed ``str | None`` with ``extra="forbid"`` — a raw ``datetime`` raises a
    ValidationError that kills the whole snapshot build)."""
    if value is None:
        return None
    iso = getattr(value, "isoformat", None)
    return iso() if callable(iso) else str(value)


def _scan_meta_for_snapshot(
    built: Any, report_data: Any, scan_id: str, tenant_id: str
) -> dict[str, Any]:
    """Assemble snapshot scan-meta from ScanReportData.scan (tolerant getattr).

    Also folds generation-time degradations into the snapshot so they reach the client
    bundle, not only the logs: failed AI sections (RC-15) become ``failures`` /
    ``skipped_reasons``, and a branded-PDF template fallback recorded on the template
    context (RC-18) becomes a ``failure``.
    """
    scan_row = getattr(getattr(built, "scan_report_data", None), "scan", None)
    failures: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    ai_results = getattr(built, "ai_section_results", None)
    if isinstance(ai_results, dict):
        for rec in ReportGenerator.ai_section_failures(ai_results):
            if rec.get("reason_code") == "skipped_no_llm":
                skipped.append(rec)
            else:
                failures.append(rec)
    tctx = getattr(built, "template_context", None)
    if isinstance(tctx, dict):
        for rf in tctx.get("render_failures") or []:
            if isinstance(rf, dict) and rf.get("where"):
                failures.append(rf)
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
        # R-13 passport scalar: the scans table has no started_at column, so the
        # scan's created_at is its start time. Without this the release gate blocks
        # every Valhalla report on "passport field 'started_at' is empty".
        "started_at": _iso_or_none(getattr(scan_row, "created_at", None)),
        "completed_at": _iso_or_none(getattr(report_data, "created_at", None)),
        "failures": failures,
        "skipped_reasons": skipped,
        # R-13 passport DICTS must be non-empty, and R-14 requires non-empty
        # ``limitations`` when the WSTG coverage gate fails. Populate them from
        # authoritative sources so the snapshot passport is complete and truthful
        # (not forced): the signed-catalog/profile registry versions, a scope
        # summary derived from the scan, and the standard NIST SP 800-115 test
        # limitations. Callers may still override via their own meta.
        "registry_versions": registry_versions(
            tool_registry_version=getattr(scan_row, "tool_registry_version", None),
            payload_registry_version=getattr(scan_row, "payload_registry_version", None),
            prompt_registry_version=getattr(scan_row, "prompt_registry_version", None),
        ),
        "scope_summary": {
            "target": getattr(report_data, "target", None),
            "scan_profile": getattr(scan_row, "scan_profile", None),
            "execution_mode": getattr(scan_row, "execution_mode", None),
            "resolved_scan_mode": getattr(scan_row, "resolved_scan_mode", None)
            or getattr(scan_row, "scan_mode", None),
            "authorized_targets_only": True,
        },
        # ReportDocumentV1.limitations is list[str]; build_test_limitations returns
        # structured dicts (category/description/impact) for the readable renderers, so
        # flatten each to a sentence here.
        "limitations": [
            f"{lim.get('description', '')} (scope: {lim.get('category', '')}; "
            f"impact: {lim.get('impact', '')})".strip()
            for lim in build_test_limitations({})
            if isinstance(lim, dict) and lim.get("description")
        ],
    }


class ReportGenerationError(Exception):
    """Raised when the report generation pipeline encounters a recoverable failure."""


REPORT_FORMAT_SET: frozenset[str] = frozenset({"pdf", "html", "json", "csv", "md", "xml"})
DEFAULT_REPORT_FORMATS: tuple[str, ...] = ("html", "json", "csv", "pdf", "md", "xml")

# Free-tier Midgard target format set (prompt §5.5): the free report is offered
# as all five of these, each built from the SAME free-tier projection. Introduced
# as a per-tier required set so the Midgard bundle guarantees all five without
# changing Valhalla's canonical set (``canonical_bundle.REQUIRED_CANONICAL_FORMATS``).
MIDGARD_FREE_FORMATS: tuple[str, ...] = ("pdf", "html", "json", "xml", "csv")

# Paid Asgard target format set (prompt §4): the paid report is offered as all
# five of these, each built from the SAME Asgard projection.
ASGARD_PAID_FORMATS: tuple[str, ...] = ("pdf", "json", "xml", "html", "csv")


def required_formats_for_tier(tier: str) -> tuple[str, ...]:
    """Minimum format set a tier's bundle must contain.

    Midgard → the five free-tier formats; Asgard → the five paid-tier formats;
    other tiers keep the existing default generation set. Pure helper, safe to
    call from the pipeline and from tests.
    """
    from src.services.reporting import normalize_report_tier

    t = normalize_report_tier(tier)
    if t == "midgard":
        return MIDGARD_FREE_FORMATS
    if t == "asgard":
        return ASGARD_PAID_FORMATS
    return DEFAULT_REPORT_FORMATS


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


def _guarded(label: str, fn: Callable[[], list[str]], blockers: list[str]) -> None:
    """Run one release sub-check fail-closed (RC-01).

    An exception inside a check ADDS a ``GATE-ERROR`` blocker instead of silently
    dropping the check. A gate that cannot be evaluated is a gate that fails.
    """
    try:
        blockers.extend(fn())
    except Exception as exc:  # noqa: BLE001 — fail-closed: an errored gate blocks release
        blockers.append(f"GATE-ERROR: {label} failed: {type(exc).__name__}")
        logger.warning(
            "release_gate_errored",
            extra={
                "event": "release_gate_errored",
                "gate": label,
                "error_type": type(exc).__name__,
            },
        )


def _vp04_inputs(doc: ReportDocumentV1) -> tuple[dict[str, Any], dict[str, Any]]:
    """Bridge the snapshot + ordered-section registry to the VALHALLA_REQUIRED_SOURCES
    vocabulary so VP-04 (source present / section empty) fires for real (RC-03).

    ``validate_valhalla_completeness`` pairs ``snapshot[src.key]`` with
    ``sections[src.section]`` over ``VALHALLA_REQUIRED_SOURCES`` — whose key/section
    names differ from the section-registry ids. The snap-map is built from the collected
    data; the sections-map is derived from the registry's per-section presence through the
    declarative ``REQUIRED_SOURCE_TO_REGISTRY_SECTIONS`` bridge (Wave 4 / Stage 2) — no
    inline transition map, so the mapping is single-sourced and drift-tested.
    """
    present = {st.section_id: st.present for st in iter_sections(doc)}
    snap: dict[str, Any] = {
        "findings": list(doc.findings),
        "evidence": list(doc.evidence_references),
        "tool_runs": list(doc.tool_runs),
        "raw_artifacts": [t for t in doc.tool_runs if t.raw_artifact_ref]
        + [f for f in doc.findings if f.raw_artifact_ref],
        "ports_services": [s for s in doc.surface_inventory if (s.port or s.service)],
        "tech_stack": [s for s in doc.surface_inventory if s.technology],
        "wstg_coverage": doc.wstg or {},
        "exploitation": list(doc.exploit_chains),
    }
    sections: dict[str, Any] = {}
    for src in VALHALLA_REQUIRED_SOURCES:
        reg_ids = REQUIRED_SOURCE_TO_REGISTRY_SECTIONS.get(src.section)
        if not reg_ids:
            # Unmapped (passport-only / limits / optional graph) or deliberately empty:
            # not subject to the VP-04 section rule → leave the section slot absent.
            continue
        sections[src.section] = any(present.get(r) for r in reg_ids)
    return snap, sections


def _degrade_doc_for_llm_merge_failure(doc: ReportDocumentV1, reason: str) -> ReportDocumentV1:
    """Reflect an LLM-merge failure IN the canonical document (RC-04).

    Marks the release ``partial`` / LLM ``failed`` and records a ``ReportFailure`` so the
    degradation is visible in all four canonical formats, not only the logs.
    """
    failures = [
        *doc.failures,
        ReportFailure(where="llm_merge", reason_code="llm_merge_failed", message=str(reason)[:480]),
    ]
    return doc.model_copy(
        update={
            "generation_status": "partial",
            "llm_analysis_status": "failed",
            "failures": failures,
        }
    ).finalized()


def _compute_valhalla_release_blockers(
    *,
    report_data: Any,
    template_context: dict[str, Any],
    requested_tier: str,
    actual_tier: str,
    valhalla_llm_status: str,
    llm_merge_failed: bool = False,
    ai_section_failed: bool = False,
    pdf_missing: bool = False,
    ledger_blockers: list[str] | None = None,
    scan_meta: dict[str, Any] | None = None,
) -> list[str]:
    """Evaluate the Valhalla release blockers fail-closed (Phase G, RC-01…RC-04).

    Every sub-check is guarded independently via :func:`_guarded`: an exception inside
    one ADDS a ``GATE-ERROR`` blocker instead of dropping it and the checks behind it
    (RC-01). A failed report-text render is itself a blocker, never a silent clean pass
    (RC-02). VP-04 runs against the real snapshot through the ordered-section registry
    bridge (RC-03). An upstream LLM-merge failure is surfaced as a blocker (RC-04). The
    VH-LLM manifest ``generation_status`` is ``ready`` on success; normalise it to the
    gate's ``completed`` vocabulary.
    """
    blockers: list[str] = []

    # --- Rendered report text (RC-02): a failed render is a blocker, not a clean pass.
    report_text: str | None = None
    try:
        report_text = generate_markdown(
            report_data, jinja_context=template_context, tier=actual_tier
        ).decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 — fail-closed
        blockers.append(f"GATE-ERROR: report_text unavailable: {type(exc).__name__}")
        logger.warning(
            "release_gate_errored",
            extra={
                "event": "release_gate_errored",
                "gate": "report_text",
                "error_type": type(exc).__name__,
            },
        )

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

    # --- Canonical snapshot (built once; several checks consume it). Guarded (RC-01).
    snapshot: Any = None
    try:
        # Build the snapshot with the FULL scan-meta (passport scalars + dicts +
        # limitations), not just the tier — otherwise the passport is empty and the
        # gate blocks itself on R-13/R-14 for data that exists upstream (RC-03).
        _snap_meta = dict(scan_meta or {})
        _snap_meta["tier"] = actual_tier
        snapshot = build_snapshot_from_report_data(report_data, scan_meta=_snap_meta)
    except Exception as exc:  # noqa: BLE001 — fail-closed
        blockers.append(f"GATE-ERROR: snapshot build failed: {type(exc).__name__}")
        logger.warning(
            "release_gate_errored",
            extra={
                "event": "release_gate_errored",
                "gate": "snapshot",
                "error_type": type(exc).__name__,
            },
        )

    # --- VP-01/02/04/05/§9 — tier swap, stop-list, source/section parity (RC-03),
    #     unclassified-in-registry, mandatory-LLM. VP-04 now uses the real snapshot.
    def _completeness() -> list[str]:
        snap_map, sections_map = _vp04_inputs(snapshot) if snapshot is not None else ({}, {})
        return valhalla_release_blockers(
            snapshot=snap_map,
            sections=sections_map,
            report_text=report_text or "",
            findings=findings,
            requested_tier=requested_tier,
            actual_tier=actual_tier,
            llm_analysis_status=llm_analysis_status,
        )

    _guarded("completeness", _completeness, blockers)

    # --- Phase N — prose discipline on the rendered text (only when text is available).
    # Reference-requirement defaults off; the unconditional stop-list / absolute-safety
    # BLOCK rules always apply. Operators opt in via report_require_prose_references.
    _require_refs = bool(settings.report_require_prose_references)
    if report_text is not None:

        def _prose() -> list[str]:
            return [
                f"PROSE: {pv.rule}: {pv.detail}"
                for pv in blocking_prose_violations(
                    evaluate_prose(report_text, require_references=_require_refs)
                )
            ]

        _guarded("prose", _prose, blockers)

    # --- Phase O/T/U/9/Q — all consume the snapshot; each guarded independently (RC-01).
    if snapshot is not None:
        _guarded(
            "severity_review",
            lambda: list(severity_review_blockers(snapshot.findings)),
            blockers,
        )

        if report_text is not None:

            def _output_consistency() -> list[str]:
                from src.reports.evidence_references import build_evidence_reference_index

                known_ids = {f.finding_id for f in snapshot.findings if f.finding_id}
                has_proven = any(c.kind == "proven" for c in snapshot.exploit_chains)
                wstg_pct = None
                if isinstance(snapshot.wstg, dict):
                    raw_pct = snapshot.wstg.get("coverage_pct")
                    wstg_pct = float(raw_pct) if isinstance(raw_pct, (int, float)) else None
                # R-6.2.2/3 — reference resolvability: a [CL-…]/[E-…] marker in prose must
                # name a label minted from this report's findings/evidence; a dangling
                # reference is a release blocker.
                ref_index = build_evidence_reference_index(
                    [
                        {"finding_id": f.finding_id, "evidence_ids": list(f.evidence_ids)}
                        for f in snapshot.findings
                    ]
                )
                return [
                    f"OUTPUT: {cv.rule}: {cv.detail}"
                    for cv in blocking_prose_violations(
                        check_output_consistency(
                            report_text,
                            known_finding_ids=known_ids,
                            has_proven_chains=has_proven,
                            wstg_coverage_pct=wstg_pct,
                            known_reference_labels=ref_index.known_labels(),
                        )
                    )
                ]

            _guarded("output_consistency", _output_consistency, blockers)

        _guarded(
            "snapshot_completeness",
            lambda: list(snapshot_release_blockers(snapshot)),
            blockers,
        )

        def _content_parity() -> list[str]:
            from src.reports.renderers import render_html, render_json, render_markdown, render_xml
            from src.reports.report_content_parity import content_parity_blockers
            from src.reports.report_parity import (
                finding_id_set_parity,
                finding_ids_in_canonical_json,
            )

            canon_json = render_json(snapshot)
            canon = {
                "json": canon_json.encode("utf-8"),
                "md": render_markdown(snapshot).encode("utf-8"),
                "xml": render_xml(snapshot).encode("utf-8"),
                "html": render_html(snapshot).encode("utf-8"),
            }
            out = [f"PARITY: {pb}" for pb in content_parity_blockers(canon, doc=snapshot)]
            # R-6.2.4 — finding-ID *set* parity (not counts): the rendered registry must
            # expose exactly the snapshot's finding ids — no phantom, none dropped.
            json_ids = finding_ids_in_canonical_json(canon_json)
            if json_ids is not None:
                snap_ids = {f.finding_id for f in snapshot.findings if f.finding_id}
                out += [
                    f"PARITY: {pb}"
                    for pb in finding_id_set_parity(
                        {"snapshot": snap_ids, "canonical_json": json_ids},
                        reference="snapshot",
                    )
                ]
            return out

        _guarded("content_parity", _content_parity, blockers)

        def _count_parity() -> list[str]:
            counts: dict[str, int] = {
                "snapshot": len(snapshot.findings) + len(snapshot.unconfirmed_observations)
            }
            md_count = count_findings_in_markdown(report_text or "")
            if md_count is not None:
                counts["main_md"] = md_count
            return list(finding_count_parity(counts))

        _guarded("count_parity", _count_parity, blockers)

    # --- RC-04 — an upstream LLM-merge failure makes the canonical remediation/closure
    #     incomplete; surface it as a blocker (logged always, enforced when enabled).
    if llm_merge_failed:
        blockers.append("GATE-ERROR: llm_merge failed; canonical remediation/closure incomplete")

    # --- RC-15 — a mandatory AI section failed to generate; the report is not complete.
    if ai_section_failed:
        blockers.append("GATE-ERROR: AI section generation failed; report is incomplete")

    # --- RC-17 — a Valhalla deliverable with no PDF is incomplete; the absence must be
    #     noticed (honest draft) rather than shipped silently.
    if pdf_missing:
        blockers.append("GATE-ERROR: no PDF in the Valhalla bundle; deliverable is incomplete")

    # --- Wave 4 / R-6.1.2 — a stored artifact the report neither presented nor explicitly
    #     excluded (the ledger's ``unprocessed`` state) is a completeness blocker. Computed
    #     in the async pipeline scope (DB-backed) and threaded in here.
    if ledger_blockers:
        blockers.extend(ledger_blockers)

    return blockers


async def _build_artifact_ledger_blockers(
    session: AsyncSession,
    *,
    built: Any,
    report_data: Any,
    report_id: str,
    scan_id: str,
    tenant_id: str,
) -> list[str]:
    """Build + persist the per-artifact accounting ledger and return its blockers.

    Fail-closed (Wave 4 / R-6.1.2): any error building the ledger is itself a blocker,
    never a silent clean pass. The ledger is always persisted + logged; the caller
    decides whether the blockers are *enforced* (``artifact_ledger_enforced``).
    """
    try:
        from src.reports.artifact_ledger import ledger_release_blockers
        from src.reports.artifact_ledger_builder import build_and_persist_ledger

        snapshot = build_snapshot_from_report_data(
            report_data,
            scan_meta=_scan_meta_for_snapshot(built, report_data, scan_id, tenant_id),
            scan_report_data=getattr(built, "scan_report_data", None),
        )
        entries = await build_and_persist_ledger(
            session,
            tenant_id=tenant_id,
            scan_id=scan_id,
            report_id=report_id,
            doc=snapshot,
        )
        return ledger_release_blockers(entries)
    except ValidationError as exc:  # surface the offending field, don't discard it
        logger.warning(
            "artifact_ledger_errored",
            extra={
                "event": "artifact_ledger_errored",
                "report_id": report_id,
                "error_type": "ValidationError",
                "errors": exc.errors()[:20],
            },
        )
        return [f"GATE-ERROR: artifact_ledger failed: ValidationError: {str(exc)[:300]}"]
    except Exception as exc:  # noqa: BLE001 — fail-closed: an errored ledger blocks release
        logger.warning(
            "artifact_ledger_errored",
            extra={
                "event": "artifact_ledger_errored",
                "report_id": report_id,
                "error_type": type(exc).__name__,
            },
        )
        return [f"GATE-ERROR: artifact_ledger failed: {type(exc).__name__}"]


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
    """One row per (report_id, format): overwrite object_key and size.

    Tolerant of pre-existing duplicates: there is no unique constraint on
    (report_id, format), so a race or a prior double-write can leave more than one
    row — ``scalar_one_or_none`` would then raise ``MultipleResultsFound`` and abort
    the whole canonical bundle (observed as ``canonical_snapshot_llm_merge_failed`` →
    "no PDF"). Update the first row, collapse any extras, so the invariant self-heals.
    """
    result = await session.execute(
        select(ReportObject).where(
            cast(ReportObject.report_id, String) == report_id,
            ReportObject.format == fmt,
        )
    )
    rows = list(result.scalars().all())
    if rows:
        existing = rows[0]
        existing.object_key = object_key
        existing.size_bytes = size_bytes
        existing.scan_id = scan_id
        existing.tenant_id = tenant_id
        for extra in rows[1:]:
            await session.delete(extra)
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


async def _rgp_valhalla_llm_remediation(
    artifact,
    built,
    canon_fmt,
    canon_key,
    generated,
    report_data,
    report_id,
    scan_id,
    session,
    tenant_id,
    tier_str,
    upload,
    valhalla_llm_status,
    vfmt,
):
    llm_merge_failed = False
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
            # The remediation LLM needs concrete grounding to produce a VALIDATED
            # fix (endpoint, component/version, demonstrated impact, evidence text),
            # not just a title + CWE. Without it every finding honestly returns
            # insufficient_context and the release can never leave draft — the
            # context package was being starved, not the findings. Forward the
            # snapshot finding's resolvable location/stack/impact fields and the
            # redacted evidence descriptions (build_finding_context redacts again,
            # so no raw secret reaches the model) into the per-finding context.
            _evidence_text = {
                e.evidence_id: e.description
                for e in (vsnapshot.evidence_references or [])
                if e.description
            }
            # Provability partition (VHL-PROVABLE-001): only a provable finding is
            # required to reach a validated remediation for the release to be a
            # completed final; a non-provable "unconfirmed — requires manual
            # verification" observation is reported honestly and does not hold the
            # release in draft. Computed on report_data.findings (the shape
            # is_provable_from_raw expects, same objects the main render partitions)
            # and keyed by finding_id, which the snapshot preserves.
            from src.reports.evidence_partition import is_provable_from_raw

            _provable_by_id: dict[str, bool] = {}
            for _rf in report_data.findings or []:
                _fid = str(getattr(_rf, "finding_id", "") or "")
                if _fid:
                    _provable_by_id[_fid] = is_provable_from_raw(_rf)
            vfindings = []
            vfragments: dict[str, dict[str, str]] = {}
            for f in vsnapshot.findings:
                ev_ids = list(f.evidence_ids)
                vfindings.append(
                    {
                        "finding_id": f.finding_id,
                        "title": f.title,
                        "severity": f.severity,
                        "verification_status": f.verification_status,
                        "evidence_refs": ev_ids,
                        "description": f.description,
                        "cwe": f.cwe,
                        # provability gate for the completeness assessment
                        "is_provable": _provable_by_id.get(f.finding_id, True),
                        # location / asset so the plan can name a concrete control
                        "asset": f.asset or vsnapshot.target,
                        "endpoint": f.url or f.path,
                        "port": f.port,
                        "parameter": f.parameter,
                        # stack so the plan stops guessing (the insufficient_context trigger)
                        "components": [f.component] if f.component else [],
                        "confirmed_versions": [f.observed_version] if f.observed_version else [],
                        "cvss": f.cvss_vector,
                        "confidence": f.confidence,
                        # demonstrated exploitation → the plan can ground the retest
                        "demonstrated": f.exploit_demonstrated,
                        "hypothesis": f.exploit_summary or f.potential_impact,
                    }
                )
                # The concrete observed artefact (DMARC TXT, dig answer, captured
                # request/response, replay command) lives on the PoC, not in the
                # evidence-row label — without it the model only sees "Finding PoC
                # JSON" and asks for the actual value. Fold the PoC evidence into
                # the finding's allowed evidence fragment so the plan can ground a
                # validated fix + retest (context.build_finding_context filters by
                # allowed id and redacts again).
                poc = f.poc
                poc_bits: list[str] = []
                if poc is not None:
                    for label, val in (
                        ("observed", poc.observation),
                        ("command", poc.command),
                        ("payload", poc.payload),
                        ("request", poc.http_request),
                        ("response", poc.http_response),
                    ):
                        if val:
                            poc_bits.append(f"{label}: {val}")
                poc_text = "\n".join(poc_bits)
                frag: dict[str, str] = {}
                for i, eid in enumerate(ev_ids):
                    parts = []
                    if eid in _evidence_text:
                        parts.append(_evidence_text[eid])
                    # Attach the PoC evidence to the finding's first evidence id so
                    # it rides an allowed ref rather than being filtered out.
                    if poc_text and i == 0:
                        parts.append(poc_text)
                    if parts:
                        frag[eid] = "\n".join(parts)
                if frag:
                    vfragments[f.finding_id] = frag
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
                evidence_fragments=vfragments,
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
                    # Single-artifact mode: in-memory parity + gate only; ship only Jinja.
                    if settings.valhalla_single_artifact_per_format:
                        continue
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
            except Exception as merge_exc:  # noqa: BLE001 — surface, don't hide (RC-04)
                llm_merge_failed = True
                logger.warning(
                    "canonical_snapshot_llm_merge_failed",
                    extra={
                        "event": "canonical_snapshot_llm_merge_failed",
                        "report_id": report_id,
                        "error_type": type(merge_exc).__name__,
                    },
                )
                # Re-render the canonical bundle from a degraded copy so the failure is
                # visible in all four client formats, not only the logs (RC-04). The
                # degraded doc carries generation_status=partial / llm_analysis_status=
                # failed + a ReportFailure(where="llm_merge").
                try:
                    degraded_doc = _degrade_doc_for_llm_merge_failure(
                        vsnapshot, safe_report_task_error_message(merge_exc)
                    )
                    degraded_completed_at = degraded_doc.completed_at or ""
                    degraded_artifacts = render_canonical_bundle(
                        degraded_doc,
                        include_pdf=True,
                        html_to_pdf=lambda html: _snapshot_pdf_bytes(html, degraded_completed_at),
                        scan_id=scan_id,
                        tenant_id=tenant_id,
                    )
                    assert_canonical_parity(degraded_artifacts)
                    for artifact in degraded_artifacts:
                        canon_fmt = f"canonical_{artifact.format}"
                        # Single-artifact mode: in-memory parity only; ship only Jinja.
                        if settings.valhalla_single_artifact_per_format:
                            continue
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
                except Exception:  # noqa: BLE001 — degraded re-render is itself best-effort
                    logger.warning(
                        "canonical_snapshot_llm_merge_degrade_failed",
                        extra={
                            "event": "canonical_snapshot_llm_merge_degrade_failed",
                            "report_id": report_id,
                        },
                    )
            for vfmt, artifact in vrelease.artifacts.items():
                llm_fmt = f"valhalla_llm_{vfmt}"
                # Single-artifact mode: the LLM remediation/closure is already merged
                # into the canonical snapshot and recorded via the verification kit +
                # llm manifest; do NOT persist the standalone valhalla_llm_<fmt> duplicate.
                if settings.valhalla_single_artifact_per_format:
                    continue
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
                    "assessment_completeness": (vrelease.manifest.assessment_completeness.value),
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
    return (valhalla_llm_status, llm_merge_failed)


def redact_free_canonical_finding(f: Any) -> Any:
    """Redact paid per-finding DETAIL for the FREE (Midgard) canonical bundle.

    The canonical snapshot renders findings in full; for a free report it must
    stay inventory-only (title/severity/cwe/cvss). This nulls the description,
    impact, exploit outcome, PoC and verification command so none of the paid
    layer lands in the free canonical_* artifacts. The single free teaser writeup
    is built elsewhere (build_free_payload) from un-redacted data, so this does
    not blind it.
    """
    return f.model_copy(
        update={
            "exploit_demonstrated": False,
            "exploit_summary": None,
            "description": "",
            "observed_impact": None,
            "proof_of_concept": None,
            "verification_command": None,
        }
    )


async def _rgp_canonical_snapshot(
    built, generated, report_data, report_id, scan_id, session, tenant_id, tier_str, upload
):
    artifact = None
    canon_fmt = None
    canon_key = None
    if settings.canonical_report_snapshot_enabled:
        try:
            # Tier-gate the canonical snapshot (paid-content leak fix). The canonical
            # bundle is otherwise built from UN-projected report_data, so for a free
            # Midgard scan where Dark Web Monitoring ran it persisted dark-web (and
            # raw/PoC) into canonical_* artifacts keyed to the free report — bypassing
            # both Midgard defences. Project to the free-tier shape first:
            # classify_for_tier(..., MIDGARD) forces dark_web_monitoring to None and
            # strips raw/PoC. Paid tiers (asgard/valhalla) keep the full record.
            from src.services.reporting import normalize_report_tier

            if normalize_report_tier(tier_str) == "midgard":
                from dataclasses import replace as _dc_replace

                from src.reports.report_bundle import ReportTier
                from src.reports.tier_classifier import classify_for_tier

                report_data = classify_for_tier(report_data, ReportTier.MIDGARD)
                # Strip paid-tier per-finding DETAIL from the findings the canonical
                # bundle renders in full for a FREE report, leaving the inventory
                # fields (title/severity/cwe/cvss) only. The free tier's single
                # teaser writeup is built elsewhere (build_free_payload, from the
                # un-stripped report_data), so redacting here does not blind it.
                # Done here — not in _project_midgard — so the upstream teaser gate
                # (_is_safe_teaser_candidate) can still read exploit_demonstrated to
                # exclude proven-exploit findings from the free sample (clearing it
                # earlier would blind that gate: fail-open). Without this, every
                # finding's description landed in the free canonical_* artifacts.
                report_data = _dc_replace(
                    report_data,
                    findings=[redact_free_canonical_finding(f) for f in report_data.findings],
                )
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
                # Single-artifact mode (valhalla): the parity check above validated the
                # bundle in-memory; the gate re-renders canonical itself, so do NOT
                # persist the duplicate canonical_<fmt> object — ship only the Jinja design.
                if tier_str == "valhalla" and settings.valhalla_single_artifact_per_format:
                    continue
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
    return (
        artifact,
        canon_fmt,
        canon_key,
    )


async def _rgp_generate_formats(
    built,
    fmt_list,
    generated,
    report_data,
    report_id,
    scan_id,
    session,
    tenant_id,
    tenant_pdf_format,
    tier_str,
    upload,
):
    vfmt = None
    # Free-tier (Midgard) single projection point for the pipeline path too:
    # project the ReportData + context ONCE so every format (incl. json/csv/xml)
    # is built from the trimmed, leak-safe free-tier data (prompt §5.2/§5.3).
    template_context = built.template_context
    from src.services.reporting import normalize_report_tier

    _tier_norm = normalize_report_tier(tier_str)
    if _tier_norm == "midgard":
        from src.services.reporting import _apply_midgard_free_projection

        report_data, template_context = _apply_midgard_free_projection(
            report_data, template_context
        )
    elif _tier_norm == "asgard":
        from src.services.reporting import _apply_asgard_paid_projection

        report_data, template_context = _apply_asgard_paid_projection(report_data, template_context)
    # No per-row format union: each Report row renders ONLY its own requested
    # format. The generate-all bundle already creates one row per format
    # (DEFAULT_GENERATE_ALL_FORMATS), so unioning the full tier format set here
    # made every row re-render ALL formats — N duplicate objects per format and an
    # N-times slower bundle. The per-format rows still guarantee every format is
    # emitted, exactly once each.
    for fmt in fmt_list:
        if fmt == "html":
            content = generate_html(
                report_data,
                jinja_context=template_context,
                tier=tier_str,
            )
        elif fmt == "pdf":
            # Phase 1 (C-01): the canonical snapshot bundle emits the single
            # Valhalla PDF (``canonical_pdf``). Skip the legacy ``valhalla.html.j2``
            # PDF so the bundle never ships two competing, divergent PDFs. The
            # legacy layout stays available behind ``valhalla_legacy_pdf`` and is
            # only skipped when a canonical PDF will actually be produced.
            if (
                tier_str == "valhalla"
                and not settings.valhalla_single_artifact_per_format
                and not settings.valhalla_legacy_pdf
                and settings.canonical_report_snapshot_enabled
            ):
                # Legacy: the canonical bundle emits the single Valhalla PDF. In
                # single-artifact mode the Jinja "secreport" PDF IS the single
                # Valhalla PDF, so it is NOT skipped here.
                continue
            content = generate_pdf(
                report_data,
                jinja_context=template_context,
                tier=tier_str,
                pdf_archival_format=tenant_pdf_format,
            )
        elif fmt == "json":
            content = generate_json(report_data, jinja_context=template_context, tier=tier_str)
        elif fmt == "csv":
            content = generate_csv(report_data, jinja_context=template_context, tier=tier_str)
        elif fmt == "md":
            content = generate_markdown(report_data, jinja_context=template_context, tier=tier_str)
        elif fmt == "xml":
            content = generate_xml(report_data, jinja_context=template_context, tier=tier_str)
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
    return (vfmt,)


def _align_valhalla_wstg_display(
    report_data: Any,
    template_context: dict[str, Any] | None,
    *,
    tier: str,
) -> None:
    """Make the displayed WSTG headline equal the authoritative evidence-gated coverage.

    The Valhalla WSTG table historically rendered ``wstg_coverage.coverage_percentage``,
    which is the *legacy capability heuristic* (:func:`build_wstg_coverage`) — explicitly
    NOT the headline per its own docstring (it maps executed tool names to WSTG tests).
    The honest-draft gate (R-12) compares the rendered coverage against the authoritative
    ``build_wstg_block`` value the canonical snapshot carries, so the two disagreed and
    every Valhalla report was forced to ``draft`` over a cosmetic figure.

    Recompute the authoritative percentage from the SAME ``report_data`` the release gate
    snapshots (identical inputs → identical value) and write it back onto the display
    dict(s). Idempotent and fail-safe: any error, a disabled strict gate, or an undefined
    (``None``) coverage leaves the legacy value untouched — the report then stays an
    honest draft, never shows a wrong number.
    """
    if str(tier or "").strip().lower() != "valhalla":
        return
    try:
        from src.reports.snapshot_builder import _build_wstg_block

        block = _build_wstg_block(report_data, None, scan_meta={"tier": tier})
    except Exception:  # noqa: BLE001 — display alignment must never break generation
        return
    if not isinstance(block, dict):
        return
    pct = block.get("coverage_pct")
    if not isinstance(pct, (int, float)) or isinstance(pct, bool):
        return
    auth = round(float(pct), 4)

    # Collect every wstg_coverage dict the readable Valhalla render can read from —
    # the markdown/HTML path rebuilds its context from ``template_context["valhalla_context"]``
    # (a nested dict/object), NOT the top-level ``wstg_coverage`` key, so overwriting only
    # the latter misses the figure that actually renders. Walk all plausible carriers.
    display_dicts: list[dict[str, Any]] = []
    seen: set[int] = set()

    def _carrier_cov(carrier: Any) -> None:
        if carrier is None:
            return
        cov = carrier.get("wstg_coverage") if isinstance(carrier, dict) else getattr(
            carrier, "wstg_coverage", None
        )
        if isinstance(cov, dict) and id(cov) not in seen:
            seen.add(id(cov))
            display_dicts.append(cov)

    _carrier_cov(getattr(report_data, "valhalla_context", None))
    if isinstance(template_context, dict):
        tcov = template_context.get("wstg_coverage")
        if isinstance(tcov, dict) and id(tcov) not in seen:
            seen.add(id(tcov))
            display_dicts.append(tcov)
        _carrier_cov(template_context.get("valhalla_context"))
    for d in display_dicts:
        d["coverage_percentage"] = auth
        d["coverage_pct"] = auth


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

    # Report AI runs in a reports worker, which has no scan budget ledger (the
    # registry is process-local to the scan worker), so the §8.3 guard would deny
    # the paid cloud call. Register a bounded, ISOLATED in-memory ledger for the
    # report path: it enforces a hard report cap (no unbounded cloud spend) WITHOUT
    # touching the scan's shared Postgres budget row (no budget-control bypass). A
    # cap of 0 means "deny" — the cloud call then falls back to the local model.
    _report_ledger_registered = False
    if (
        getattr(settings, "budget_ledger_enabled", False)
        and float(getattr(settings, "report_ledger_max_cost_usd", 0.0) or 0.0) > 0
    ):
        try:
            from src.orchestration.budget_ledger import (
                BudgetLedger,
                BudgetScope,
                InMemoryBudgetStore,
            )
            from src.orchestration.budget_scan_registry import (
                get_scan_ledger,
                register_scan_ledger,
            )

            if get_scan_ledger(scan_id) is None:
                _store = InMemoryBudgetStore()
                _scope_keys = BudgetScope(
                    tenant_id=tenant_id, scan_id=scan_id
                ).keys()  # noqa: SIM118 — method, not dict
                for _k in _scope_keys:
                    await _store.set_limits(
                        _k,
                        max_tokens=int(settings.report_ledger_max_tokens),
                        max_cost_usd=float(settings.report_ledger_max_cost_usd),
                    )
                register_scan_ledger(scan_id, BudgetLedger(_store))
                _report_ledger_registered = True
        except Exception:
            logger.warning(
                "report_budget_ledger_register_failed",
                extra={"event": "report_budget_ledger_register_failed", "scan_id": scan_id},
            )

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
        # R-12 — align the displayed WSTG headline to the authoritative evidence-gated
        # coverage the release gate treats as truth, so a Valhalla report is not forced
        # to honest-draft over the legacy capability-heuristic percentage. Must run
        # before the per-format renders and the gate below both consume the context.
        _align_valhalla_wstg_display(report_data, built.template_context, tier=tier_str)
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
        (vfmt,) = await _rgp_generate_formats(
            built,
            fmt_list,
            generated,
            report_data,
            report_id,
            scan_id,
            session,
            tenant_id,
            tenant_pdf_format,
            tier_str,
            upload,
        )

        # R7 — canonical immutable snapshot: emit JSON/MD/XML(/PDF) companion
        # artifacts rendered from ONE ReportDocumentV1. Additive + fail-soft:
        # never breaks the standard tier outputs above (opt-in via flag).
        # Canonical snapshot (canonical_* companion artifacts) is a Valhalla
        # provability deliverable rendered from one ReportDocumentV1. For
        # Midgard/Asgard it is NOT consumed downstream (the plain per-format
        # objects are the deliverable) and emitting it per row produced duplicate
        # canonical_json/html/md/pdf/xml objects alongside the plain formats. Emit
        # it only for Valhalla.
        if tier_str == "valhalla":
            (
                artifact,
                canon_fmt,
                canon_key,
            ) = await _rgp_canonical_snapshot(
                built,
                generated,
                report_data,
                report_id,
                scan_id,
                session,
                tenant_id,
                tier_str,
                upload,
            )
        else:
            artifact, canon_fmt, canon_key = None, None, None

        # Valhalla mandatory LLM remediation/closure deliverable (VH-LLM):
        # per-finding remediation plan + closure conclusion projected into
        # MD/XML/HTML/JSON + a release manifest, all from one document tree.
        # Opt-in + fail-soft: never breaks the standard Valhalla outputs.
        valhalla_llm_status, llm_merge_failed = await _rgp_valhalla_llm_remediation(
            artifact,
            built,
            canon_fmt,
            canon_key,
            generated,
            report_data,
            report_id,
            scan_id,
            session,
            tenant_id,
            tier_str,
            upload,
            valhalla_llm_status,
            vfmt,
        )

        expected_keys = set(fmt_list)
        # Phase 1 (C-01): the legacy ``pdf`` is intentionally not generated for
        # tier=valhalla (the canonical bundle emits the single PDF), so it must not
        # be required in the completeness check.
        _legacy_pdf_skipped = (
            tier_str == "valhalla"
            and not settings.valhalla_legacy_pdf
            and settings.canonical_report_snapshot_enabled
        )
        if _legacy_pdf_skipped:
            expected_keys.discard("pdf")
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
        # Phase G/§33 — Valhalla release gate. Blockers are always computed and logged.
        # When enforcement is on (default), any blocker publishes an **honest draft**
        # (``generation_status='draft'`` with reasons recorded) instead of ``ready`` —
        # artifacts are already generated above, so nothing is discarded. This is the
        # honest-draft contract (§E.2/§33): a report that fails the completeness/
        # evidence/LLM/review contract must not claim to be a finished assessment, but
        # is still available for review rather than thrown away.
        release_status = "ready"
        release_error: str | None = None
        if tier_str == "valhalla":
            # RC-15 — a real AI-section failure (not a no-LLM skip) blocks the release
            # when mandatory LLM remediation is expected.
            _ai_fail = any(
                rec.get("reason_code") != "skipped_no_llm"
                for rec in ReportGenerator.ai_section_failures(
                    getattr(built, "ai_section_results", {}) or {}
                )
            )
            ai_section_failed = _ai_fail and settings.valhalla_llm_remediation_enabled
            # RC-17 — the client Valhalla bundle must carry a PDF (canonical or legacy);
            # its absence is an honest-draft blocker, not a silent omission.
            pdf_missing = not any(k in generated for k in ("pdf", "canonical_pdf"))
            # Wave 4 / R-6.1.2 — per-artifact accounting ledger. Reconcile every stored
            # artifact against the canonical snapshot's references, persist the ledger, and
            # surface any ``unprocessed`` artifact as a release blocker. Always built +
            # persisted + logged; only *enforced* (folded into the honest-draft gate) when
            # ``artifact_ledger_enforced`` is set. Fail-closed on its own errors.
            ledger_blockers = await _build_artifact_ledger_blockers(
                session,
                built=built,
                report_data=report_data,
                report_id=report_id,
                scan_id=scan_id,
                tenant_id=tenant_id,
            )
            blockers = _compute_valhalla_release_blockers(
                report_data=report_data,
                template_context=built.template_context,
                requested_tier=str(report.tier or tier_str),
                actual_tier=tier_str,
                valhalla_llm_status=valhalla_llm_status,
                llm_merge_failed=llm_merge_failed,
                ai_section_failed=ai_section_failed,
                pdf_missing=pdf_missing,
                ledger_blockers=(ledger_blockers if settings.artifact_ledger_enforced else None),
                scan_meta=_scan_meta_for_snapshot(built, report_data, scan_id, tenant_id),
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
                    release_status = "draft"
                    release_error = ("honest_draft: " + "; ".join(blockers))[:4000]

        await session.execute(
            update(Report)
            .where(cast(Report.id, String) == report_id)
            .values(generation_status=release_status, last_error_message=release_error)
        )
        await session.commit()

        completed: dict[str, Any] = {
            "status": "completed" if release_status == "ready" else "draft",
            "report_id": report_id,
            "generation_status": release_status,
            "formats": list(generated.keys()),
            "object_keys": generated,
        }
        if release_error:
            completed["release_blockers"] = release_error
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
    finally:
        # Drop the per-report in-memory ledger so its bounded budget does not leak
        # (and accumulate) across report runs for the same scan in this worker.
        if _report_ledger_registered:
            with contextlib.suppress(Exception):
                from src.orchestration.budget_scan_registry import unregister_scan_ledger

                unregister_scan_ledger(scan_id)

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
