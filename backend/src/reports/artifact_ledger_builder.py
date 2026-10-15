"""Build + persist the per-artifact accounting ledger (Wave 4 / Stage 1).

Glue between the pure :mod:`src.reports.artifact_ledger` reconciler and the world:

* :func:`collect_artifact_records` — every artifact a scan *stored* (Evidence rows +
  tool-run outputs), read tenant-scoped from the DB.
* :func:`referenced_sets_from_snapshot` — what the canonical report *references*
  (evidence ids, storage keys, executed tool-run ids). Pure.
* :func:`persist_artifact_ledger` — replace the scan's ledger rows for this report.
* :func:`build_and_persist_ledger` — the orchestrator the report pipeline calls.

The pipeline feeds the result to :func:`ledger_release_blockers` so an ``unprocessed``
artifact fails the release fail-closed (R-6.1.2).
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import String, cast, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.models import ArtifactLedger as ArtifactLedgerRow
from src.db.models import Evidence as EvidenceModel
from src.db.models import ToolRun as ToolRunModel
from src.reports.artifact_ledger import (
    ArtifactRecord,
    LedgerEntry,
    build_artifact_ledger,
    ledger_summary,
)
from src.reports.report_document import ReportDocumentV1

logger = logging.getLogger(__name__)

#: Tool-run output kinds that are routine service noise when unreferenced (R-6.1.1).
#: Used only as a *named* exclusion reason, never as a silent drop.
_SERVICE_OUTPUT_KINDS: frozenset[str] = frozenset({"heartbeat", "healthcheck", "liveness"})


async def collect_artifact_records(
    session: AsyncSession, tenant_id: str, scan_id: str
) -> list[ArtifactRecord]:
    """Every stored artifact for ``scan_id`` as :class:`ArtifactRecord`\\ s.

    Evidence rows come first (the richer, deliberately-collected proof) so that when a
    tool-run output and an Evidence row share a storage key, the Evidence row is the
    canonical copy and the tool-run copy is accounted as a duplicate.
    """
    records: list[ArtifactRecord] = []

    ev_rows = (
        (
            await session.execute(
                select(EvidenceModel)
                .where(
                    cast(EvidenceModel.tenant_id, String) == str(tenant_id),
                    cast(EvidenceModel.scan_id, String) == str(scan_id),
                )
                .order_by(EvidenceModel.created_at.asc().nullsfirst(), EvidenceModel.id.asc())
            )
        )
        .scalars()
        .all()
    )
    for ev in ev_rows:
        records.append(
            ArtifactRecord(
                scan_id=str(scan_id),
                evidence_id=str(ev.id),
                object_key=ev.object_key,
                kind=ev.kind,
                size_bytes=ev.size_bytes,
                source="evidence",
                tool_run_id=ev.tool_run_id,
            )
        )

    tr_rows = (
        (
            await session.execute(
                select(ToolRunModel)
                .where(
                    cast(ToolRunModel.tenant_id, String) == str(tenant_id),
                    cast(ToolRunModel.scan_id, String) == str(scan_id),
                    ToolRunModel.output_object_key.isnot(None),
                )
                .order_by(ToolRunModel.started_at.asc().nullsfirst(), ToolRunModel.id.asc())
            )
        )
        .scalars()
        .all()
    )
    for tr in tr_rows:
        records.append(
            ArtifactRecord(
                scan_id=str(scan_id),
                evidence_id=None,
                object_key=tr.output_object_key,
                kind="tool_output",
                size_bytes=None,
                source="tool_run",
                tool_run_id=str(tr.id),
            )
        )

    return records


def referenced_sets_from_snapshot(
    doc: ReportDocumentV1,
) -> tuple[set[str], set[str], set[str]]:
    """Return ``(referenced_keys, referenced_evidence_ids, referenced_tool_run_ids)``.

    The union of every artifact reference the report surfaces: evidence-register object
    keys + evidence ids, finding/observation ``raw_artifact_ref`` + ``evidence_ids``,
    coverage evidence ids, and the ids of every tool run listed in the execution log.
    """
    keys: set[str] = set()
    ev_ids: set[str] = set()
    tr_ids: set[str] = set()

    for ref in doc.evidence_references:
        if ref.evidence_id:
            ev_ids.add(ref.evidence_id)
        if ref.object_key:
            keys.add(ref.object_key)
        if getattr(ref, "producer_tool_run_id", None):
            tr_ids.add(ref.producer_tool_run_id)  # type: ignore[arg-type]

    for group in (doc.findings, doc.unconfirmed_observations):
        for f in group:
            for eid in f.evidence_ids:
                if eid:
                    ev_ids.add(eid)
            if f.raw_artifact_ref:
                keys.add(f.raw_artifact_ref)

    for cov in doc.coverage:
        for eid in cov.evidence_ids:
            if eid:
                ev_ids.add(eid)

    for tr in doc.tool_runs:
        if tr.tool_run_id:
            tr_ids.add(tr.tool_run_id)
        if tr.raw_artifact_ref:
            keys.add(tr.raw_artifact_ref)

    return keys, ev_ids, tr_ids


async def persist_artifact_ledger(
    session: AsyncSession,
    *,
    tenant_id: str,
    scan_id: str,
    report_id: str | None,
    entries: list[LedgerEntry],
) -> None:
    """Replace this report's ledger rows with ``entries`` (idempotent on regen).

    ``report_id`` is normally a real report; it is nullable (the accounting is
    scan-scoped and survives regeneration), so ``None`` is preserved as SQL NULL rather
    than coerced to the string ``"None"`` (which would break the FK).
    """
    report_key = str(report_id) if report_id is not None else None
    if report_key is not None:
        await session.execute(
            delete(ArtifactLedgerRow).where(
                cast(ArtifactLedgerRow.report_id, String) == report_key,
            )
        )
    for e in entries:
        art = e.artifact
        session.add(
            ArtifactLedgerRow(
                tenant_id=str(tenant_id),
                scan_id=str(scan_id),
                report_id=report_key,
                evidence_id=art.evidence_id,
                object_key=art.object_key,
                kind=art.kind,
                size_bytes=art.size_bytes,
                source=art.source,
                tool_run_id=art.tool_run_id,
                state=e.state.value,
                exclusion_reason=(
                    e.exclusion_reason.value if e.exclusion_reason is not None else None
                ),
                section_ref=e.section_ref,
            )
        )


async def build_and_persist_ledger(
    session: AsyncSession,
    *,
    tenant_id: str,
    scan_id: str,
    report_id: str,
    doc: ReportDocumentV1,
) -> list[LedgerEntry]:
    """Collect → reconcile → persist the ledger; return the entries for the gate.

    ``doc`` is the canonical snapshot the release gate evaluates, so the ledger's
    "referenced" view is exactly what the client report shows.
    """
    records = await collect_artifact_records(session, tenant_id, scan_id)
    keys, ev_ids, tr_ids = referenced_sets_from_snapshot(doc)
    size_limit = settings.artifact_ledger_size_limit_bytes or None
    entries = build_artifact_ledger(
        records,
        referenced_keys=keys,
        referenced_evidence_ids=ev_ids,
        referenced_tool_run_ids=frozenset(tr_ids),
        size_limit_bytes=size_limit,
        service_output_kinds=_SERVICE_OUTPUT_KINDS,
    )
    await persist_artifact_ledger(
        session,
        tenant_id=tenant_id,
        scan_id=scan_id,
        report_id=report_id,
        entries=entries,
    )
    summ = ledger_summary(entries)
    logger.info(
        "artifact_ledger_built",
        extra={
            "event": "artifact_ledger_built",
            "report_id": report_id,
            "scan_id": scan_id,
            "tenant_id": tenant_id,
            **summ,
        },
    )
    return entries


def ledger_entries_for_report(entries: list[LedgerEntry]) -> list[dict[str, Any]]:
    """Client-safe projection of the ledger for the report appendix (no object_key).

    Each row carries the opaque evidence id (or a tool-run token), kind, size, state,
    exclusion reason and section — never the internal storage key (C-29).
    """
    out: list[dict[str, Any]] = []
    for e in entries:
        art = e.artifact
        ref = art.evidence_id or (f"toolrun:{art.tool_run_id}" if art.tool_run_id else "—")
        out.append(
            {
                "ref": ref,
                "source": art.source,
                "kind": art.kind or "unknown",
                "size_bytes": art.size_bytes,
                "state": e.state.value,
                "exclusion_reason": (
                    e.exclusion_reason.value if e.exclusion_reason is not None else None
                ),
                "section_ref": e.section_ref,
            }
        )
    return out


__all__ = [
    "build_and_persist_ledger",
    "collect_artifact_records",
    "ledger_entries_for_report",
    "persist_artifact_ledger",
    "referenced_sets_from_snapshot",
]
