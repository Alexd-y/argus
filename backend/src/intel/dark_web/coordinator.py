"""DWM collection coordinator — selectors -> collectors -> classify/redact ->
persist (MinIO raw + DB row + audit) -> DarkWebReport.

The pure assembly step (``build_observations_from_raw``) is DB/MinIO-free and
unit-tested directly; :func:`run_sweep` adds persistence and audit around it.
Nothing here ever raises out to the scan pipeline — a sweep degrades to an empty
report on error.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from typing import Any

from src.core.config import settings
from src.intel.dark_web.catalog import DarkWebCatalog, load_catalog
from src.intel.dark_web.classifier import classify
from src.intel.dark_web.collectors import default_breach_first_collectors
from src.intel.dark_web.collectors.base import BaseCollector
from src.intel.dark_web.contracts import (
    DarkWebObservation,
    DarkWebRawRecord,
    DarkWebReport,
    DarkWebReportStatus,
    DarkWebSelector,
    selector_hash,
)
from src.intel.dark_web.redaction import build_redacted_summary

logger = logging.getLogger(__name__)

_SEV_TO_TIER_FLOOR = {"critical": 2, "high": 2}


def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def build_observations_from_raw(
    records_by_selector: list[tuple[DarkWebSelector, list[DarkWebRawRecord]]],
    *,
    classifier_rules: dict[str, Any] | None = None,
) -> list[DarkWebObservation]:
    """Pure: classify + redact + hash each raw record into an observation."""

    out: list[DarkWebObservation] = []
    for selector, records in records_by_selector:
        for rec in records:
            c = classify(rec, classifier_rules)
            raw_sha = _sha256(rec.content)
            summary = build_redacted_summary(
                rec.content, prefix=f"[{c.exposure_type.value}/{rec.source_network.value}]"
            )
            out.append(
                DarkWebObservation(
                    selector_kind=selector.kind,
                    selector_value_hash=selector.value_hash or selector_hash(selector.value),
                    finding_id=selector.finding_id or rec.extra.get("finding_id", "") or "",
                    source_network=rec.source_network,
                    source_ref=rec.source_ref,
                    exposure_type=c.exposure_type,
                    severity=c.severity,
                    confidence=c.confidence,
                    evidence_tier=c.evidence_tier,  # already clamped <= 2
                    observed_at=rec.observed_at,
                    raw_sha256=raw_sha,
                    redacted_summary=summary,
                    collector=rec.collector,
                    provenance={
                        "source_ref": rec.source_ref,
                        "collector": rec.collector,
                        "selector_kind": selector.kind.value,
                    },
                )
            )
    return out


async def _store_raw(tenant_id: str, scan_id: str, content: str, sha: str) -> str:
    """Best-effort: upload the raw record to the argus-darkweb MinIO bucket."""

    if not content:
        return ""
    try:
        from src.storage import s3
        from src.storage.s3 import OBJECT_TYPE_DARKWEB

        s3.ensure_bucket(getattr(settings, "minio_darkweb_bucket", None))
        key = s3.upload(
            tenant_id,
            scan_id,
            OBJECT_TYPE_DARKWEB,
            f"{sha[:16]}.bin",
            content.encode("utf-8"),
            content_type="text/plain; charset=utf-8",
        )
        return key or ""
    except Exception:  # noqa: BLE001 - storage is best-effort; provenance sha still recorded
        logger.info("darkweb_raw_store_failed", extra={"scan_id": scan_id})
        return ""


_audit_logger: Any = None


def _get_audit_logger() -> Any:
    """Lazily build a process-local AuditLogger (no durable sink exists yet —
    the durable DWM record is the DB row's ``chain_hash``)."""

    global _audit_logger
    if _audit_logger is None:
        from src.policy.audit import AuditLogger, InMemoryAuditSink

        _audit_logger = AuditLogger(InMemoryAuditSink())
    return _audit_logger


def _audit(tenant_id: str, scan_id: str, obs: DarkWebObservation) -> str:
    """Best-effort DARKWEB_COLLECTION audit; returns the chain hash or ''."""

    if not _is_uuid(tenant_id):
        return ""
    try:
        from src.policy.audit import AuditEventType

        event = _get_audit_logger().emit(
            event_type=AuditEventType.DARKWEB_COLLECTION,
            tenant_id=uuid.UUID(tenant_id),
            scan_id=uuid.UUID(scan_id) if _is_uuid(scan_id) else None,
            decision_allowed=True,
            payload={
                "selector_kind": obs.selector_kind.value,
                "selector_value_hash": obs.selector_value_hash,
                "source_network": obs.source_network.value,
                "exposure_type": obs.exposure_type.value,
                "evidence_tier": obs.evidence_tier,
            },
        )
        return getattr(event, "event_hash", "") or ""
    except Exception:  # noqa: BLE001 - audit must never break collection
        logger.info("darkweb_audit_failed", extra={"scan_id": scan_id})
        return ""


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, TypeError, AttributeError):
        return False


async def _persist(session: Any, tenant_id: str, scan_id: str, obs: DarkWebObservation) -> None:
    """Insert one observation row (best-effort; caller handles commit)."""

    from src.intel.dark_web.models import DarkWebObservation as Row

    row = Row(
        tenant_id=tenant_id,
        scan_id=scan_id,
        finding_id=obs.finding_id or None,
        selector_kind=obs.selector_kind.value,
        selector_value_hash=obs.selector_value_hash,
        source_network=obs.source_network.value,
        source_ref=obs.source_ref or None,
        exposure_type=obs.exposure_type.value,
        severity=obs.severity.value,
        confidence=obs.confidence.value,
        evidence_tier=obs.evidence_tier,
        observed_at=obs.observed_at,
        raw_object_key=obs.raw_object_key or None,
        raw_sha256=obs.raw_sha256 or None,
        chain_hash=obs.chain_hash or None,
        redacted_summary=obs.redacted_summary or None,
        provenance=obs.provenance or None,
        collector=obs.collector or None,
    )
    session.add(row)


async def run_sweep(
    session: Any,
    tenant_id: str,
    scan_id: str,
    selectors: list[DarkWebSelector],
    *,
    target: str = "",
    collectors: list[BaseCollector] | None = None,
    catalog: DarkWebCatalog | None = None,
    store_raw: bool = True,
    persist: bool = True,
    audit: bool = True,
) -> DarkWebReport:
    """Run collectors over selectors and persist the results. Never raises."""

    report = DarkWebReport(
        scan_id=scan_id,
        target=target,
        selectors_count=len(selectors),
        status=DarkWebReportStatus.NOT_COLLECTED,
    )
    try:
        catalog = catalog or load_catalog()
        collectors = collectors if collectors is not None else default_breach_first_collectors()
        active = [c for c in collectors if c.is_enabled()]

        records_by_selector: list[tuple[DarkWebSelector, list[DarkWebRawRecord]]] = []
        for selector in selectors:
            for collector in active:
                recs = await collector.safe_collect(selector)
                if recs:
                    records_by_selector.append((selector, recs))

        observations = build_observations_from_raw(
            records_by_selector, classifier_rules=catalog.classifier_rules
        )

        for obs in observations:
            if store_raw:
                # Re-derive the raw text we classified from the summary is lossy; the
                # raw record content was hashed into raw_sha256. Store the redacted
                # summary as the retrievable artifact (plaintext raw stays only if a
                # collector provided it — not persisted plaintext here for MVP).
                key = await _store_raw(tenant_id, scan_id, obs.redacted_summary, obs.raw_sha256)
                if key:
                    object.__setattr__(obs, "raw_object_key", key)
            if audit:
                chain = _audit(tenant_id, scan_id, obs)
                if chain:
                    object.__setattr__(obs, "chain_hash", chain)
            if persist and session is not None:
                await _persist(session, tenant_id, scan_id, obs)

        report = DarkWebReport(
            scan_id=scan_id,
            target=target,
            selectors_count=len(selectors),
            observations=observations,
            status=DarkWebReportStatus.PRESENT if observations else DarkWebReportStatus.RAN_EMPTY,
        )
    except Exception:  # noqa: BLE001 - a sweep must never break the scan pipeline
        logger.exception("darkweb_sweep_failed", extra={"scan_id": scan_id})
    return report


__all__ = ["build_observations_from_raw", "run_sweep"]
