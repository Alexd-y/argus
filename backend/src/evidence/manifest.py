"""Evidence-base manifest + integrity verification (wave 2, R-5.6.2 – R-5.6.4).

The manifest is a per-scan, tamper-evident summary: a root hash over the
deterministically-sorted evidence checksums. The integrity-check command
(``scripts/verify_evidence_integrity.py``) recomputes each object's SHA-256 from
storage, re-derives the root hash, and compares against the stored manifest —
working on the data alone, without trusting the running application.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ManifestEntry:
    """One evidence artifact in a scan's manifest."""

    object_key: str
    sha256: str
    size_bytes: int | None = None


def compute_root_hash(entries: Sequence[ManifestEntry]) -> str:
    """Deterministic SHA-256 over the evidence checksums.

    Entries are sorted by ``object_key`` then ``sha256`` so the root hash is
    reproducible regardless of DB row / insert order (R-5.6.2: "Сортировка
    обязана быть детерминированной — иначе корневой хэш не воспроизводится").
    """
    lines = sorted(f"{e.object_key}:{e.sha256}" for e in entries)
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IntegrityDiscrepancy:
    object_key: str
    reason: str  # "missing" | "checksum_mismatch" | "no_checksum" | "root_hash_mismatch"
    expected: str | None = None
    actual: str | None = None


@dataclass(frozen=True)
class IntegrityReport:
    scan_id: str
    ok: bool
    checked: int
    discrepancies: tuple[IntegrityDiscrepancy, ...]


def verify_integrity(
    *,
    scan_id: str,
    manifest_root_hash: str,
    entries: Sequence[ManifestEntry],
    download: Callable[[str], bytes | None],
) -> IntegrityReport:
    """Recompute each object's SHA-256 from storage and re-derive the root hash.

    ``download(object_key)`` returns the stored bytes (or ``None`` if missing).
    Discrepancies: a missing object, a stored object whose hash differs from the
    manifest's recorded checksum, an entry with no recorded checksum, or a root
    hash that no longer matches the entry set.
    """
    discrepancies: list[IntegrityDiscrepancy] = []
    checked = 0
    for entry in entries:
        if not entry.sha256:
            discrepancies.append(IntegrityDiscrepancy(entry.object_key, "no_checksum"))
            continue
        data = download(entry.object_key)
        if data is None:
            discrepancies.append(
                IntegrityDiscrepancy(entry.object_key, "missing", entry.sha256, None)
            )
            continue
        actual = hashlib.sha256(data).hexdigest()
        checked += 1
        if actual != entry.sha256:
            discrepancies.append(
                IntegrityDiscrepancy(entry.object_key, "checksum_mismatch", entry.sha256, actual)
            )
    recomputed_root = compute_root_hash(entries)
    if recomputed_root != manifest_root_hash:
        discrepancies.append(
            IntegrityDiscrepancy("<root>", "root_hash_mismatch", manifest_root_hash, recomputed_root)
        )
    return IntegrityReport(
        scan_id=scan_id,
        ok=not discrepancies,
        checked=checked,
        discrepancies=tuple(discrepancies),
    )


def detect_overwrite(*, existing_sha256: str | None, new_sha256: str) -> bool:
    """Programmatic overwrite guard (R-5.6.4 fallback when object-lock is absent).

    Returns ``True`` when an object with the same key already exists but with a
    different hash — i.e. a silent overwrite that the caller must refuse / flag.
    """
    return existing_sha256 is not None and existing_sha256 != new_sha256


async def build_and_persist_manifest(
    session: Any,
    *,
    tenant_id: str,
    scan_id: str,
    audit_logger: Any | None = None,
) -> dict[str, Any]:
    """Build the scan's manifest from its evidence rows, persist it, and audit it.

    Reads every ``evidence`` row for the scan, derives the deterministic root
    hash, writes one ``evidence_manifests`` row, and emits an
    ``EVIDENCE_INTEGRITY_CHECK`` audit event carrying the root-hash prefix so the
    manifest's formation is itself in the tamper-evident chain (R-5.6.2).
    """
    from sqlalchemy import String, cast, select

    from src.db.models import Evidence as EvidenceModel
    from src.db.models import EvidenceManifest

    rows = (
        await session.execute(
            select(
                EvidenceModel.object_key,
                EvidenceModel.checksum_value,
                EvidenceModel.size_bytes,
            ).where(
                cast(EvidenceModel.scan_id, String) == scan_id,
                cast(EvidenceModel.tenant_id, String) == tenant_id,
            )
        )
    ).all()
    entries = [
        ManifestEntry(object_key=str(r.object_key), sha256=str(r.checksum_value or ""), size_bytes=r.size_bytes)
        for r in rows
    ]
    root_hash = compute_root_hash(entries)
    total_size = sum(e.size_bytes or 0 for e in entries) or None

    audit_event_id: str | None = None
    if audit_logger is not None:
        try:
            from uuid import UUID

            from src.policy.audit import AuditEventType

            event = audit_logger.emit(
                event_type=AuditEventType.EVIDENCE_INTEGRITY_CHECK,
                tenant_id=UUID(tenant_id),
                scan_id=UUID(scan_id),
                decision_allowed=True,
                payload={"root_hash_prefix": root_hash[:16], "artifact_count": len(entries)},
            )
            audit_event_id = str(event.event_id)
        except Exception:
            _logger.warning(
                "manifest_audit_emit_failed",
                extra={"event": "argus.evidence.manifest_audit_failed", "scan_id": scan_id},
            )

    manifest_id = str(uuid4())
    session.add(
        EvidenceManifest(
            id=manifest_id,
            tenant_id=tenant_id,
            scan_id=scan_id,
            root_hash=root_hash,
            artifact_count=len(entries),
            total_size_bytes=total_size,
            audit_event_id=audit_event_id,
        )
    )
    return {
        "id": manifest_id,
        "scan_id": scan_id,
        "root_hash": root_hash,
        "artifact_count": len(entries),
        "total_size_bytes": total_size,
        "audit_event_id": audit_event_id,
    }


__all__ = [
    "IntegrityDiscrepancy",
    "IntegrityReport",
    "ManifestEntry",
    "build_and_persist_manifest",
    "compute_root_hash",
    "detect_overwrite",
    "verify_integrity",
]
