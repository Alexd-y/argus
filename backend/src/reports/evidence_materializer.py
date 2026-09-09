"""Materialise persisted Evidence rows from a finding's uploaded PoC artifacts.

Pure row-builder (no IO): given a finding's MinIO object keys (PoC JSON and/or
screenshot PNG already uploaded by the scan pipeline), produce deterministic,
idempotent :class:`EvidenceRow` descriptors. The caller (state machine) turns
these into ``models.Evidence`` ORM rows via ``session.merge`` so that a phase
retry / resume never duplicates them (upsert by primary key).

This is the *producer* half of store-backed WSTG evidence validation
(ARGUS-WSTG-COV-1 §Evidence): without a real ``Evidence`` row (``finding_id`` +
``object_key``) a finding's control-failure is never counted toward coverage —
a bare ``evidence_refs`` list of ids/hashes is not sufficient.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

# Stable namespace for deterministic Evidence ids. A fixed namespace makes
# ``build_evidence_id`` a pure function of (scan_id, finding_id, object_key), so
# re-running finding persistence upserts the same row instead of inserting a
# duplicate.
_EVIDENCE_NAMESPACE = uuid.UUID("b7d2f0c4-6a1e-5f83-9c2a-2f1e6d4c8a90")

POC_CONTENT_TYPE = "application/json"
SCREENSHOT_CONTENT_TYPE = "image/png"

_POC_DESCRIPTION = "Finding PoC JSON"
_SCREENSHOT_DESCRIPTION = "Finding PoC screenshot"


@dataclass(frozen=True)
class EvidenceRow:
    """Descriptor for one persisted Evidence row (maps 1:1 to ``models.Evidence``)."""

    id: str
    tenant_id: str
    scan_id: str
    finding_id: str
    object_key: str
    content_type: str
    description: str


def build_evidence_id(scan_id: str, finding_id: str, object_key: str) -> str:
    """Deterministic UUID5 id for an evidence artifact (idempotent upsert key)."""
    return str(uuid.uuid5(_EVIDENCE_NAMESPACE, f"{scan_id}:{finding_id}:{object_key}"))


def build_finding_evidence_rows(
    *,
    tenant_id: str,
    scan_id: str,
    finding_id: str,
    poc_object_key: str | None = None,
    screenshot_object_key: str | None = None,
) -> list[EvidenceRow]:
    """Build deterministic Evidence rows for a finding's uploaded artifacts.

    Only non-empty, unique object keys yield rows. Returns an empty list when no
    artifact was persisted (e.g. object store unavailable) — honest: no artifact,
    no evidence, no coverage credit.
    """
    rows: list[EvidenceRow] = []
    seen: set[str] = set()
    for object_key, content_type, description in (
        (poc_object_key, POC_CONTENT_TYPE, _POC_DESCRIPTION),
        (screenshot_object_key, SCREENSHOT_CONTENT_TYPE, _SCREENSHOT_DESCRIPTION),
    ):
        key = (object_key or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        rows.append(
            EvidenceRow(
                id=build_evidence_id(scan_id, finding_id, key),
                tenant_id=tenant_id,
                scan_id=scan_id,
                finding_id=finding_id,
                object_key=key,
                content_type=content_type,
                description=description,
            )
        )
    return rows


__all__ = [
    "POC_CONTENT_TYPE",
    "SCREENSHOT_CONTENT_TYPE",
    "EvidenceRow",
    "build_evidence_id",
    "build_finding_evidence_rows",
]
