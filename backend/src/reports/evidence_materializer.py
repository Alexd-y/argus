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
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

# Stable namespace for deterministic Evidence ids. A fixed namespace makes
# ``build_evidence_id`` a pure function of (scan_id, finding_id, object_key), so
# re-running finding persistence upserts the same row instead of inserting a
# duplicate.
_EVIDENCE_NAMESPACE = uuid.UUID("b7d2f0c4-6a1e-5f83-9c2a-2f1e6d4c8a90")

POC_CONTENT_TYPE = "application/json"
SCREENSHOT_CONTENT_TYPE = "image/png"

_POC_DESCRIPTION = "Finding PoC JSON"
_SCREENSHOT_DESCRIPTION = "Finding PoC screenshot"

# Cap for serialised observation text so a stored evidence artifact stays small.
_MAX_OBSERVATION_LEN = 4000
_MAX_OBSERVATION_REFS = 64


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


def build_observation_poc(
    *,
    description: str | None,
    evidence_refs: Sequence[str] | None,
    reproducible_steps: str | None = None,
) -> dict[str, Any] | None:
    """Build a minimal, honest evidence artifact from a finding's *captured*
    observation (ARGUS-WSTG-COV-1 §Evidence).

    Intended for passive checks (TLS/headers/DNS) whose result is a stored
    observation rather than an interactive PoC. It NEVER fabricates from a bare
    finding: it returns ``None`` unless the finding carries at least one real
    captured evidence reference *and* an observed fact (a description or a
    reproduction). The returned dict is uploaded as the finding's evidence
    artifact and linked via :func:`build_finding_evidence_rows`.
    """
    refs = [str(r).strip() for r in (evidence_refs or []) if str(r or "").strip()]
    observation = (description or "").strip()
    steps = (reproducible_steps or "").strip()
    if not refs or (not observation and not steps):
        return None
    poc: dict[str, Any] = {"kind": "observation", "evidence_refs": refs[:_MAX_OBSERVATION_REFS]}
    if observation:
        poc["observation"] = observation[:_MAX_OBSERVATION_LEN]
    if steps:
        poc["reproducible_steps"] = steps[:_MAX_OBSERVATION_LEN]
    return poc


__all__ = [
    "POC_CONTENT_TYPE",
    "SCREENSHOT_CONTENT_TYPE",
    "EvidenceRow",
    "build_evidence_id",
    "build_finding_evidence_rows",
    "build_observation_poc",
]
