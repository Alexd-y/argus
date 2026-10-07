"""Evidence / claim reference index for report prose traceability (Phase 14.3).

``prose_gate`` already *enforces* that factual paragraphs carry a ``[CL-…]`` /
``[E-…]`` reference (see :func:`src.reports.prose_gate.has_reference`); what was
missing is a deterministic way to *mint* those references from a report's findings
so claims can be traced to the evidence backing them.

This module is pure and deterministic: the same findings always produce the same
labels (``CL-0001``, ``E-0001`` …), in first-seen order, so references are stable
across renders (report bundles are hashed and snapshot-tested).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Cap on evidence ids rendered inside a single reference marker (keeps prose terse).
_MAX_EVIDENCE_PER_REF = 3


def _finding_id(finding: Any) -> str:
    if isinstance(finding, dict):
        return str(finding.get("finding_id") or finding.get("id") or "")
    return str(getattr(finding, "finding_id", None) or getattr(finding, "id", None) or "")


def _evidence_ids(finding: Any) -> list[str]:
    if isinstance(finding, dict):
        raw = finding.get("evidence_ids") or finding.get("evidence_refs")
    else:
        raw = getattr(finding, "evidence_ids", None) or getattr(finding, "evidence_refs", None)
    return [str(x) for x in (raw or []) if str(x).strip()]


@dataclass(frozen=True)
class EvidenceReferenceIndex:
    """Stable ``finding_id → CL-id`` and ``evidence_id → E-id`` maps."""

    claim_ref: dict[str, str]
    evidence_ref: dict[str, str]

    def reference_for(self, finding: Any) -> str:
        """Return the ``[CL-… / E-…]`` marker for ``finding`` (matches prose_gate).

        Empty string when the finding has neither a known claim nor evidence id, so
        callers can decide whether a paragraph is referenceable.
        """
        fid = _finding_id(finding)
        parts: list[str] = []
        cl = self.claim_ref.get(fid)
        if cl:
            parts.append(cl)
        for e in _evidence_ids(finding):
            label = self.evidence_ref.get(e)
            if label and label not in parts:
                parts.append(label)
                if len(parts) >= _MAX_EVIDENCE_PER_REF + 1:
                    break
        if not parts:
            return ""
        return "[" + " / ".join(parts) + "]"


def build_evidence_reference_index(findings: Any) -> EvidenceReferenceIndex:
    """Assign stable ``CL-``/``E-`` labels over ``findings`` in first-seen order."""
    claim: dict[str, str] = {}
    evidence: dict[str, str] = {}
    for finding in findings or []:
        fid = _finding_id(finding)
        if fid and fid not in claim:
            claim[fid] = f"CL-{len(claim) + 1:04d}"
        for e in _evidence_ids(finding):
            if e not in evidence:
                evidence[e] = f"E-{len(evidence) + 1:04d}"
    return EvidenceReferenceIndex(claim_ref=claim, evidence_ref=evidence)


__all__ = [
    "EvidenceReferenceIndex",
    "build_evidence_reference_index",
]
