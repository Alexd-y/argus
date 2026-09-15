"""Valhalla LLM document tree (VH-LLM-07).

The accepted per-finding remediation/closure analyses are frozen into a single
ordered, versioned document. Every output format (MD/XML/HTML/PDF/JSON) is a
pure projection of this one tree — renderers never call the LLM, fetch new
facts or change conclusions (prompt §5, §11). Re-rendering is therefore not
re-analysis; a change of facts/conclusions must produce a new version.

``content_hash`` is deterministic over the accepted narrative + facts and
*excludes* volatile provenance fields (analysis_id, generated_at, token/cost)
so the same validated inputs yield the same content hash (idempotency, L23).
Post-render artifact hashes live in the release manifest, not here, to avoid a
hashing cycle (prompt §11).
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.reports.llm_remediation.schemas import (
    FindingClosureConclusion,
    FindingRemediationAnalysis,
    ReportClosureSummary,
)

VALHALLA_LLM_DOC_VERSION = "valhalla-llm-doc-v1"


class AssessmentCompleteness(StrEnum):
    """Report-level LLM assessment completeness (prompt §12 status separation)."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


class ValhallaFindingNode(BaseModel):
    """One finding with its two mandatory LLM blocks (prompt §10)."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, max_length=128)
    title: str = Field(default="", max_length=1000)
    severity: str = Field(default="unknown", max_length=32)
    verification_status: str = Field(default="not_assessed", max_length=64)
    llm_analysis_status: str = Field(default="failed", max_length=64)
    remediation: FindingRemediationAnalysis | None = None
    closure: FindingClosureConclusion | None = None


class ValhallaLlmDocument(BaseModel):
    """Immutable, versioned tree of accepted Valhalla LLM analyses."""

    model_config = ConfigDict(extra="forbid")

    doc_version: str = VALHALLA_LLM_DOC_VERSION
    report_id: str = Field(default="", max_length=128)
    report_version: str = Field(default="unknown", max_length=128)
    tenant_id: str = Field(default="", max_length=128)
    scan_id: str = Field(default="", max_length=128)
    target: str = Field(default="", max_length=2000)
    locale: str = Field(default="ru", max_length=16)
    canonical_snapshot_hash: str = Field(default="", max_length=128)
    findings: list[ValhallaFindingNode] = Field(default_factory=list)
    summary: ReportClosureSummary | None = None
    assessment_completeness: AssessmentCompleteness = AssessmentCompleteness.INCOMPLETE
    generated_at: str = ""
    content_hash: str = ""

    # ------------------------------------------------------------------ hash

    def _canonical_content(self) -> dict[str, Any]:
        """Deterministic projection excluding volatile provenance/timestamps."""

        def _strip_provenance(payload: dict[str, Any] | None) -> dict[str, Any] | None:
            if payload is None:
                return None
            clone = json.loads(json.dumps(payload))
            prov = clone.get("llm_provenance")
            if isinstance(prov, dict):
                for volatile in ("analysis_id", "generated_at", "token_usage", "cost_usd"):
                    prov.pop(volatile, None)
            return clone

        def _strip_summary(payload: dict[str, Any] | None) -> dict[str, Any] | None:
            clone = _strip_provenance(payload)
            if clone is not None:
                # source_analysis_ids reference volatile per-finding analysis ids.
                clone.pop("source_analysis_ids", None)
            return clone

        return {
            "doc_version": self.doc_version,
            "report_version": self.report_version,
            "canonical_snapshot_hash": self.canonical_snapshot_hash,
            "findings": [
                {
                    "finding_id": n.finding_id,
                    "llm_analysis_status": n.llm_analysis_status,
                    "remediation": _strip_provenance(
                        n.remediation.model_dump(mode="json") if n.remediation else None
                    ),
                    "closure": _strip_provenance(
                        n.closure.model_dump(mode="json") if n.closure else None
                    ),
                }
                for n in self.findings
            ],
            "summary": _strip_summary(
                self.summary.model_dump(mode="json") if self.summary else None
            ),
            "assessment_completeness": self.assessment_completeness.value,
        }

    def compute_content_hash(self) -> str:
        blob = json.dumps(self._canonical_content(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def finalized(self, *, generated_at: str = "") -> ValhallaLlmDocument:
        return self.model_copy(
            update={"content_hash": self.compute_content_hash(), "generated_at": generated_at}
        )


__all__ = [
    "VALHALLA_LLM_DOC_VERSION",
    "AssessmentCompleteness",
    "ValhallaFindingNode",
    "ValhallaLlmDocument",
]
