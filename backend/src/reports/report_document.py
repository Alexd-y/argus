"""ReportDocumentV1 — the canonical, immutable report snapshot.

All report formats (JSON / Markdown / XML / PDF) are rendered from a single
instance of :class:`ReportDocumentV1`. This guarantees semantic parity across
formats (Requirements R7, P4) and is the enforcement point for the
"AI must not fabricate data" rule (Requirements R6, P5):

* A finding may only carry a ``confirmed`` / ``exploitable`` verification
  status if it references at least one evidence id AND a tool_run/validator id.
  Otherwise the status is downgraded to ``insufficient_evidence`` and a
  validation error is recorded.
* When data is missing, the snapshot uses one of the canonical "no-data"
  statuses instead of inventing content.

The snapshot is content-addressed via :attr:`snapshot_hash` (SHA-256 of the
canonical JSON, excluding the hash itself and the non-deterministic
``generated_at`` timestamp), so re-generation with an unchanged snapshot never
changes meaning (Requirements P7).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

SNAPSHOT_SCHEMA_VERSION: Final[str] = "v1"

#: Canonical statuses used when data is missing — never invent content.
NO_DATA_STATUSES: Final[frozenset[str]] = frozenset(
    {
        "not_assessed",
        "not_tested",
        "insufficient_evidence",
        "tool_failed",
        "parser_unavailable",
        "out_of_scope",
        "budget_exhausted",
    }
)

#: Verification statuses that assert a real, provable finding.
_PROVABLE_STATUSES: Final[frozenset[str]] = frozenset({"confirmed", "exploitable"})

VerificationStatus = Literal[
    "confirmed",
    "exploitable",
    "suspected",
    "not_tested",
    "not_assessed",
    "insufficient_evidence",
    "out_of_scope",
    "false_positive",
]


class ReportFinding(BaseModel):
    """One finding in the snapshot. Provable status requires evidence."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    category: str | None = None
    cwe: str | None = None
    description: str = ""
    verification_status: VerificationStatus = "not_assessed"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    tool_run_id: str | None = None
    validator_id: str | None = None
    raw_artifact_ref: str | None = None


class ReportToolRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_run_id: str
    tool_name: str
    status: str = "unknown"
    parser_status: str | None = None
    raw_artifact_ref: str | None = None
    started_at: str | None = None
    finished_at: str | None = None


class ReportCoverageItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability_id: str
    status: str
    reason_code: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class ReportEvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    kind: str = "artifact"
    object_key: str | None = None
    description: str | None = None


class ReportFailure(BaseModel):
    model_config = ConfigDict(extra="forbid")

    where: str
    reason_code: str
    message: str = ""


class ReportValidationError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str | None = None
    code: str
    message: str


class ReportDocumentV1(BaseModel):
    """Canonical immutable report snapshot. All renderers read only this."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SNAPSHOT_SCHEMA_VERSION

    # Identity / profile provenance
    scan_id: str
    tenant_id: str
    target: str
    scan_profile: str | None = None
    resolved_scan_mode: str | None = None
    execution_mode: str | None = None
    quick_profile: str | None = None
    nuclei_profile: str | None = None

    started_at: str | None = None
    completed_at: str | None = None

    # Scope / limits
    scope_summary: dict[str, Any] = Field(default_factory=dict)
    profile_limits: dict[str, Any] = Field(default_factory=dict)

    # Execution facts
    tool_runs: list[ReportToolRun] = Field(default_factory=list)
    tested_capabilities: list[str] = Field(default_factory=list)
    not_assessed_capabilities: list[str] = Field(default_factory=list)
    coverage: list[ReportCoverageItem] = Field(default_factory=list)

    # Results
    findings: list[ReportFinding] = Field(default_factory=list)
    evidence_references: list[ReportEvidenceRef] = Field(default_factory=list)
    oast_references: list[dict[str, Any]] = Field(default_factory=list)

    # Failures / limits
    failures: list[ReportFailure] = Field(default_factory=list)
    skipped_reasons: list[dict[str, Any]] = Field(default_factory=list)
    budget_usage: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)

    # Validation of the evidence gate (populated during build)
    validation_errors: list[ReportValidationError] = Field(default_factory=list)

    # Versions
    prompt_model_versions: dict[str, Any] = Field(default_factory=dict)
    registry_versions: dict[str, Any] = Field(default_factory=dict)

    generated_at: str = ""
    snapshot_hash: str = ""

    # ------------------------------------------------------------------ hash

    def canonical_payload(self) -> dict[str, Any]:
        """Deterministic payload for hashing (excludes hash + generated_at)."""
        data = self.model_dump(mode="json", exclude={"snapshot_hash", "generated_at"})
        return data

    def compute_hash(self) -> str:
        blob = json.dumps(self.canonical_payload(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def finalized(self, *, generated_at: datetime | None = None) -> ReportDocumentV1:
        """Return a copy with snapshot_hash + generated_at populated."""
        ts = (generated_at or datetime.now(UTC)).isoformat()
        digest = self.compute_hash()
        return self.model_copy(update={"snapshot_hash": digest, "generated_at": ts})


def apply_evidence_gate(findings: list[ReportFinding]) -> tuple[list[ReportFinding], list[ReportValidationError]]:
    """Downgrade provable findings that lack evidence (Requirements R7.4/P5).

    A finding may keep ``confirmed``/``exploitable`` only if it has at least one
    evidence id AND a tool_run_id or validator_id. Otherwise it is downgraded to
    ``insufficient_evidence`` and a validation error is recorded.
    """
    gated: list[ReportFinding] = []
    errors: list[ReportValidationError] = []
    for finding in findings:
        if finding.verification_status in _PROVABLE_STATUSES:
            has_evidence = bool(finding.evidence_ids)
            has_source = bool(finding.tool_run_id or finding.validator_id)
            if not (has_evidence and has_source):
                errors.append(
                    ReportValidationError(
                        finding_id=finding.finding_id,
                        code="insufficient_evidence",
                        message=(
                            f"Finding {finding.finding_id!r} claimed "
                            f"{finding.verification_status!r} without evidence refs; downgraded."
                        ),
                    )
                )
                gated.append(finding.model_copy(update={"verification_status": "insufficient_evidence"}))
                continue
        gated.append(finding)
    return gated, errors


def build_report_document(
    *,
    scan_id: str,
    tenant_id: str,
    target: str,
    scan_profile: str | None = None,
    resolved_scan_mode: str | None = None,
    execution_mode: str | None = None,
    quick_profile: str | None = None,
    nuclei_profile: str | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    scope_summary: dict[str, Any] | None = None,
    profile_limits: dict[str, Any] | None = None,
    tool_runs: list[ReportToolRun] | None = None,
    tested_capabilities: list[str] | None = None,
    not_assessed_capabilities: list[str] | None = None,
    coverage: list[ReportCoverageItem] | None = None,
    findings: list[ReportFinding] | None = None,
    evidence_references: list[ReportEvidenceRef] | None = None,
    oast_references: list[dict[str, Any]] | None = None,
    failures: list[ReportFailure] | None = None,
    skipped_reasons: list[dict[str, Any]] | None = None,
    budget_usage: dict[str, Any] | None = None,
    limitations: list[str] | None = None,
    prompt_model_versions: dict[str, Any] | None = None,
    registry_versions: dict[str, Any] | None = None,
    generated_at: datetime | None = None,
) -> ReportDocumentV1:
    """Assemble + finalize a canonical snapshot with the evidence gate applied."""
    gated_findings, gate_errors = apply_evidence_gate(list(findings or []))
    doc = ReportDocumentV1(
        scan_id=scan_id,
        tenant_id=tenant_id,
        target=target,
        scan_profile=scan_profile,
        resolved_scan_mode=resolved_scan_mode,
        execution_mode=execution_mode,
        quick_profile=quick_profile,
        nuclei_profile=nuclei_profile,
        started_at=started_at,
        completed_at=completed_at,
        scope_summary=scope_summary or {},
        profile_limits=profile_limits or {},
        tool_runs=list(tool_runs or []),
        tested_capabilities=list(tested_capabilities or []),
        not_assessed_capabilities=list(not_assessed_capabilities or []),
        coverage=list(coverage or []),
        findings=gated_findings,
        evidence_references=list(evidence_references or []),
        oast_references=list(oast_references or []),
        failures=list(failures or []),
        skipped_reasons=list(skipped_reasons or []),
        budget_usage=budget_usage or {},
        limitations=list(limitations or []),
        validation_errors=gate_errors,
        prompt_model_versions=prompt_model_versions or {},
        registry_versions=registry_versions or {},
    )
    return doc.finalized(generated_at=generated_at)


__all__ = [
    "NO_DATA_STATUSES",
    "SNAPSHOT_SCHEMA_VERSION",
    "ReportCoverageItem",
    "ReportDocumentV1",
    "ReportEvidenceRef",
    "ReportFailure",
    "ReportFinding",
    "ReportToolRun",
    "ReportValidationError",
    "VerificationStatus",
    "apply_evidence_gate",
    "build_report_document",
]
