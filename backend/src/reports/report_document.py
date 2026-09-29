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

SNAPSHOT_SCHEMA_VERSION: Final[str] = "v2"

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


class ReportPoC(BaseModel):
    """Proof-of-concept for a finding (v2, prompt §6/§15.1).

    Carries both the Part-I evidence fields and the senior discriminator/negative-
    control/canary fields. ``discriminator`` and ``negative_control`` are mandatory
    for a ``confirmed_vulnerability`` claim; without them the status is downgraded to
    ``observed`` (enforced by the class-rule table + release gate).
    """

    model_config = ConfigDict(extra="forbid")

    tool: str | None = None
    payload: str | None = None
    command: str | None = None
    http_request: str | None = None
    http_response: str | None = None
    observation: str | None = None
    oast_callback: str | None = None
    screenshot_ref: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    reproducibility: str | None = None  # confirmed | one-shot | not_reproduced
    # Senior fields (§15.1)
    preconditions: str | None = None
    discriminator: str | None = None
    negative_control: str | None = None
    canary: str | None = None
    timing: str | None = None
    source: str | None = None  # source IP / sandbox
    attempts: int | None = None
    observed_impact: str | None = None
    potential_impact: str | None = None
    blast_radius: str | None = None
    cleanup: str | None = None
    client_repro: str | None = None


class ReportRemediation(BaseModel):
    """Per-finding remediation plan (v2, prompt §7 / E.3)."""

    model_config = ConfigDict(extra="forbid")

    status: str = "not_generated"  # AnalysisStatus value
    established_or_hypothesis: str | None = None
    temporary_containment: str | None = None
    permanent_fix: str | None = None
    preventive_measures: str | None = None
    component: str | None = None
    rollout_order: str | None = None
    rollback_risk: str | None = None
    acceptance_criteria: list[str] = Field(default_factory=list)
    retest_plan: str | None = None


class ReportClosure(BaseModel):
    """Per-finding closure conclusion (v2, prompt §7 / E.3).

    ``permitted_status`` is computed by the application (``compute_permitted_closure_
    status``); the LLM may only downgrade it, never strengthen it.
    """

    model_config = ConfigDict(extra="forbid")

    permitted_status: str | None = None
    what_verified: str | None = None
    what_not_verified: str | None = None
    residual_risk: str | None = None
    next_step: str | None = None


class ReportClaim(BaseModel):
    """A claim projected into the snapshot (v2, prompt §14)."""

    model_config = ConfigDict(extra="forbid")

    claim_id: str
    claim_type: str
    text: str
    subject: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    derived_from: list[str] = Field(default_factory=list)
    limitations: str = ""
    validator: str | None = None
    reviewer: str | None = None


class ReportSurfaceItem(BaseModel):
    """One attack-surface entry: host/port/service/version/technology (v2, prompt §5)."""

    model_config = ConfigDict(extra="forbid")

    host: str
    port: int | None = None
    service: str | None = None
    version: str | None = None
    technology: str | None = None


class ReportTestExecution(BaseModel):
    """An executed check, whether or not it yielded a finding (v2, prompt §15.3)."""

    model_config = ConfigDict(extra="forbid")

    test_id: str
    control: str
    method: str = ""
    executed_at: str | None = None
    result: str = "not_applicable"  # passed|failed|blocked|tool_failed|not_applicable|inconclusive
    evidence_ids: list[str] = Field(default_factory=list)


class ReportAttackStep(BaseModel):
    """One step in the attack narrative (v2, prompt §16)."""

    model_config = ConfigDict(extra="forbid")

    order_index: int = 0
    phase: str = ""  # recon|entry|persistence|privesc|data_access
    description: str = ""
    tactic: str | None = None  # MITRE ATT&CK tactic
    technique_id: str | None = None  # MITRE ATT&CK technique
    claim_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    timestamp: str | None = None


class ReportExploitChain(BaseModel):
    """A proven or hypothetical impact chain (v2, prompt §16, FND-03)."""

    model_config = ConfigDict(extra="forbid")

    chain_id: str
    kind: str = "hypothetical"  # proven | hypothetical
    title: str = ""
    steps: list[ReportAttackStep] = Field(default_factory=list)
    preconditions: str | None = None
    outcome: str | None = None
    breaks_at: str | None = None
    to_verify: list[str] = Field(default_factory=list)


class ReportMethodologyRef(BaseModel):
    """An applied methodology/framework with revision (v2, prompt §22)."""

    model_config = ConfigDict(extra="forbid")

    framework: str
    revision: str | None = None
    applied: bool = True
    notes: str | None = None


class EngagementMetadata(BaseModel):
    """Engagement parameters for log correlation (v2, prompt §17 / Phase L)."""

    model_config = ConfigDict(extra="forbid")

    testing_windows: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    user_agents: list[str] = Field(default_factory=list)
    canaries: list[str] = Field(default_factory=list)
    oast_domains: list[str] = Field(default_factory=list)
    test_accounts: list[str] = Field(default_factory=list)  # aliases + roles, no passwords
    run_profile: str | None = None
    execution_mode: str | None = None
    tool_catalog_version: str | None = None
    roe_restrictions: list[str] = Field(default_factory=list)
    incidents: list[str] = Field(default_factory=list)
    time_source: str | None = None


class ClientImpact(BaseModel):
    """Impact on the client environment + cleanup proof (v2, prompt §20.3 / Phase O)."""

    model_config = ConfigDict(extra="forbid")

    created_artifacts: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    not_removed: list[str] = Field(default_factory=list)
    data_exfiltration: str | None = None
    availability_impact: str | None = None


class ReportConclusions(BaseModel):
    """Report-level LLM conclusions (v2, prompt §7 / E.3)."""

    model_config = ConfigDict(extra="forbid")

    executive_summary: str | None = None
    business_risk: str | None = None
    closure_summary: str | None = None
    priority_plan: list[dict[str, Any]] = Field(default_factory=list)


class ReportFinding(BaseModel):
    """One finding in the snapshot. Provable status requires evidence."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str
    # ``unknown`` is a first-class band (finding whose severity could not be
    # determined) — it is NEVER folded into ``info`` or ``low``. ``info`` is a
    # CVSS "None"/informational observation and is distinct. Additive to the v1
    # schema: no pre-existing snapshot used ``unknown``, so hashes are stable.
    severity: Literal["critical", "high", "medium", "low", "info", "unknown"] = "info"
    category: str | None = None
    cwe: str | None = None
    description: str = ""
    verification_status: VerificationStatus = "not_assessed"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    tool_run_id: str | None = None
    validator_id: str | None = None
    raw_artifact_ref: str | None = None

    # ---- v2 additions (all optional / defaulted → backward-compatible) ----
    owasp_category: str | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    established_or_hypothesis: str | None = None  # established | hypothesis
    confirmation_class: str | None = None  # poc_validation.ConfirmationClass value
    downgrade_reason: str | None = None  # why confirmed→observed (§15.2)
    reviewer: str | None = None
    review_status: str = "not_required"  # not_required|pending|approved|changes_requested
    poc: ReportPoC | None = None
    remediation: ReportRemediation | None = None
    closure: ReportClosure | None = None
    claims: list[ReportClaim] = Field(default_factory=list)
    # ---- Phase U (§30.1): object identity + impact + acceptance/retest/priority ----
    asset: str | None = None
    ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    scheme: str | None = None
    url: str | None = None
    path: str | None = None
    parameter: str | None = None
    component: str | None = None
    observed_version: str | None = None
    wstg_test_ids: list[str] = Field(default_factory=list)
    observed_impact: str | None = None
    potential_impact: str | None = None
    blast_radius: str | None = None
    acceptance_criteria: list[str] = Field(default_factory=list)
    retest_plan: list[str] = Field(default_factory=list)
    priority_rationale: str | None = None


class ReportToolRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_run_id: str
    tool_name: str
    status: str = "unknown"
    parser_status: str | None = None
    raw_artifact_ref: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    # ---- Phase U (§30.1 item 4, R-15): provable execution log ----
    exit_code: int | None = None
    argv: str | None = None  # redacted
    sandbox_id: str | None = None
    source_ip: str | None = None


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
    # ---- Phase U (§30.1 item 5, R-16): integrity + provenance of evidence ----
    sha256: str | None = None
    size: int | None = None
    mime: str | None = None
    collected_at_utc: str | None = None
    collector: str | None = None  # tool + version
    producer_tool_run_id: str | None = None
    redaction_applied: bool | None = None
    chain_hash: str | None = None


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

    # Evidence-based WSTG v4.2 coverage (ARGUS-WSTG-COV-1) — per-test states,
    # applicability decisions, executions, integrity errors, verdict and versions
    # (see docs/wstg-coverage.md, built by src/reports/wstg_report.build_wstg_block).
    # None when the coverage subsystem is disabled.
    wstg: dict[str, Any] | None = None

    # Validation of the evidence gate (populated during build)
    validation_errors: list[ReportValidationError] = Field(default_factory=list)

    # Versions
    prompt_model_versions: dict[str, Any] = Field(default_factory=dict)
    registry_versions: dict[str, Any] = Field(default_factory=dict)

    # ---- v2 additions (all optional / defaulted → backward-compatible) ----
    #: Attack-surface inventory (hosts/ports/services/versions/technologies).
    surface_inventory: list[ReportSurfaceItem] = Field(default_factory=list)
    #: Observations that did not meet their class confirmation bar (kept out of the
    #: findings registry; printed separately, prompt §6.D.1 / §15.2).
    unconfirmed_observations: list[ReportFinding] = Field(default_factory=list)
    #: Executed checks that produced no finding (prompt §15.3 — proves coverage).
    test_executions: list[ReportTestExecution] = Field(default_factory=list)
    #: Attack narrative (chronological, prompt §16 / Phase K).
    attack_narrative: list[ReportAttackStep] = Field(default_factory=list)
    #: Proven + hypothetical impact chains, kept separate (FND-03).
    exploit_chains: list[ReportExploitChain] = Field(default_factory=list)
    #: Applied methodologies with revisions (prompt §22).
    methodology: list[ReportMethodologyRef] = Field(default_factory=list)
    #: Engagement parameters for client log correlation (prompt §17 / Phase L).
    engagement: EngagementMetadata | None = None
    #: Impact on the client environment + cleanup proof (prompt §20.3 / Phase O).
    client_impact: ClientImpact | None = None
    #: Report-level LLM conclusions (executive/business-risk/closure/priority-plan).
    conclusions: ReportConclusions | None = None
    #: Doc-level claims (the narrative substrate, prompt §14).
    claims: list[ReportClaim] = Field(default_factory=list)

    # Release status model (prompt E.2 — independent fields, never conflated).
    generation_status: str = "unknown"  # unknown|ready|partial|failed
    llm_analysis_status: str = "not_run"  # not_run|completed|partial|failed
    assessment_completeness: str = "unknown"  # complete|partial|incomplete|unknown
    evidence_integrity: str = "unknown"  # verified|unverified|failed|unknown
    review_status: str = "not_required"  # not_required|pending|approved|changes_requested
    #: Reference (object key / path) to the independent verification kit (Phase M).
    verification_kit_ref: str | None = None

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


def apply_evidence_gate(
    findings: list[ReportFinding],
    *,
    known_evidence_ids: set[str] | None = None,
    known_tool_run_ids: set[str] | None = None,
) -> tuple[list[ReportFinding], list[ReportValidationError]]:
    """Downgrade provable findings that lack a *verifiable* evidence chain.

    A finding may keep ``confirmed``/``exploitable`` only if:

    * it references verifiable evidence — an ``evidence_id`` that resolves to a
      real ``evidence_reference`` (or object key) in the snapshot, OR a concrete
      ``raw_artifact_ref``; AND
    * it names a producer — a ``tool_run_id`` that resolves to a real tool run,
      OR a ``validator_id``.

    When ``known_evidence_ids`` / ``known_tool_run_ids`` are provided the check
    is *referential* (Requirements §5: "finding → evidence → run/session;
    confirmed запрещён при непроверяемых связях") — opaque, unresolvable refs
    such as ``finding-3`` no longer satisfy the gate. When they are omitted the
    check falls back to the historical non-empty test (backward compatible).

    Otherwise the status is downgraded to ``insufficient_evidence`` and a
    validation error is recorded.
    """
    enforce_refs = known_evidence_ids is not None or known_tool_run_ids is not None
    ev_set = known_evidence_ids or set()
    run_set = known_tool_run_ids or set()

    gated: list[ReportFinding] = []
    errors: list[ReportValidationError] = []
    for finding in findings:
        if finding.verification_status in _PROVABLE_STATUSES:
            if enforce_refs:
                has_evidence = any(e in ev_set for e in finding.evidence_ids) or bool(
                    finding.raw_artifact_ref
                )
                has_source = (
                    finding.tool_run_id in run_set if finding.tool_run_id else False
                ) or bool(finding.validator_id)
            else:
                has_evidence = bool(finding.evidence_ids)
                has_source = bool(finding.tool_run_id or finding.validator_id)
            if not (has_evidence and has_source):
                errors.append(
                    ReportValidationError(
                        finding_id=finding.finding_id,
                        code="insufficient_evidence",
                        message=(
                            f"Finding {finding.finding_id!r} claimed "
                            f"{finding.verification_status!r} without a verifiable "
                            "evidence chain (evidence→run/session); downgraded."
                        ),
                    )
                )
                gated.append(
                    finding.model_copy(update={"verification_status": "insufficient_evidence"})
                )
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
    wstg: dict[str, Any] | None = None,
    # ---- v2 pass-through (optional) ----
    surface_inventory: list[ReportSurfaceItem] | None = None,
    unconfirmed_observations: list[ReportFinding] | None = None,
    test_executions: list[ReportTestExecution] | None = None,
    attack_narrative: list[ReportAttackStep] | None = None,
    exploit_chains: list[ReportExploitChain] | None = None,
    methodology: list[ReportMethodologyRef] | None = None,
    engagement: EngagementMetadata | None = None,
    client_impact: ClientImpact | None = None,
    conclusions: ReportConclusions | None = None,
    claims: list[ReportClaim] | None = None,
    generation_status: str = "unknown",
    llm_analysis_status: str = "not_run",
    assessment_completeness: str = "unknown",
    evidence_integrity: str = "unknown",
    review_status: str = "not_required",
    verification_kit_ref: str | None = None,
    generated_at: datetime | None = None,
) -> ReportDocumentV1:
    """Assemble + finalize a canonical snapshot with the evidence gate applied."""
    _evidence_refs = list(evidence_references or [])
    _tool_runs = list(tool_runs or [])
    # Referential-integrity sets: an evidence id / tool_run id is "verifiable"
    # only if it resolves to a real reference/run in this snapshot.
    known_evidence_ids: set[str] = set()
    for _ref in _evidence_refs:
        known_evidence_ids.add(_ref.evidence_id)
        if _ref.object_key:
            known_evidence_ids.add(_ref.object_key)
    known_tool_run_ids: set[str] = {t.tool_run_id for t in _tool_runs}
    gated_findings, gate_errors = apply_evidence_gate(
        list(findings or []),
        known_evidence_ids=known_evidence_ids,
        known_tool_run_ids=known_tool_run_ids,
    )
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
        wstg=wstg,
        surface_inventory=list(surface_inventory or []),
        unconfirmed_observations=list(unconfirmed_observations or []),
        test_executions=list(test_executions or []),
        attack_narrative=list(attack_narrative or []),
        exploit_chains=list(exploit_chains or []),
        methodology=list(methodology or []),
        engagement=engagement,
        client_impact=client_impact,
        conclusions=conclusions,
        claims=list(claims or []),
        generation_status=generation_status,
        llm_analysis_status=llm_analysis_status,
        assessment_completeness=assessment_completeness,
        evidence_integrity=evidence_integrity,
        review_status=review_status,
        verification_kit_ref=verification_kit_ref,
    )
    return doc.finalized(generated_at=generated_at)


__all__ = [
    "NO_DATA_STATUSES",
    "SNAPSHOT_SCHEMA_VERSION",
    "ClientImpact",
    "EngagementMetadata",
    "ReportAttackStep",
    "ReportClaim",
    "ReportClosure",
    "ReportConclusions",
    "ReportCoverageItem",
    "ReportDocumentV1",
    "ReportEvidenceRef",
    "ReportExploitChain",
    "ReportFailure",
    "ReportFinding",
    "ReportMethodologyRef",
    "ReportPoC",
    "ReportRemediation",
    "ReportSurfaceItem",
    "ReportTestExecution",
    "ReportToolRun",
    "ReportValidationError",
    "VerificationStatus",
    "apply_evidence_gate",
    "build_report_document",
]
