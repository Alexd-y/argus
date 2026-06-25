"""Shared Pydantic v2 primitives for recon AI task schemas."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictStr,
    StringConstraints,
    model_validator,
)


class ReconAiTask(StrEnum):
    JS_FINDINGS_ANALYSIS = "js_findings_analysis"
    PARAMETER_INPUT_ANALYSIS = "parameter_input_analysis"
    API_SURFACE_INFERENCE = "api_surface_inference"
    HEADERS_TLS_SUMMARY = "headers_tls_summary"
    CONTENT_SIMILARITY_INTERPRETATION = "content_similarity_interpretation"
    ANOMALY_INTERPRETATION = "anomaly_interpretation"
    STAGE2_PREPARATION_SUMMARY = "stage2_preparation_summary"
    STAGE3_PREPARATION_SUMMARY = "stage3_preparation_summary"


class ReportSectionId(StrEnum):
    JS_FRONTEND_ANALYSIS = "section-08-javascript-frontend-analysis"
    PARAMS_INPUT_SURFACES = "section-09-parameters-input-surfaces"
    API_SURFACE_MAPPING = "section-10-api-surface-mapping"
    HEADERS_TLS = "section-11-headers-cookies-tls-analysis"
    CONTENT_ROUTING = "section-12-content-similarity-and-routing-behavior"
    ANOMALY_VALIDATION = "section-13-anomaly-validation"
    STAGE2_PREP = "section-14-stage-2-preparation"
    STAGE3_READINESS = "section-17-stage-3-readiness"


class StatementType(StrEnum):
    EVIDENCE = "evidence"
    OBSERVATION = "observation"
    INFERENCE = "inference"
    HYPOTHESIS = "hypothesis"


class VulnerabilityAnalysisAiTask(StrEnum):
    VALIDATION_TARGET_PLANNING = "validation_target_planning"
    AUTH_SURFACE_ANALYSIS = "auth_surface_analysis"
    AUTHORIZATION_ANALYSIS = "authorization_analysis"
    INPUT_SURFACE_ANALYSIS = "input_surface_analysis"
    ROUTE_AND_WORKFLOW_ANALYSIS = "route_and_workflow_analysis"
    API_SURFACE_ANALYSIS = "api_surface_analysis"
    RESOURCE_ACCESS_ANALYSIS = "resource_access_analysis"
    FRONTEND_LOGIC_ANALYSIS = "frontend_logic_analysis"
    SECURITY_CONTROLS_ANALYSIS = "security_controls_analysis"
    ANOMALOUS_HOST_ANALYSIS = "anomalous_host_analysis"
    TRUST_BOUNDARY_VALIDATION_ANALYSIS = "trust_boundary_validation_analysis"
    BUSINESS_LOGIC_ANALYSIS = "business_logic_analysis"
    # VA3UP-008: Stage 3 confirmation pipeline (replaces finding_correlation, remediation_note_generation, stage3_report_summary)
    EVIDENCE_BUNDLE_ASSEMBLY = "evidence_bundle_assembly"
    FINDING_CONFIRMATION_ASSESSMENT = "finding_confirmation_assessment"
    CONTRADICTION_ANALYSIS = "contradiction_analysis"
    DUPLICATE_FINDING_CORRELATION = "duplicate_finding_correlation"
    FINDING_TO_SCENARIO_MAPPING = "finding_to_scenario_mapping"
    REMEDIATION_GENERATION = "remediation_generation"
    STAGE3_CONFIRMATION_SUMMARY = "stage3_confirmation_summary"
    EXPLOITATION_CANDIDATE_GENERATION = "exploitation_candidate_generation"
    # OWASP-006: post active-scan tool interpretation (enum values appended for backward compatibility)
    ACTIVE_SCAN_PLANNING = "active_scan_planning"
    XSS_ANALYSIS = "xss_analysis"
    SQLI_ANALYSIS = "sqli_analysis"
    # OWASP2-006: Nuclei JSONL summaries — triage false positives, enrich descriptions
    NUCLEI_ANALYSIS = "nuclei_analysis"
    # WEB-003: web-specific active scan interpretation
    WEB_SCAN_PLANNING = "web_scan_planning"
    GENERIC_WEB_FINDING = "generic_web_finding"


class ThreatModelingAiTask(StrEnum):
    CRITICAL_ASSETS = "critical_assets"
    TRUST_BOUNDARIES = "trust_boundaries"
    ATTACKER_PROFILES = "attacker_profiles"
    ENTRY_POINTS = "entry_points"
    APPLICATION_FLOWS = "application_flows"
    THREAT_SCENARIOS = "threat_scenarios"
    SCENARIO_SCORING = "scenario_scoring"
    TESTING_ROADMAP = "testing_roadmap"
    REPORT_SUMMARY = "report_summary"


class ThreatModelRunMetadata(BaseModel):
    """Run/job linkage metadata for threat modeling AI task payloads."""

    model_config = ConfigDict(extra="forbid")

    task: ThreatModelingAiTask
    run_id: StrictStr = Field(min_length=1, max_length=200)
    job_id: StrictStr = Field(min_length=1, max_length=200)
    trace_id: StrictStr = Field(min_length=1, max_length=300)


class PriorityLevel(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


EVIDENCE_REF_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/?#\-\[\]@%+=~]{0,1999}$"
EvidenceRef = Annotated[
    str,
    StringConstraints(
        strict=True,
        strip_whitespace=True,
        min_length=1,
        max_length=2000,
        pattern=EVIDENCE_REF_PATTERN,
    ),
]


class TaskRunMetadata(BaseModel):
    """Run/job linkage metadata for AI task payloads."""

    model_config = ConfigDict(extra="forbid")

    task: ReconAiTask
    run_id: StrictStr = Field(min_length=1, max_length=200)
    job_id: StrictStr = Field(min_length=1, max_length=200)
    run_link: StrictStr = Field(min_length=1, max_length=300)
    job_link: StrictStr = Field(min_length=1, max_length=300)
    trace_id: StrictStr = Field(min_length=1, max_length=300)

    @model_validator(mode="after")
    def _validate_linkage(self) -> TaskRunMetadata:
        expected_run_link = f"recon://runs/{self.run_id}"
        expected_job_link = f"recon://jobs/{self.job_id}"
        if self.run_link != expected_run_link:
            raise ValueError(f"run_link must equal {expected_run_link}")
        if self.job_link != expected_job_link:
            raise ValueError(f"job_link must equal {expected_job_link}")
        return self


class EvidenceBacked(BaseModel):
    """Mixin for evidence-constrained statements."""

    model_config = ConfigDict(extra="forbid")

    statement_type: StatementType
    confidence: StrictFloat = Field(ge=0.0, le=1.0)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_evidence_requirements(self) -> EvidenceBacked:
        if (
            self.statement_type != StatementType.HYPOTHESIS
            and not self.evidence_refs
        ):
            raise ValueError(
                "evidence_refs are required for non-hypothesis statements",
            )
        return self


def validate_with_model(model_cls: type[BaseModel], payload: dict[str, Any]) -> list[str]:
    """Validate payload and return human-readable errors."""
    try:
        model_cls.model_validate(payload)
        return []
    except Exception as exc:  # noqa: BLE001 - convert model errors to compact list
        if hasattr(exc, "errors"):
            return [str(item) for item in exc.errors()]  # type: ignore[no-any-return]
        return [str(exc)]


def build_task_metadata(
    task: ReconAiTask,
    run_id: str,
    job_id: str,
    trace_id: str | None = None,
) -> TaskRunMetadata:
    """Build canonical run linkage metadata for task schemas."""
    return TaskRunMetadata(
        task=task,
        run_id=run_id,
        job_id=job_id,
        run_link=f"recon://runs/{run_id}",
        job_link=f"recon://jobs/{job_id}",
        trace_id=trace_id or f"{run_id}:{job_id}:{task.value}",
    )


def validate_meta_task(meta: TaskRunMetadata, expected_task: ReconAiTask) -> TaskRunMetadata:
    """Ensure input metadata is linked to the expected AI task."""
    if meta.task != expected_task:
        raise ValueError(
            f"meta.task must be '{expected_task.value}', got '{meta.task.value}'",
        )
    return meta


class VarunMetadata(BaseModel):
    """Run/job linkage metadata for vulnerability analysis AI task payloads."""

    model_config = ConfigDict(extra="forbid")

    task: VulnerabilityAnalysisAiTask
    run_id: StrictStr = Field(min_length=1, max_length=200)
    job_id: StrictStr = Field(min_length=1, max_length=200)
    engagement_id: StrictStr = Field(min_length=1, max_length=36)
    trace_id: StrictStr = Field(min_length=1, max_length=300)


def validate_va_meta_task(
    meta: VarunMetadata,
    expected_task: VulnerabilityAnalysisAiTask,
) -> VarunMetadata:
    """Ensure input metadata is linked to the expected VA AI task."""
    if meta.task != expected_task:
        raise ValueError(
            f"meta.task must be '{expected_task.value}', got '{meta.task.value}'",
        )
    return meta


def validate_tm_meta_task(
    meta: ThreatModelRunMetadata,
    expected_task: ThreatModelingAiTask,
) -> ThreatModelRunMetadata:
    """Ensure input metadata is linked to the expected threat modeling AI task."""
    if meta.task != expected_task:
        raise ValueError(
            f"meta.task must be '{expected_task.value}', got '{meta.task.value}'",
        )
    return meta


def build_tm_task_metadata(
    task: ThreatModelingAiTask,
    run_id: str,
    job_id: str,
    trace_id: str | None = None,
) -> ThreatModelRunMetadata:
    """Build canonical run linkage metadata for threat modeling task schemas."""
    return ThreatModelRunMetadata(
        task=task,
        run_id=run_id,
        job_id=job_id,
        trace_id=trace_id or f"{run_id}:{job_id}:{task.value}",
    )


def build_va_task_metadata(
    task: VulnerabilityAnalysisAiTask,
    run_id: str,
    job_id: str,
    engagement_id: str,
    trace_id: str | None = None,
) -> VarunMetadata:
    """Build canonical run linkage metadata for vulnerability analysis task schemas."""
    return VarunMetadata(
        task=task,
        run_id=run_id,
        job_id=job_id,
        engagement_id=engagement_id,
        trace_id=trace_id or f"{run_id}:{job_id}:{task.value}",
    )
