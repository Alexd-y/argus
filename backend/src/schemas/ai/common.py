from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ValidationError


class PriorityLevel(str, Enum):  # noqa: UP042
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ReconAiTask(str, Enum):  # noqa: UP042
    ROUTE_DISCOVERY = "route_discovery"
    JS_ANALYSIS = "js_analysis"
    PARAM_DISCOVERY = "param_discovery"
    API_SURFACE = "api_surface"
    STAGE3_READINESS = "stage3_readiness"


class ThreatModelingAiTask(str, Enum):  # noqa: UP042
    CRITICAL_ASSETS = "critical_assets"
    TRUST_BOUNDARIES = "trust_boundaries"
    ATTACKER_PROFILES = "attacker_profiles"
    ENTRY_POINTS = "entry_points"
    APPLICATION_FLOWS = "application_flows"
    THREAT_SCENARIOS = "threat_scenarios"
    SCENARIO_SCORING = "scenario_scoring"
    TESTING_ROADMAP = "testing_roadmap"
    REPORT_SUMMARY = "report_summary"


class VulnerabilityAnalysisAiTask(str, Enum):  # noqa: UP042
    # Active-scan / tool-intel interpretation (registry order)
    ACTIVE_SCAN_PLANNING = "active_scan_planning"
    WEB_SCAN_PLANNING = "web_scan_planning"
    XSS_ANALYSIS = "xss_analysis"
    SQLI_ANALYSIS = "sqli_analysis"
    NUCLEI_ANALYSIS = "nuclei_analysis"
    GENERIC_WEB_FINDING = "generic_web_finding"
    # Legacy VA AI tasks
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
    EVIDENCE_BUNDLE_ASSEMBLY = "evidence_bundle_assembly"
    FINDING_CONFIRMATION_ASSESSMENT = "finding_confirmation_assessment"
    CONTRADICTION_ANALYSIS = "contradiction_analysis"
    DUPLICATE_FINDING_CORRELATION = "duplicate_finding_correlation"
    FINDING_TO_SCENARIO_MAPPING = "finding_to_scenario_mapping"
    REMEDIATION_GENERATION = "remediation_generation"
    STAGE3_CONFIRMATION_SUMMARY = "stage3_confirmation_summary"
    EXPLOITATION_CANDIDATE_GENERATION = "exploitation_candidate_generation"
    # Prompt / shorthand aliases (distinct task_name strings)
    EVIDENCE_BUNDLE = "evidence_bundle"
    EVIDENCE_SUFFICIENCY = "evidence_sufficiency"
    CONFIRMATION_POLICY = "confirmation_policy"
    SCENARIO_MAPPING = "scenario_mapping"
    NEXT_PHASE_GATE = "next_phase_gate"
    EXPLOITATION_CANDIDATES = "exploitation_candidates"
    DUPLICATE_CORRELATION = "duplicate_correlation"


class TaskMetadata(BaseModel):
    task_name: str
    run_id: str
    job_id: str
    engagement_id: str | None = None


def build_task_metadata(
    task: ReconAiTask, run_id: str, job_id: str
) -> TaskMetadata:
    return TaskMetadata(task_name=task.value, run_id=run_id, job_id=job_id)


def build_tm_task_metadata(
    task: ThreatModelingAiTask, run_id: str, job_id: str
) -> TaskMetadata:
    return TaskMetadata(task_name=task.value, run_id=run_id, job_id=job_id)


def build_va_task_metadata(
    task: VulnerabilityAnalysisAiTask,
    run_id: str,
    job_id: str,
    engagement_id: str | None = None,
) -> TaskMetadata:
    return TaskMetadata(
        task_name=task.value,
        run_id=run_id,
        job_id=job_id,
        engagement_id=engagement_id,
    )


def validate_with_model(
    model_class: type[BaseModel], payload: dict
) -> list[str]:
    try:
        model_class.model_validate(payload)
    except ValidationError as exc:
        return [err["msg"] for err in exc.errors()]
    return []
