"""Scan phases enum and input/output contracts (Pydantic models).

Extended with structured exploitation queue (ExploitationQueue),
evidence tier (EvidenceTier), and source analysis phase.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from src.orchestration.evidence_tier import EvidenceTier
from src.orchestration.exploitation_queue import (
    ExploitationQueue,
)

# Progress mapping per phase (0-100)
PHASE_PROGRESS: dict[str, int] = {
    "source_analysis": 5,
    "recon": 15,
    "quick_fuzz": 35,
    "threat_modeling": 45,
    "vuln_analysis": 55,
    "exploitation": 70,
    "post_exploitation": 85,
    "reporting": 100,
}


@dataclass(frozen=True)
class PhaseDefinition:
    """Phase definition: name, schemas, prompt keys for LLM."""

    name: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    prompt_key: str
    retry_prompt_key: str


class ScanPhase(str, Enum):
    """8 phases of pentest pipeline (quick_fuzz added between recon and threat_modeling)."""

    SOURCE_ANALYSIS = "source_analysis"
    RECON = "recon"
    QUICK_FUZZ = "quick_fuzz"
    THREAT_MODELING = "threat_modeling"
    VULN_ANALYSIS = "vuln_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


PHASE_ORDER: list[ScanPhase] = [
    ScanPhase.SOURCE_ANALYSIS,
    ScanPhase.RECON,
    ScanPhase.QUICK_FUZZ,
    ScanPhase.THREAT_MODELING,
    ScanPhase.VULN_ANALYSIS,
    ScanPhase.EXPLOITATION,
    ScanPhase.POST_EXPLOITATION,
    ScanPhase.REPORTING,
]


class ExploitationSubPhase(str, Enum):
    """Sub-phases within exploitation phase."""

    EXPLOIT_ATTEMPT = "exploit_attempt"
    EXPLOIT_VERIFY = "exploit_verify"


# --- Source Analysis ---
class SourceAnalysisInput(BaseModel):
    """Input for source_analysis phase (phase 0).

    Receives the target URL and optional repository path for white-box analysis.
    If ``repo_path`` is None, source analysis is skipped and the pipeline
    proceeds directly to recon.
    """

    target: str
    repo_path: str | None = Field(
        default=None,
        description="Local path to cloned repository (None = skip source analysis).",
    )
    repo_url: str | None = Field(
        default=None,
        description="Remote repository URL for git clone if not yet cloned.",
    )
    options: dict[str, Any] = Field(default_factory=dict)


class CodeSink(BaseModel):
    """A security-relevant sink identified in source code."""

    file_path: str = Field(description="Relative file path in the repository.")
    line_number: int | None = Field(default=None, description="Line number.")
    sink_type: str = Field(
        description="Type: sql_query, command_exec, html_render, http_request, file_read, etc.",
    )
    code_snippet: str = Field(default="", max_length=2000, description="Surrounding code.")
    function_name: str | None = Field(default=None, description="Containing function/method.")
    severity: str = Field(default="medium", description="Estimated severity: low, medium, high, critical.")


class CodeSource(BaseModel):
    """A user-input source identified in source code."""

    file_path: str = Field(description="Relative file path.")
    line_number: int | None = Field(default=None, description="Line number.")
    source_type: str = Field(
        description="Type: http_param, form_input, cookie, header, url_path, websocket, etc.",
    )
    parameter_name: str | None = Field(default=None, description="Parameter/variable name.")
    code_snippet: str = Field(default="", max_length=2000, description="Surrounding code.")


class TaintPath(BaseModel):
    """A source-to-sink data flow path identified by static analysis."""

    source: CodeSource
    sink: CodeSink
    intermediate_nodes: list[str] = Field(
        default_factory=list,
        description="Intermediate function calls in the data flow.",
    )
    sanitizers: list[str] = Field(
        default_factory=list,
        description="Sanitizer/validation functions applied along the path.",
    )
    is_sanitized: bool = Field(
        default=False,
        description="Whether the sanitization is sufficient for this vulnerability class.",
    )


class SourceAnalysisOutput(BaseModel):
    """Output of source_analysis phase (phase 0).

    Provides architectural intelligence from static source code analysis
    that feeds into recon and threat modeling phases.
    """

    framework: str | None = Field(
        default=None,
        description="Detected application framework (e.g., Django, Express, Spring Boot).",
    )
    language: str | None = Field(default=None, description="Primary programming language.")
    entry_points: list[CodeSource] = Field(
        default_factory=list,
        description="All identified user-input sources (HTTP params, form fields, etc.).",
    )
    sinks: list[CodeSink] = Field(
        default_factory=list,
        description="All identified dangerous sinks (SQL queries, command exec, HTML render).",
    )
    taint_paths: list[TaintPath] = Field(
        default_factory=list,
        description="Source-to-sink data flow paths with sanitization analysis.",
    )
    auth_patterns: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Identified authentication/authorization patterns.",
    )
    api_endpoints: list[dict[str, Any]] = Field(
        default_factory=list,
        description="API endpoints discovered from code (routes, controllers, handlers).",
    )
    file_tree: dict[str, Any] = Field(
        default_factory=dict,
        description="Simplified repository file tree for context.",
    )
    summary: str = Field(
        default="",
        max_length=10000,
        description="Executive summary of source analysis findings.",
    )
    skipped: bool = Field(
        default=True,
        description="Whether source analysis was skipped (no repository provided).",
    )


# --- Recon ---
class ReconInput(BaseModel):
    """Input for recon phase."""

    target: str
    options: dict[str, Any] = Field(default_factory=dict)
    source_analysis: SourceAnalysisOutput | None = Field(
        default=None,
        description="Results from source_analysis phase (if available).",
    )


class ReconOutput(BaseModel):
    """Output of recon phase."""

    assets: list[str] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    technologies: list[str] = Field(
        default_factory=list,
        description=(
            "Detected technology stack (WhatWeb/httpx), reconciled deterministically "
            "from raw tool output so it is not lost when the LLM omits it (Block 1.1)."
        ),
    )
    tool_results: dict[str, Any] = Field(default_factory=dict, exclude=True)
    crawl_params: list[dict[str, Any]] = Field(default_factory=list, exclude=True)
    crawl_forms: list[dict[str, Any]] = Field(default_factory=list, exclude=True)
    coverage_results: list[dict[str, Any]] = Field(default_factory=list)


# --- Quick Fuzz ---
class QuickFuzzInput(BaseModel):
    """Input for quick_fuzz phase (between recon and threat_modeling).

    Receives the target URL and recon output (discovered endpoints, tech
    stack) to identify quick-win vulnerabilities before deep VULN_ANALYSIS.
    """

    target: str
    recon_output: dict[str, Any] = Field(default_factory=dict)
    options: dict[str, Any] = Field(default_factory=dict)


class QuickFuzzOutput(BaseModel):
    """Output of quick_fuzz phase.

    Produces candidate findings and narrowed-down endpoint/parameter
    combinations that deserve deep testing in VULN_ANALYSIS.
    """

    findings: list[dict[str, Any]] = Field(default_factory=list)
    fuzz_results: list[dict[str, Any]] = Field(default_factory=list)
    candidates: list[dict[str, Any]] = Field(
        default_factory=list,
        description="FuzzCandidate dicts — endpoints for deep VULN_ANALYSIS testing.",
    )
    tech_stack: dict[str, Any] = Field(default_factory=dict)
    baseline_responses: dict[str, Any] = Field(default_factory=dict)


# --- Threat Modeling ---
class ThreatModelInput(BaseModel):
    """Input for threat modeling phase."""

    assets: list[str] = Field(default_factory=list)
    source_analysis: SourceAnalysisOutput | None = Field(
        default=None,
        description="Source code analysis results for code-aware threat modeling.",
    )


class ThreatModelOutput(BaseModel):
    """Output of threat modeling phase."""

    threat_model: dict[str, Any] = Field(default_factory=dict)


# --- Vuln Analysis ---
class VulnAnalysisInput(BaseModel):
    """Input for vuln_analysis phase."""

    threat_model: dict[str, Any] = Field(default_factory=dict)
    assets: list[str] = Field(default_factory=list)


class VulnAnalysisOutput(BaseModel):
    """Output of vuln_analysis phase.

    Extended with ``exploitation_queues`` — a structured mapping of
    vulnerability class to ``ExploitationQueue``.  When present, the
    exploitation phase consumes this instead of raw ``findings`` dicts.

    The ``exploitation_queues`` field is optional for backward
    compatibility: older pipeline producers that only populate
    ``findings`` continue to work unchanged.
    """

    findings: list[dict[str, Any]] = Field(default_factory=list)
    coverage_results: list[dict[str, Any]] = Field(default_factory=list)
    active_injection_coverage: dict[str, Any] = Field(default_factory=dict)
    exploitation_queues: dict[str, ExploitationQueue] | None = Field(
        default=None,
        description=(
            "Structured queues of exploit hypotheses keyed by VulnClass. "
            "When present, these replace raw findings as input to exploitation."
        ),
    )
    hypotheses: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Exploit hypotheses from CWE-specialized vuln agents. "
            "Each hypothesis includes vuln_type, location, method, parameter, "
            "evidence, suggested_payload, confidence, source_domain, source_agent."
        ),
    )


# --- Exploitation ---
class ExploitationInput(BaseModel):
    """Input for exploitation phase.

    Supports both legacy ``findings`` dicts and the new structured
    ``exploitation_queue``.  When ``exploitation_queue`` is present,
    exploit agents should prefer its hypotheses over raw findings.
    """

    findings: list[dict[str, Any]] = Field(default_factory=list)
    exploitation_queue: ExploitationQueue | None = Field(
        default=None,
        description=(
            "Structured exploitation queue from vuln_analysis. "
            "When present, provides typed hypotheses with confidence, "
            "evidence tier, and suggested payloads."
        ),
    )
    auth_config: dict[str, Any] | None = Field(
        default=None,
        description="Authentication configuration for the target (serialized AuthConfig).",
    )


class ExploitationOutput(BaseModel):
    """Output of exploitation phase.

    Extended with ``evidence_tiers`` — a mapping from finding/stable IDs
    to their final evidence tier after exploitation.  This enables the
    reporting phase to classify findings as EXPLOITED, CONFIRMED,
    SUSPECTED, or INFORMATIONAL.
    """

    exploits: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    evidence_tiers: dict[str, EvidenceTier] = Field(
        default_factory=dict,
        description=(
            "Mapping of finding/stable IDs to their EvidenceTier after "
            "exploitation. Keys are finding IDs, values are tier integers (1-4)."
        ),
    )
    status: str = Field(
        default="",
        description=(
            "Phase status. 'skipped: no actionable hypotheses' when vuln_analysis "
            "produced no exploitable (non-informational) hypothesis, so the phase "
            "honestly did not run rather than emitting empty results (Block 1.4)."
        ),
    )


# --- Post Exploitation ---
class PostExploitationInput(BaseModel):
    """Input for post_exploitation phase."""

    exploits: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Evidence artifacts from exploitation phase (screenshots, tool output, PoC data).",
    )
    evidence_tiers: dict[str, int] = Field(
        default_factory=dict,
        description="Mapping of finding IDs to EvidenceTier (1-4) from exploitation.",
    )


class PostExploitationOutput(BaseModel):
    """Output of post_exploitation phase."""

    lateral: list[dict[str, Any]] = Field(default_factory=list)
    persistence: list[dict[str, Any]] = Field(default_factory=list)
    status: str = Field(
        default="",
        description=(
            "Phase status. 'analyzed' when grounded in a confirmed exploit; "
            "'not applicable (no confirmed access)' when there is no verified "
            "exploit — in which case lateral/persistence are forced empty "
            "(Block 1.5 anti-hallucination)."
        ),
    )


# --- Reporting ---
class ReportingInput(BaseModel):
    """Input for reporting phase — aggregates all prior outputs."""

    target: str = ""
    recon: ReconOutput | None = None
    threat_model: ThreatModelOutput | None = None
    vuln_analysis: VulnAnalysisOutput | None = None
    exploitation: ExploitationOutput | None = None
    post_exploitation: PostExploitationOutput | None = None
    # Server-side enrichment (e.g. HIBP aggregate); no secrets — merged into LLM summary in ai_reporting.
    report_context: dict[str, Any] = Field(default_factory=dict)
    # Scoping configuration for the report — what to focus/avoid,
    # minimum severity/confidence thresholds, and free-form guidance.
    scope_config: dict[str, Any] | None = Field(
        default=None,
        description="Serialized TargetConfig with rules of engagement for the report.",
    )
    source_analysis: dict[str, Any] | None = Field(
        default=None,
        description="Source analysis output for code-level findings (taint paths, code locations).",
    )


class ReportingOutput(BaseModel):
    """Output of reporting phase."""

    report: dict[str, Any] = Field(default_factory=dict)
    coverage_results: list[dict[str, Any]] = Field(default_factory=list)


# --- Phase definitions (input/output schemas, prompt keys) ---

SOURCE_ANALYSIS_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["target"],
    "properties": {
        "target": {"type": "string"},
        "repo_path": {"type": "string"},
        "repo_url": {"type": "string"},
        "options": {"type": "object"},
    },
}
RECON_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["target", "options"],
    "properties": {"target": {"type": "string"}, "options": {"type": "object"}},
}
QUICK_FUZZ_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["target"],
    "properties": {
        "target": {"type": "string"},
        "recon_output": {"type": "object"},
        "options": {"type": "object"},
    },
}
THREAT_MODELING_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["assets"],
    "properties": {"assets": {"type": "array", "items": {"type": "string"}}},
}
VULN_ANALYSIS_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["threat_model", "assets"],
    "properties": {
        "threat_model": {"type": "object"},
        "assets": {"type": "array", "items": {"type": "string"}},
    },
}
EXPLOITATION_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["findings"],
    "properties": {"findings": {"type": "array", "items": {"type": "object"}}},
}
POST_EXPLOITATION_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["exploits"],
    "properties": {"exploits": {"type": "array", "items": {"type": "object"}}},
}
REPORTING_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["target"],
    "properties": {
        "target": {"type": "string"},
        "recon": {"type": "object"},
        "threat_model": {"type": "object"},
        "vuln_analysis": {"type": "object"},
        "exploitation": {"type": "object"},
        "post_exploitation": {"type": "object"},
        "report_context": {"type": "object"},
    },
}


def _get_output_schemas() -> dict[str, dict[str, Any]]:
    """Lazy import to avoid circular dependency with prompt_registry."""
    from src.orchestration.prompt_registry import PHASE_SCHEMAS

    return PHASE_SCHEMAS


def get_phase_definition(phase: str) -> PhaseDefinition:
    """Return PhaseDefinition for phase name."""
    schemas = _get_output_schemas()
    input_schemas = {
        "source_analysis": SOURCE_ANALYSIS_INPUT_SCHEMA,
        "recon": RECON_INPUT_SCHEMA,
        "quick_fuzz": QUICK_FUZZ_INPUT_SCHEMA,
        "threat_modeling": THREAT_MODELING_INPUT_SCHEMA,
        "vuln_analysis": VULN_ANALYSIS_INPUT_SCHEMA,
        "exploitation": EXPLOITATION_INPUT_SCHEMA,
        "post_exploitation": POST_EXPLOITATION_INPUT_SCHEMA,
        "reporting": REPORTING_INPUT_SCHEMA,
    }
    return PhaseDefinition(
        name=phase,
        input_schema=input_schemas.get(phase, {}),
        output_schema=schemas.get(phase, {}),
        prompt_key=phase,
        retry_prompt_key=f"{phase}_retry",
    )


PHASE_DEFINITIONS: dict[str, PhaseDefinition] = {
    p.value: get_phase_definition(p.value) for p in ScanPhase
}
