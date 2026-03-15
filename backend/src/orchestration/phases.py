"""Scan phases enum and input/output contracts (Pydantic models)."""

from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# Progress mapping per phase (0-100)
PHASE_PROGRESS: dict[str, int] = {
    "recon": 15,
    "threat_modeling": 25,
    "vuln_analysis": 45,
    "exploitation": 65,
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
    """6 phases of pentest pipeline."""

    RECON = "recon"
    THREAT_MODELING = "threat_modeling"
    VULN_ANALYSIS = "vuln_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


PHASE_ORDER: list[ScanPhase] = [
    ScanPhase.RECON,
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


# --- Recon ---
class ReconInput(BaseModel):
    """Input for recon phase."""

    target: str
    options: dict[str, Any] = Field(default_factory=dict)


class ReconOutput(BaseModel):
    """Output of recon phase."""

    assets: list[str] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)


# --- Threat Modeling ---
class ThreatModelInput(BaseModel):
    """Input for threat modeling phase."""

    assets: list[str] = Field(default_factory=list)


class ThreatModelOutput(BaseModel):
    """Output of threat modeling phase."""

    threat_model: dict[str, Any] = Field(default_factory=dict)


# --- Vuln Analysis ---
class VulnAnalysisInput(BaseModel):
    """Input for vuln_analysis phase."""

    threat_model: dict[str, Any] = Field(default_factory=dict)
    assets: list[str] = Field(default_factory=list)


class VulnAnalysisOutput(BaseModel):
    """Output of vuln_analysis phase."""

    findings: list[dict[str, Any]] = Field(default_factory=list)


# --- Exploitation ---
class ExploitationInput(BaseModel):
    """Input for exploitation phase."""

    findings: list[dict[str, Any]] = Field(default_factory=list)


class ExploitationOutput(BaseModel):
    """Output of exploitation phase."""

    exploits: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)


# --- Post Exploitation ---
class PostExploitationInput(BaseModel):
    """Input for post_exploitation phase."""

    exploits: list[dict[str, Any]] = Field(default_factory=list)


class PostExploitationOutput(BaseModel):
    """Output of post_exploitation phase."""

    lateral: list[dict[str, Any]] = Field(default_factory=list)
    persistence: list[dict[str, Any]] = Field(default_factory=list)


# --- Reporting ---
class ReportingInput(BaseModel):
    """Input for reporting phase — aggregates all prior outputs."""

    target: str = ""
    recon: ReconOutput | None = None
    threat_model: ThreatModelOutput | None = None
    vuln_analysis: VulnAnalysisOutput | None = None
    exploitation: ExploitationOutput | None = None
    post_exploitation: PostExploitationOutput | None = None


class ReportingOutput(BaseModel):
    """Output of reporting phase."""

    report: dict[str, Any] = Field(default_factory=dict)


# --- Phase definitions (input/output schemas, prompt keys) ---

RECON_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["target", "options"],
    "properties": {"target": {"type": "string"}, "options": {"type": "object"}},
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
        "recon": RECON_INPUT_SCHEMA,
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
