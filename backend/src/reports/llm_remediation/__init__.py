"""Mandatory Valhalla per-finding LLM remediation + closure analysis.

This package implements the core of the 2026-09-15 Valhalla spec: strict LLM
output contracts, deterministic application-owned closure status, redacted
per-finding context, versioned prompts and the orchestration runner. Rendering,
XML/XSD, format delivery and parity are built on top in later slices.
"""

from src.reports.llm_remediation.builder import (
    CompletenessAssessment,
    assess_llm_completeness,
    build_valhalla_llm_document,
)
from src.reports.llm_remediation.bundle import (
    VALHALLA_LLM_FORMATS,
    GenerationStatus,
    UnknownFormatError,
    ValhallaArtifact,
    ValhallaRelease,
    ValhallaReleaseManifest,
    build_valhalla_release,
)
from src.reports.llm_remediation.closure_status import (
    ClosureComputationInput,
    ClosureComputationResult,
    RetestExecution,
    RetestOutcome,
    compute_permitted_closure_status,
)
from src.reports.llm_remediation.context import (
    REDACTION_VERSION,
    FindingContext,
    build_finding_context,
    redact_text,
)
from src.reports.llm_remediation.document import (
    VALHALLA_LLM_DOC_VERSION,
    AssessmentCompleteness,
    ValhallaFindingNode,
    ValhallaLlmDocument,
)
from src.reports.llm_remediation.render import (
    VALHALLA_LLM_XSD,
    assert_semantic_parity,
    parity_facts,
    render_all_text_formats,
    render_html,
    render_json,
    render_markdown,
    render_xml,
    validate_valhalla_xml,
)
from src.reports.llm_remediation.runner import (
    FindingAnalysisResult,
    LlmCallable,
    LlmTransientError,
    RemediationRunner,
    RemediationRunResult,
    make_retest_execution,
)
from src.reports.llm_remediation.schemas import (
    AnalysisStatus,
    FindingClosureConclusion,
    FindingRemediationAnalysis,
    PermittedClosureStatus,
    ReportClosureSummary,
)

__all__ = [
    "REDACTION_VERSION",
    "VALHALLA_LLM_DOC_VERSION",
    "VALHALLA_LLM_FORMATS",
    "VALHALLA_LLM_XSD",
    "AnalysisStatus",
    "AssessmentCompleteness",
    "ClosureComputationInput",
    "ClosureComputationResult",
    "CompletenessAssessment",
    "FindingAnalysisResult",
    "FindingClosureConclusion",
    "FindingContext",
    "FindingRemediationAnalysis",
    "GenerationStatus",
    "LlmCallable",
    "LlmTransientError",
    "PermittedClosureStatus",
    "RemediationRunResult",
    "RemediationRunner",
    "ReportClosureSummary",
    "RetestExecution",
    "RetestOutcome",
    "UnknownFormatError",
    "ValhallaArtifact",
    "ValhallaFindingNode",
    "ValhallaLlmDocument",
    "ValhallaRelease",
    "ValhallaReleaseManifest",
    "assert_semantic_parity",
    "assess_llm_completeness",
    "build_finding_context",
    "build_valhalla_llm_document",
    "build_valhalla_release",
    "compute_permitted_closure_status",
    "make_retest_execution",
    "parity_facts",
    "redact_text",
    "render_all_text_formats",
    "render_html",
    "render_json",
    "render_markdown",
    "render_xml",
    "validate_valhalla_xml",
]
