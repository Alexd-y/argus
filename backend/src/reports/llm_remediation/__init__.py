"""Mandatory Valhalla per-finding LLM remediation + closure analysis.

This package implements the core of the 2026-09-15 Valhalla spec: strict LLM
output contracts, deterministic application-owned closure status, redacted
per-finding context, versioned prompts and the orchestration runner. Rendering,
XML/XSD, format delivery and parity are built on top in later slices.
"""

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
    "AnalysisStatus",
    "ClosureComputationInput",
    "ClosureComputationResult",
    "FindingAnalysisResult",
    "FindingClosureConclusion",
    "FindingContext",
    "FindingRemediationAnalysis",
    "LlmCallable",
    "LlmTransientError",
    "PermittedClosureStatus",
    "RemediationRunResult",
    "RemediationRunner",
    "ReportClosureSummary",
    "RetestExecution",
    "RetestOutcome",
    "build_finding_context",
    "compute_permitted_closure_status",
    "make_retest_execution",
    "redact_text",
]
