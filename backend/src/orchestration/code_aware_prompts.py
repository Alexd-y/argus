"""Code-aware prompt builder — injects AST fragments into verifier prompts.

Takes source analysis output (sinks, sources, taint paths) and constructs
prompt sections that give the LLM concrete code context for vulnerability
verification. This replaces generic "check for injection" instructions with
specific "file X line Y calls mysql_query with user input from line Z".

Ось D / Фаза 1 из Развитие2.md: code-aware verification prompts.
"""

from __future__ import annotations

import logging

from src.orchestration.phases import (
    CodeSink,
    CodeSource,
    SourceAnalysisOutput,
    TaintPath,
)

logger = logging.getLogger(__name__)

MAX_SNIPPET_LENGTH = 500
MAX_SINKS_IN_PROMPT = 10
MAX_SOURCES_IN_PROMPT = 10
MAX_TAINT_PATHS_IN_PROMPT = 5


def build_sink_context(sinks: list[CodeSink], limit: int = MAX_SINKS_IN_PROMPT) -> str:
    """Build a prompt section listing identified sinks with code snippets."""
    if not sinks:
        return "No sinks identified in source analysis."
    lines = ["=== IDENTIFIED SINKS (dangerous function calls) ==="]
    for sink in sinks[:limit]:
        snippet = sink.code_snippet[:MAX_SNIPPET_LENGTH] if sink.code_snippet else ""
        lines.append(
            f"- {sink.file_path}:{sink.line_number or '?'} "
            f"[{sink.sink_type}] severity={sink.severity}"
        )
        if snippet:
            lines.append(f"  Code: {snippet}")
    lines.append("=== END SINKS ===")
    return "\n".join(lines)


def build_source_context(sources: list[CodeSource], limit: int = MAX_SOURCES_IN_PROMPT) -> str:
    """Build a prompt section listing identified user-input sources."""
    if not sources:
        return "No entry-point sources identified in source analysis."
    lines = ["=== USER INPUT SOURCES (entry points) ==="]
    for source in sources[:limit]:
        snippet = source.code_snippet[:MAX_SNIPPET_LENGTH] if source.code_snippet else ""
        lines.append(
            f"- {source.file_path}:{source.line_number or '?'} "
            f"[{source.source_type}] param={source.parameter_name or 'unknown'}"
        )
        if snippet:
            lines.append(f"  Code: {snippet}")
    lines.append("=== END SOURCES ===")
    return "\n".join(lines)


def build_taint_path_context(taint_paths: list[TaintPath], limit: int = MAX_TAINT_PATHS_IN_PROMPT) -> str:
    """Build a prompt section listing identified taint paths (source→sink)."""
    if not taint_paths:
        return "No taint paths identified in source analysis."
    lines = ["=== TAINT PATHS (source→sink data flows) ==="]
    for i, path in enumerate(taint_paths[:limit], 1):
        src = path.source
        snk = path.sink
        sanitized = " [SANITIZED]" if path.is_sanitized else ""
        lines.append(
            f"Path {i}: {src.file_path}:{src.line_number or '?'} "
            f"({src.source_type}) → {snk.file_path}:{snk.line_number or '?'} "
            f"({snk.sink_type}){sanitized}"
        )
        if path.sanitizers:
            lines.append(f"  Sanitizers: {', '.join(path.sanitizers)}")
        if path.intermediate_nodes:
            lines.append(f"  Via: {' → '.join(path.intermediate_nodes)}")
    lines.append("=== END TAINT PATHS ===")
    return "\n".join(lines)


def build_code_aware_prompt_section(
    source_analysis: SourceAnalysisOutput | None,
) -> str:
    """Build a complete code-aware prompt section from source analysis output.

    Injects this into vulnerability verification prompts so the LLM
    knows exactly which sinks, sources, and taint paths to verify.
    """
    if source_analysis is None or source_analysis.skipped:
        return ""

    parts: list[str] = []

    if source_analysis.framework:
        parts.append(f"Framework: {source_analysis.framework}")
    if source_analysis.language:
        parts.append(f"Primary language: {source_analysis.language}")

    if source_analysis.sinks:
        parts.append(build_sink_context(source_analysis.sinks))
    if source_analysis.entry_points:
        parts.append(build_source_context(source_analysis.entry_points))
    if source_analysis.taint_paths:
        parts.append(build_taint_path_context(source_analysis.taint_paths))

    return "\n\n".join(parts) if parts else ""


__all__ = [
    "MAX_SINKS_IN_PROMPT",
    "MAX_SOURCES_IN_PROMPT",
    "MAX_TAINT_PATHS_IN_PROMPT",
    "build_code_aware_prompt_section",
    "build_sink_context",
    "build_source_context",
    "build_taint_path_context",
]
