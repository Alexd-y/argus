"""Source analysis module — white-box source code analysis pipeline.

Performs static analysis of the target application's source code to
identify architectural patterns, attack surface, sinks, and taint paths.
Inspired by Shannon's Pre-Reconnaissance agent but adapted for ARGUS's
multi-LLM, multi-tool architecture.
"""

from src.orchestration.source_analysis.analyzer import SourceAnalyzer
from src.orchestration.source_analysis.tree_sitter_parser import (
    LanguageDetector,
    TreeSitterParser,
)

__all__ = [
    "SourceAnalyzer",
    "LanguageDetector",
    "TreeSitterParser",
]