"""CONT-004 — Key metrics for LAB execution mode (delegates to unified catalogue).

Integer helpers and legacy increment functions remain here for backward
compatibility. Prometheus registration lives in
``src.core.unified_ai_metrics`` to avoid duplicate Counter registration.
"""

from __future__ import annotations

from src.core import unified_ai_metrics as _metrics
from src.nuclei.legacy_metrics import (
    get_legacy_argv_total as get_nuclei_legacy_argv_total,
)

__all__ = [
    "get_lab_boundary_denials_total",
    "get_lab_executions_total",
    "get_llm_fallback_total",
    "get_nuclei_legacy_argv_builder_total",
    "increment_lab_boundary_denial",
    "increment_lab_execution",
    "increment_llm_fallback",
    "reset_execution_mode_metrics",
]


def increment_lab_execution() -> int:
    """Record one LAB allow-all policy decision."""
    return _metrics.record_lab_execution()


def increment_lab_boundary_denial() -> int:
    """Record one LAB boundary denial."""
    return _metrics.record_lab_boundary_denial()


def increment_llm_fallback() -> int:
    """Record one LLM provider failover / fallback attempt."""
    return _metrics.record_llm_fallback()


def get_lab_executions_total() -> int:
    return _metrics.get_lab_executions_total()


def get_lab_boundary_denials_total() -> int:
    return _metrics.get_lab_boundary_denials_total()


def get_llm_fallback_total() -> int:
    return _metrics.get_llm_fallback_total()


def get_nuclei_legacy_argv_builder_total() -> int:
    """Delegate to nuclei legacy argv counter (``nuclei_legacy_argv_builder_total``)."""
    return get_nuclei_legacy_argv_total()


def reset_execution_mode_metrics() -> None:
    """Reset module counters — tests only."""
    _metrics.reset_unified_ai_metrics()
