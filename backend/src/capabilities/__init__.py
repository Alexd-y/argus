"""Capability knowledge graph and coverage accounting."""

from src.capabilities.coverage import (
    CoverageAccountingError,
    absence_of_finding_is_not_coverage,
    build_coverage_result,
    can_transition_coverage,
    infer_status_from_execution,
    is_covered_status,
    resolve_coverage_status,
)
from src.capabilities.graph import CapabilityGraph, default_capability_graph
from src.capabilities.schemas import (
    COVERED_STATUSES,
    AssetCapabilityProfile,
    CapabilityApplicability,
    CapabilityEdge,
    CapabilityEdgeType,
    CapabilityFamily,
    CapabilityNode,
    CoverageRequirement,
    CoverageResult,
    CoverageStatus,
    ProductionRisk,
)

__all__ = [
    "COVERED_STATUSES",
    "AssetCapabilityProfile",
    "CapabilityApplicability",
    "CapabilityEdge",
    "CapabilityEdgeType",
    "CapabilityFamily",
    "CapabilityGraph",
    "CapabilityNode",
    "CoverageAccountingError",
    "CoverageRequirement",
    "CoverageResult",
    "CoverageStatus",
    "ProductionRisk",
    "absence_of_finding_is_not_coverage",
    "build_coverage_result",
    "can_transition_coverage",
    "default_capability_graph",
    "infer_status_from_execution",
    "is_covered_status",
    "resolve_coverage_status",
]
