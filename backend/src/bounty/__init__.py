"""Bug Bounty Planning Module for ARGUS.

Provides scope ingestion, attack surface classification, vulnerability
prioritisation by payout, phased test plan generation, and LLM-powered
hunter insights. This is a standalone module, not part of the scan pipeline.
"""

from src.bounty.surface_classifier import SurfaceType, classify_surfaces
from src.bounty.vuln_prioritizer import VULN_PRIORITY, prioritize_vulns
from src.bounty.test_planner import generate_test_plan, TestPlanPhase
from src.bounty.schemas import (
    BountyScope,
    BountyTestPlan,
    ClassifiedSurface,
    ScopeIngestRequest,
    VulnPriority,
)

__all__ = [
    "BountyScope",
    "BountyTestPlan",
    "ClassifiedSurface",
    "ScopeIngestRequest",
    "SurfaceType",
    "VulnPriority",
    "VULN_PRIORITY",
    "classify_surfaces",
    "generate_test_plan",
    "prioritize_vulns",
]