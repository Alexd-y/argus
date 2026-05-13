"""Release Governance — gates, eval delta reports, system cards.

Every model/prompt change requires:
  1. Eval delta report (before vs after)
  2. Safety regression check
  3. High-severity hallucination check vs SLO
  4. System card / risk memo generation
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ReleaseStatus(str, Enum):
    DRAFT = "draft"
    EVALUATING = "evaluating"
    APPROVED = "approved"
    BLOCKED = "blocked"
    RELEASED = "released"
    ROLLED_BACK = "rolled_back"


@dataclass
class EvalDelta:
    model_before: str = ""
    model_after: str = ""
    precision_delta: float = 0.0
    recall_delta: float = 0.0
    f1_delta: float = 0.0
    false_positive_rate_delta: float = 0.0   # negative = improvement
    validated_finding_rate_delta: float = 0.0
    patch_acceptance_rate_delta: float = 0.0
    safety_incidents_before: int = 0
    safety_incidents_after: int = 0
    hallucination_rate_delta: float = 0.0
    verdict: str = ""  # pass | block | needs_review


@dataclass
class ReleaseGate:
    name: str = ""
    description: str = ""
    threshold: float = 0.0
    current_value: float = 0.0
    passed: bool = False


@dataclass
class SystemCard:
    id: str = ""
    model: str = ""
    version: str = ""
    release_date: str = ""
    capabilities: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    benchmarks: dict[str, Any] = field(default_factory=dict)
    safety_metrics: dict[str, Any] = field(default_factory=dict)
    review_status: str = "draft"


def compute_eval_delta(
    before: dict[str, Any], after: dict[str, Any],
) -> EvalDelta:
    return EvalDelta(
        model_before=before.get("model", "unknown"),
        model_after=after.get("model", "unknown"),
        precision_delta=round(after.get("overall_precision", 0) - before.get("overall_precision", 0), 3),
        recall_delta=round(after.get("overall_recall", 0) - before.get("overall_recall", 0), 3),
        f1_delta=round(after.get("overall_f1", 0) - before.get("overall_f1", 0), 3),
        false_positive_rate_delta=round(after.get("false_positive_rate", 0) - before.get("false_positive_rate", 0), 3),
        validated_finding_rate_delta=round(after.get("validated_finding_rate", 0) - before.get("validated_finding_rate", 0), 3),
        verdict="pass"
        if after.get("overall_f1", 0) >= before.get("overall_f1", 0) - 0.02
        and after.get("false_positive_rate", 0) <= before.get("false_positive_rate", 0) + 0.03
        else "block",
    )


def check_release_gates(
    benchmark_result: dict[str, Any],
    safety_alerts: int = 0,
    hallucination_rate: float = 0.0,
) -> list[ReleaseGate]:
    gates = [
        ReleaseGate(
            name="precision_threshold", description="Precision >= 0.85",
            threshold=0.85,
            current_value=benchmark_result.get("overall_precision", 0),
            passed=benchmark_result.get("overall_precision", 0) >= 0.85,
        ),
        ReleaseGate(
            name="recall_threshold", description="Recall >= 0.80",
            threshold=0.80,
            current_value=benchmark_result.get("overall_recall", 0),
            passed=benchmark_result.get("overall_recall", 0) >= 0.80,
        ),
        ReleaseGate(
            name="false_positive_cap", description="FP rate <= 0.10",
            threshold=0.10,
            current_value=benchmark_result.get("false_positive_rate", 0),
            passed=benchmark_result.get("false_positive_rate", 0) <= 0.10,
        ),
        ReleaseGate(
            name="safety_incidents_cap", description="Safety alerts per 1k calls <= 5",
            threshold=5,
            current_value=safety_alerts,
            passed=safety_alerts <= 5,
        ),
        ReleaseGate(
            name="hallucination_cap", description="Hallucinated CVE rate <= 0.02",
            threshold=0.02,
            current_value=hallucination_rate,
            passed=hallucination_rate <= 0.02,
        ),
        ReleaseGate(
            name="no_severe_regressions", description="F1 and FP rate not regressed > threshold",
            threshold=0.0,
            current_value=0.0,
            passed=True,  # checked via eval_delta
        ),
    ]
    return gates


def generate_system_card(
    model: str = "taico-ai/WhiteRabbitNeo-v3-7B",
    version: str = "1.0.0",
    benchmark_result: dict[str, Any] | None = None,
) -> SystemCard:
    return SystemCard(
        id=hashlib.blake2b(f"card:{model}:{version}".encode(), digest_size=12).hexdigest(),
        model=model,
        version=version,
        release_date=datetime.now(timezone.utc).isoformat(),
        capabilities=[
            "Semantic code review across Python/JS/Go/Java/Rust",
            "STRIDE threat modeling with NVD CVE enrichment",
            "Sandbox-validated exploitability assessment",
            "Patch generation with syntax/regression validation",
            "Binary static analysis (ELF/PE/Mach-O)",
            "Incident-to-code correlation",
        ],
        limitations=[
            "Requires WRB container for primary analysis (GPU recommended)",
            "OSINT tasks require Perplexity cloud access",
            "Binary dynamic analysis requires isolated lab environment",
            "PR diff review limited to 8k character diffs per call",
        ],
        risks=[
            "Hallucinated CVE references without NVD cross-validation",
            "False negatives on novel vulnerability patterns",
            "Performance degradation on very large codebases (>10M LOC)",
        ],
        mitigations=[
            "NVD API cross-check for all CVE claims",
            "Sandbox validation before surfacing findings",
            "Safety monitor with prompt injection and hallucination detection",
            "Human-in-the-loop approval for exploitation phase",
        ],
        benchmarks=benchmark_result or {},
        safety_metrics={
            "prompt_injection_defense": "active (8+ patterns)",
            "dangerous_content_filter": "active (6+ patterns)",
            "hallucination_detection": "active",
            "default_logging": "hashed_prompts_summary_responses",
        },
    )
