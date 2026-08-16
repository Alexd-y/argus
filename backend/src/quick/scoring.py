"""Configurable Quick priority formula with deterministic tie-break."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, StrictFloat


class ScoringWeights(BaseModel):
    """Exponents for the Quick priority product. Defaults reproduce master §6.4."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    exploitability: StrictFloat = Field(default=1.0, ge=0.0, le=8.0)
    expected_impact: StrictFloat = Field(default=1.0, ge=0.0, le=8.0)
    evidence_confidence: StrictFloat = Field(default=1.0, ge=0.0, le=8.0)
    asset_criticality: StrictFloat = Field(default=1.0, ge=0.0, le=8.0)
    coverage_value: StrictFloat = Field(default=1.0, ge=0.0, le=8.0)
    epsilon: StrictFloat = Field(default=1e-6, gt=0.0, le=1.0)


class ScoringComponents(BaseModel):
    """Inputs to the priority product. All factors are in [0, 1] except cost."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    exploitability_probability: StrictFloat = Field(ge=0.0, le=1.0)
    expected_impact: StrictFloat = Field(ge=0.0, le=1.0)
    evidence_confidence: StrictFloat = Field(ge=0.0, le=1.0)
    asset_criticality: StrictFloat = Field(ge=0.0, le=1.0)
    coverage_value: StrictFloat = Field(ge=0.0, le=1.0)
    estimated_cost: StrictFloat = Field(ge=0.0)


def compute_priority(
    components: ScoringComponents,
    weights: ScoringWeights | None = None,
) -> float:
    """priority = Π factor^weight / max(cost, epsilon), clamped to [0, 1]."""
    resolved = weights or ScoringWeights()
    raw = (
        (components.exploitability_probability ** resolved.exploitability)
        * (components.expected_impact ** resolved.expected_impact)
        * (components.evidence_confidence ** resolved.evidence_confidence)
        * (components.asset_criticality ** resolved.asset_criticality)
        * (components.coverage_value ** resolved.coverage_value)
        / max(float(components.estimated_cost), float(resolved.epsilon))
    )
    if raw < 0.0:
        return 0.0
    if raw > 1.0:
        return 1.0
    return float(raw)


def tie_break_key(
    *,
    priority_score: float,
    capability_id: str,
    tool_id: str,
    template_id: str = "",
) -> tuple[float, str, str, str]:
    """Sort key: higher score first, then stable ids."""
    return (-float(priority_score), capability_id, tool_id, template_id)


def sort_candidates(items: list[tuple[float, str, str, str]]) -> list[tuple[float, str, str, str]]:
    """Sort (score, capability_id, tool_id, template_id) deterministically."""
    return sorted(
        items,
        key=lambda row: tie_break_key(
            priority_score=row[0],
            capability_id=row[1],
            tool_id=row[2],
            template_id=row[3],
        ),
    )


DEFAULT_SCORING_WEIGHTS = ScoringWeights()

__all__ = [
    "DEFAULT_SCORING_WEIGHTS",
    "ScoringComponents",
    "ScoringWeights",
    "compute_priority",
    "sort_candidates",
    "tie_break_key",
]
