"""QUICK-003 — deterministic priority formula and tie-break."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.quick.scoring import (
    DEFAULT_SCORING_WEIGHTS,
    ScoringComponents,
    ScoringWeights,
    compute_priority,
    sort_candidates,
    tie_break_key,
)


def _components(**overrides) -> ScoringComponents:
    base = dict(
        exploitability_probability=1.0,
        expected_impact=1.0,
        evidence_confidence=1.0,
        asset_criticality=1.0,
        coverage_value=1.0,
        estimated_cost=1.0,
    )
    base.update(overrides)
    return ScoringComponents(**base)


def test_compute_priority_product_over_cost() -> None:
    assert compute_priority(_components()) == 1.0
    assert compute_priority(_components(estimated_cost=2.0)) == pytest.approx(0.5)
    half = compute_priority(
        _components(
            exploitability_probability=0.5,
            expected_impact=0.5,
            evidence_confidence=0.5,
            asset_criticality=0.5,
            coverage_value=0.5,
            estimated_cost=1.0,
        )
    )
    assert half == pytest.approx(0.5**5)


def test_compute_priority_zero_exploitability_is_zero() -> None:
    assert compute_priority(_components(exploitability_probability=0.0)) == 0.0


def test_compute_priority_clamps_to_unit_interval() -> None:
    huge = compute_priority(_components(estimated_cost=0.0))
    assert huge == 1.0
    assert 0.0 <= compute_priority(_components(estimated_cost=10.0)) <= 1.0


def test_compute_priority_uses_default_weights_when_omitted() -> None:
    components = _components(estimated_cost=4.0)
    assert compute_priority(components) == compute_priority(
        components, DEFAULT_SCORING_WEIGHTS
    )


def test_tie_break_higher_score_first() -> None:
    high = tie_break_key(
        priority_score=0.9,
        capability_id="zzz.late",
        tool_id="nuclei",
        template_id="z-template",
    )
    low = tie_break_key(
        priority_score=0.1,
        capability_id="aaa.early",
        tool_id="nmap",
        template_id="a-template",
    )
    assert high < low


def test_tie_break_equal_score_sorts_by_capability_tool_template() -> None:
    items = [
        (0.5, "web.b", "nuclei", "t2"),
        (0.5, "web.a", "nuclei", "t2"),
        (0.5, "web.a", "nmap", "t1"),
        (0.5, "web.a", "nuclei", "t1"),
        (0.9, "zzz.late", "sqlmap", "x"),
    ]
    ordered = sort_candidates(list(items))
    assert [row[1:] for row in ordered] == [
        ("zzz.late", "sqlmap", "x"),
        ("web.a", "nmap", "t1"),
        ("web.a", "nuclei", "t1"),
        ("web.a", "nuclei", "t2"),
        ("web.b", "nuclei", "t2"),
    ]
    assert ordered == sort_candidates(list(reversed(items)))


def test_sort_candidates_does_not_mutate_input() -> None:
    items = [(0.1, "b", "nuclei", "t2"), (0.2, "a", "nmap", "t1")]
    snapshot = list(items)
    sort_candidates(items)
    assert items == snapshot


def test_scoring_models_reject_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ScoringWeights(unexpected=1.0)  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        ScoringComponents(
            exploitability_probability=0.5,
            expected_impact=0.5,
            evidence_confidence=0.5,
            asset_criticality=0.5,
            coverage_value=0.5,
            estimated_cost=1.0,
            extra=True,  # type: ignore[call-arg]
        )
