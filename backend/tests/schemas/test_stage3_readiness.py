"""Tests for Stage 3 readiness schemas."""

import pytest
from app.schemas.recon.stage3_readiness import (
    ROUTE_CLASSIFICATION_CSV_COLUMNS,
    CoverageScores,
    RouteClassificationRow,
    Stage3ReadinessResult,
)
from pydantic import ValidationError


def test_stage3_readiness_result_validates() -> None:
    result = Stage3ReadinessResult(
        status="ready_for_stage3",
        missing_evidence=[],
        unknowns=[],
        recommended_follow_up=["Verify API auth boundaries"],
        coverage_scores={
            "route": 0.9,
            "input_surface": 0.8,
            "api_surface": 0.85,
            "content_anomaly": 0.7,
            "boundary_mapping": 0.75,
        },
    )
    assert result.status == "ready_for_stage3"
    assert result.coverage_scores.route == 0.9
    assert "Verify API auth boundaries" in result.recommended_follow_up


def test_stage3_readiness_result_rejects_invalid_status() -> None:
    with pytest.raises(ValidationError):
        Stage3ReadinessResult(
            status="invalid_status",
            coverage_scores=CoverageScores(),
        )


def test_stage3_readiness_result_valid_statuses() -> None:
    for status in ("ready_for_stage3", "partially_ready_for_stage3", "not_ready_for_stage3"):
        result = Stage3ReadinessResult(status=status, coverage_scores=CoverageScores())
        assert result.status == status


def test_coverage_scores_validates_bounds() -> None:
    with pytest.raises(ValidationError):
        CoverageScores(route=1.5, input_surface=0.0, api_surface=0.0, content_anomaly=0.0, boundary_mapping=0.0)

    with pytest.raises(ValidationError):
        CoverageScores(route=-0.1, input_surface=0.0, api_surface=0.0, content_anomaly=0.0, boundary_mapping=0.0)


def test_coverage_scores_defaults() -> None:
    scores = CoverageScores()
    assert scores.route == 0.0
    assert scores.input_surface == 0.0
    assert scores.api_surface == 0.0
    assert scores.content_anomaly == 0.0
    assert scores.boundary_mapping == 0.0


def test_route_classification_csv_columns() -> None:
    assert ROUTE_CLASSIFICATION_CSV_COLUMNS == (
        "route",
        "host",
        "classification",
        "discovery_source",
        "evidence_ref",
    )


def test_route_classification_row_validates() -> None:
    row = RouteClassificationRow(
        route="/login",
        host="example.com",
        classification="auth_related",
        discovery_source="crawl",
        evidence_ref="route_inventory.csv:1",
    )
    assert row.route == "/login"
    assert row.host == "example.com"


def test_route_classification_row_rejects_empty_fields() -> None:
    with pytest.raises(ValidationError):
        RouteClassificationRow(
            route="",
            host="example.com",
            classification="auth_related",
            discovery_source="crawl",
            evidence_ref="route_inventory.csv:1",
        )


def test_route_classification_row_accepts_empty_evidence_ref() -> None:
    row = RouteClassificationRow(
        route="/login",
        host="example.com",
        classification="auth_related",
        discovery_source="crawl",
        evidence_ref="",
    )
    assert row.evidence_ref is None


def test_route_classification_row_accepts_none_evidence_ref() -> None:
    row = RouteClassificationRow(
        route="/login",
        host="example.com",
        classification="auth_related",
        discovery_source="crawl",
    )
    assert row.evidence_ref is None
