"""CONT-006 — acceptance gate metrics (DoD §19.6 eval harness)."""

from __future__ import annotations

import pytest

from tests.evals.harness import (
    CATEGORY_MINIMUMS,
    EVAL_CATEGORIES,
    check_cross_tenant_fixture,
    check_evidence_triage_fixture,
    check_finding_diff_fixture,
    check_lab_plan_fixture,
    check_lab_plan_policy_bridge,
    check_production_plan_fixture,
    check_prompt_injection_fixture,
    check_template_author_fixture,
    compute_cross_tenant_leak_rate,
    compute_finding_diff_accuracy,
    compute_lab_unwanted_restriction_rate,
    compute_policy_violation_rate_production,
    compute_schema_valid_rate,
    count_category_fixtures,
    load_json_fixtures,
    validate_category_fixtures,
)


@pytest.fixture
def lab_plans() -> list[dict]:
    fixtures = load_json_fixtures("lab_unrestricted_plans")
    assert len(fixtures) == CATEGORY_MINIMUMS["lab_unrestricted_plans"]
    return fixtures


@pytest.fixture
def cross_tenant_fixtures() -> list[dict]:
    fixtures = load_json_fixtures("cross_tenant_retrieval")
    assert len(fixtures) >= CATEGORY_MINIMUMS["cross_tenant_retrieval"]
    return fixtures


@pytest.fixture
def production_plans() -> list[dict]:
    fixtures = load_json_fixtures("production_plans")
    assert len(fixtures) == CATEGORY_MINIMUMS["production_plans"]
    return fixtures


@pytest.fixture
def prompt_injection_fixtures() -> list[dict]:
    fixtures = load_json_fixtures("prompt_injection")
    assert len(fixtures) == CATEGORY_MINIMUMS["prompt_injection"]
    return fixtures


@pytest.fixture
def finding_diff_fixtures() -> list[dict]:
    fixtures = load_json_fixtures("finding_diff")
    assert len(fixtures) == CATEGORY_MINIMUMS["finding_diff"]
    return fixtures


@pytest.fixture
def template_author_fixtures() -> list[dict]:
    fixtures = load_json_fixtures("template_author")
    assert len(fixtures) == CATEGORY_MINIMUMS["template_author"]
    return fixtures


@pytest.fixture
def evidence_triage_fixtures() -> list[dict]:
    fixtures = load_json_fixtures("evidence_triage")
    assert len(fixtures) == CATEGORY_MINIMUMS["evidence_triage"]
    return fixtures


@pytest.mark.parametrize("category", EVAL_CATEGORIES)
def test_category_meets_section_19_6_minimum(category: str) -> None:
    """Every §19.6 category meets the required fixture count on disk."""
    count = count_category_fixtures(category)
    minimum = CATEGORY_MINIMUMS[category]
    assert count == minimum, f"{category}: expected {minimum}, found {count}"


@pytest.mark.parametrize("category", EVAL_CATEGORIES)
def test_all_fixtures_schema_valid(category: str) -> None:
    """schema_valid_rate gate — every fixture has required fields and valid enums."""
    violations = validate_category_fixtures(category)
    assert not violations, violations


def test_schema_valid_rate_is_perfect() -> None:
    rate = compute_schema_valid_rate()
    assert rate == 1.0, f"schema_valid_rate={rate}"


def test_cross_tenant_leak_rate_is_zero(cross_tenant_fixtures: list[dict]) -> None:
    rate = compute_cross_tenant_leak_rate(cross_tenant_fixtures)
    assert rate == 0.0, f"cross_tenant_leak_rate={rate}"
    for fixture in cross_tenant_fixtures:
        violations = check_cross_tenant_fixture(fixture)
        assert not violations, violations


def test_lab_unwanted_restriction_rate_is_zero(lab_plans: list[dict]) -> None:
    rate = compute_lab_unwanted_restriction_rate(lab_plans)
    assert rate == 0.0, f"lab_unwanted_restriction_rate={rate}"
    for fixture in lab_plans:
        violations = check_lab_plan_fixture(fixture)
        assert not violations, violations


def test_lab_plans_use_policy_bridge_without_gates(lab_plans: list[dict]) -> None:
    """§19.6 — LAB plans call resolve_tool_policy / evaluate_with_execution_mode directly."""
    for fixture in lab_plans:
        violations = check_lab_plan_policy_bridge(fixture)
        assert not violations, violations


def test_policy_violation_rate_production_is_zero(production_plans: list[dict]) -> None:
    rate = compute_policy_violation_rate_production(production_plans)
    assert rate == 0.0, f"policy_violation_rate_production={rate}"
    for fixture in production_plans:
        violations = check_production_plan_fixture(fixture)
        assert not violations, violations


def test_finding_diff_accuracy_is_perfect(finding_diff_fixtures: list[dict]) -> None:
    accuracy = compute_finding_diff_accuracy(finding_diff_fixtures)
    assert accuracy == 1.0, f"finding_diff_accuracy={accuracy}"
    for fixture in finding_diff_fixtures:
        violations = check_finding_diff_fixture(fixture)
        assert not violations, violations


def test_template_author_fixtures_are_valid(template_author_fixtures: list[dict]) -> None:
    for fixture in template_author_fixtures:
        violations = check_template_author_fixture(fixture)
        assert not violations, violations


def test_evidence_triage_fixtures_are_valid(evidence_triage_fixtures: list[dict]) -> None:
    for fixture in evidence_triage_fixtures:
        violations = check_evidence_triage_fixture(fixture)
        assert not violations, violations


def test_prompt_injection_fixtures_are_valid(prompt_injection_fixtures: list[dict]) -> None:
    for fixture in prompt_injection_fixtures:
        violations = check_prompt_injection_fixture(fixture)
        assert not violations, violations
