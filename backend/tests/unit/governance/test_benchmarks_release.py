"""Tests for Benchmark Runner and Release Governance."""

import pytest
from src.governance.benchmarks.runner import (
    BenchmarkResult, CWEMetrics,
    run_synthetic_benchmark, BENCHMARK_PROFILES,
)
from src.governance.release.gates import (
    EvalDelta, ReleaseGate, SystemCard,
    compute_eval_delta, check_release_gates, generate_system_card,
)


class TestBenchmarkProfiles:
    def test_quick_profile_exists(self):
        assert "quick" in BENCHMARK_PROFILES
        assert len(BENCHMARK_PROFILES["quick"]["datasets"]) == 1

    def test_standard_profile_exists(self):
        assert "standard" in BENCHMARK_PROFILES
        assert len(BENCHMARK_PROFILES["standard"]["datasets"]) == 2

    def test_full_profile_exists(self):
        assert "full" in BENCHMARK_PROFILES
        assert len(BENCHMARK_PROFILES["full"]["datasets"]) == 4


class TestSyntheticBenchmark:
    def test_returns_valid_result(self):
        result = run_synthetic_benchmark("test-model")
        assert result.model == "test-model"
        assert result.overall_precision > 0.8
        assert result.overall_f1 > 0.8
        assert result.false_positive_rate < 0.3

    def test_by_cwe_has_metrics(self):
        result = run_synthetic_benchmark("test-model")
        assert len(result.by_cwe) == 5
        for cwe in result.by_cwe:
            assert cwe.cwe_id.startswith("CWE-")
            assert 0.0 <= cwe.f1 <= 1.0


class TestEvalDelta:
    def test_compute_delta_improvement(self):
        before = {"model": "old", "overall_precision": 0.85, "overall_recall": 0.80, "overall_f1": 0.82, "false_positive_rate": 0.20, "validated_finding_rate": 0.70}
        after = {"model": "new", "overall_precision": 0.92, "overall_recall": 0.88, "overall_f1": 0.90, "false_positive_rate": 0.15, "validated_finding_rate": 0.78}
        delta = compute_eval_delta(before, after)
        assert delta.precision_delta > 0
        assert delta.false_positive_rate_delta < 0  # FP улучшился
        assert delta.verdict == "pass"

    def test_compute_delta_regression(self):
        before = {"model": "old", "overall_precision": 0.92, "overall_recall": 0.88, "overall_f1": 0.90, "false_positive_rate": 0.10, "validated_finding_rate": 0.78}
        after = {"model": "new", "overall_precision": 0.80, "overall_recall": 0.75, "overall_f1": 0.77, "false_positive_rate": 0.25, "validated_finding_rate": 0.60}
        delta = compute_eval_delta(before, after)
        assert delta.f1_delta < -0.02
        assert delta.verdict == "block"


class TestReleaseGates:
    def test_all_gates_pass(self):
        result = {"overall_precision": 0.92, "overall_recall": 0.88, "overall_f1": 0.90, "false_positive_rate": 0.05}
        gates = check_release_gates(result, safety_alerts=2, hallucination_rate=0.01)
        assert all(g.passed for g in gates)

    def test_precision_below_threshold_fails(self):
        result = {"overall_precision": 0.80}  # below 0.85
        gates = check_release_gates(result)
        prec_gate = [g for g in gates if g.name == "precision_threshold"][0]
        assert prec_gate.passed is False

    def test_fp_above_cap_fails(self):
        result = {"overall_precision": 0.90, "false_positive_rate": 0.15}
        gates = check_release_gates(result)
        fp_gate = [g for g in gates if g.name == "false_positive_cap"][0]
        assert fp_gate.passed is False

    def test_safety_alerts_above_cap_fails(self):
        result = {"overall_precision": 0.90, "overall_recall": 0.85, "false_positive_rate": 0.05}
        gates = check_release_gates(result, safety_alerts=10)
        safety_gate = [g for g in gates if g.name == "safety_incidents_cap"][0]
        assert safety_gate.passed is False

    def test_hallucination_above_cap_fails(self):
        result = {"overall_precision": 0.90, "overall_recall": 0.85, "false_positive_rate": 0.05}
        gates = check_release_gates(result, hallucination_rate=0.05)
        hall_gate = [g for g in gates if g.name == "hallucination_cap"][0]
        assert hall_gate.passed is False


class TestSystemCard:
    def test_generates_complete_card(self):
        card = generate_system_card(
            model="TestModel-7B", version="2.0.0",
            benchmark_result={"overall_f1": 0.91},
        )
        assert card.model == "TestModel-7B"
        assert card.version == "2.0.0"
        assert len(card.capabilities) >= 3
        assert len(card.limitations) >= 2
        assert len(card.mitigations) >= 3
        assert card.benchmarks.get("overall_f1") == 0.91
        assert card.safety_metrics["default_logging"] == "hashed_prompts_summary_responses"
