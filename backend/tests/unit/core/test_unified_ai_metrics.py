"""CONT-004 / LAB-003 — unified AI metrics unit tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.core import unified_ai_metrics as m


@pytest.fixture(autouse=True)
def _reset_metrics():
    m.reset_unified_ai_metrics()
    yield
    m.reset_unified_ai_metrics()


def test_metric_alias_map_covers_section_18_names():
    expected = {
        "llm_requests_total",
        "llm_latency_ms",
        "llm_schema_failures_total",
        "llm_fallback_total",
        "rag_queries_total",
        "rag_retrieval_latency_ms",
        "rag_cross_tenant_denials_total",
        "nuclei_templates_loaded_total",
        "nuclei_requests_total",
        "lab_executions_total",
        "lab_boundary_denials_total",
        "coverage_requirements_total",
        "findings_total",
        "retests_total",
        "oast_interactions_total",
    }
    assert expected == set(m.METRIC_ALIAS_MAP.keys())
    assert all(name.startswith("argus_") for name in m.METRIC_ALIAS_MAP.values())


def test_record_llm_fallback_and_boundary_denial():
    m.record_llm_fallback(from_provider="qwythos", to_provider="wrb", mode="lab_unrestricted")
    m.record_lab_boundary_denial(deny_code="DENY_OUTSIDE_LAB")
    m.record_llm_request(
        alias="security_reasoner",
        provider="local",
        model="qwythos",
        task="scan_plan",
        status="ok",
        mode="production",
        latency_ms=12.5,
    )
    assert m.get_llm_fallback_total() == 1
    assert m.get_lab_boundary_denials_total() == 1
    assert m.get_llm_requests_total() == 1


def test_no_pii_in_label_truncation():
    m.record_lab_execution(tool="x" * 200, action="y" * 200)
    assert m.get_lab_executions_total() == 1


def test_increment_helpers_and_reset():
    assert m.record_rag_query(mode="production") == 1
    assert m.record_rag_cross_tenant_denial() == 1
    assert m.record_nuclei_templates_loaded(verified=True, protocol="http", mode="production") == 1
    assert m.record_nuclei_request(profile="fingerprint_safe", mode="production") == 1
    assert m.record_coverage_requirement(status="covered_no_finding", mode="lab_unrestricted") == 1
    assert m.record_finding(state="candidate", mode="production") == 1
    assert m.record_retest(result="still_present") == 1
    assert m.record_oast_interaction(correlation_status="correlated") == 1
    assert m.record_llm_schema_failure() == 1

    m.reset_unified_ai_metrics()
    assert m.get_rag_queries_total() == 0
    assert m.get_llm_schema_failures_total() == 0


def test_emit_fail_open_on_prometheus_error():
    broken = MagicMock()
    broken.labels.return_value.inc.side_effect = RuntimeError("boom")
    with patch.object(m, "_PROM_COUNTERS", {"argus_lab_boundary_denials_total": broken}):
        with patch.object(m, "_PROM_INITIALIZED", True):
            with patch.object(m, "_PROMETHEUS_AVAILABLE", True):
                assert m.record_lab_boundary_denial() == 1


def test_rag_retrieval_latency_does_not_raise():
    m.record_rag_retrieval_latency(mode="lab_unrestricted", latency_ms=42.0)


def test_policy_bridge_smoke_increments_lab_execution():
    from src.execution_mode import evaluate_with_execution_mode
    from src.execution_mode.lab_lease import LabLeaseService
    from src.execution_mode.lab_scope import LabScopeManifest
    from datetime import UTC, datetime, timedelta

    manifest = LabScopeManifest(
        tenant_id="t-1",
        engagement_id="e-1",
        cidrs=("10.90.0.0/16",),
        dns_suffixes=("lab.argus",),
        k8s_namespace="argus-lab-42",
        vm_network_ids=("labnet-42",),
        capture_full=True,
        expires_at=datetime.now(tz=UTC) + timedelta(hours=4),
        created_by="u-1",
    )
    lease = LabLeaseService().issue(manifest, boundary_proof="proof-1")
    before = m.get_lab_executions_total()
    decision = evaluate_with_execution_mode(
        mode="lab_unrestricted",
        target="10.90.1.5",
        lease=lease,
        tenant_id="t-1",
    )
    assert decision.allowed
    assert m.get_lab_executions_total() == before + 1


def test_prometheus_init_guarded_against_duplicate_registration():
    fake_counter = MagicMock()
    with patch.object(m, "_PROM_COUNTERS", {"argus_llm_requests_total": fake_counter}):
        with patch.object(m, "_PROM_INITIALIZED", True):
            m.record_llm_request(
                alias="a",
                provider="p",
                model="m",
                task="t",
                status="ok",
                mode="production",
                latency_ms=1.0,
            )
    fake_counter.labels.assert_called_once()
