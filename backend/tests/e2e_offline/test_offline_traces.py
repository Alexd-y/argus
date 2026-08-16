"""Offline E2E §22 traces."""

from __future__ import annotations

from tests.e2e_offline.trace_simulator import TraceSimulator


def test_production_trace_order():
    stages = TraceSimulator().run_production()
    assert stages[0] == "phase_input"
    assert "policy_content_classification" in stages
    assert "tenant_filtered_rag" in stages
    assert "typed_analysis" in stages
    assert "deterministic_candidate_set" in stages
    # Policy/approval before sandbox
    idx_policy = stages.index("production_policy_approval")
    idx_sandbox = stages.index("sandbox_execution_stub")
    assert idx_policy < idx_sandbox


def test_lab_unrestricted_trace_order():
    sim = TraceSimulator()
    stages = sim.run_lab_unrestricted()
    assert stages[0] == "lab_scope_manifest"
    assert "boundary_verification" in stages
    assert "unrestricted_lease" in stages
    lease_ev = next(e for e in sim.events if e.stage == "unrestricted_lease")
    assert lease_ev.detail["requires_approval"] is False
    arb = next(e for e in sim.events if e.stage == "arbitrary_tool_selection")
    assert arb.detail["approval_steps"] == 0
    assert arb.detail["rate_caps"] is None
    idx_lease = stages.index("unrestricted_lease")
    idx_exec = stages.index("sandbox_lab_exec_stub")
    assert idx_lease < idx_exec
