"""WIRE-001 — all 8 phases stamp execution_mode_context; LAB has no hidden gates."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from src.execution_mode import LabBoundaryVerifier, LabLeaseService, LabScopeManifest
from src.orchestration.execution_mode_context import (
    resolve_tool_policy_from_options,
    tool_policy_to_lab,
)
from src.orchestration.handlers import (
    _attach_phase_execution_mode,
    _lab_tool_dispatch_allowed,
    _stamped_lab_lease_active,
    run_reporting,
    run_threat_modeling,
)
from src.orchestration.phases import PHASE_ORDER, ReportingOutput, ThreatModelOutput
from src.pipeline.contracts.phase_io import ScanPhase as PolicyScanPhase
from src.pipeline.contracts.tool_job import RiskLevel
from src.policy.policy_engine import (
    PlanTier,
    PolicyContext,
    PolicyEngine,
    RateLimit,
    TenantPolicy,
)


def _manifest(**overrides):
    base = {
        "tenant_id": "t-1",
        "engagement_id": "e-1",
        "cidrs": ("10.90.0.0/16",),
        "dns_suffixes": ("lab.argus",),
        "k8s_namespace": "argus-lab-42",
        "vm_network_ids": ("labnet-42",),
        "capture_full": True,
        "expires_at": datetime.now(tz=UTC) + timedelta(hours=4),
        "created_by": "u-1",
    }
    base.update(overrides)
    return LabScopeManifest(**base)


def _usable_lease(manifest: LabScopeManifest | None = None):
    m = manifest or _manifest()
    verdict = LabBoundaryVerifier().verify(
        "10.90.2.2",
        m,
        tenant_id="t-1",
        engagement_id="e-1",
        k8s_namespace="argus-lab-42",
        vm_network_id="labnet-42",
    )
    assert verdict.allowed
    return LabLeaseService().issue(m, boundary_proof=verdict.proof)


def _lab_options_with_lease(lease) -> dict:
    return {
        "execution_mode": "lab_unrestricted",
        "tenant_id": "t-1",
        "engagement_id": "e-1",
        "lab_scope": _manifest().to_storage_dict(),
        "lab_lease": lease.to_storage_dict(),
        "k8s_namespace": "argus-lab-42",
        "vm_network_id": "labnet-42",
    }


_PHASE_NAMES = [phase.value for phase in PHASE_ORDER]
_GATE_SCENARIOS = ("production", "lab_lease", "missing_lease")
_MUTATING_TOOL = "sqlmap"


def _options_for_scenario(scenario: str) -> dict:
    if scenario == "production":
        return {"execution_mode": "production"}
    if scenario == "lab_lease":
        return _lab_options_with_lease(_usable_lease())
    return {
        "execution_mode": "lab_unrestricted",
        "tenant_id": "t-1",
        "engagement_id": "e-1",
    }


def _target_for_scenario(scenario: str) -> str:
    if scenario == "production":
        return "https://prod.example/"
    return "https://app.lab.argus/"


@pytest.mark.parametrize("phase_name", _PHASE_NAMES)
def test_attach_stamps_execution_mode_for_all_eight_phases(phase_name: str):
    """Every pipeline phase conceptually stamps via the shared attach helper."""
    prod = _attach_phase_execution_mode(
        {"execution_mode": "production"},
        tenant_id="t-1",
        scan_id=f"s-{phase_name}-prod",
    )
    ctx = prod["execution_mode_context"]
    assert ctx["mode"] == "production"
    assert ctx["lab_lease_active"] is False
    assert _stamped_lab_lease_active(prod) is False

    lease = _usable_lease()
    lab = _attach_phase_execution_mode(
        _lab_options_with_lease(lease),
        tenant_id="t-1",
        scan_id=f"s-{phase_name}-lab",
        engagement_id="e-1",
    )
    lab_ctx = lab["execution_mode_context"]
    assert lab_ctx["mode"] == "lab_unrestricted"
    assert lab_ctx["lab_lease_active"] is True
    assert _stamped_lab_lease_active(lab) is True

    missing = _attach_phase_execution_mode(
        {
            "execution_mode": "lab_unrestricted",
            "tenant_id": "t-1",
            "engagement_id": "e-1",
        },
        tenant_id="t-1",
        scan_id=f"s-{phase_name}-deny",
        engagement_id="e-1",
    )
    miss_ctx = missing["execution_mode_context"]
    assert miss_ctx["lab_lease_active"] is False
    assert miss_ctx["deny_code"] == "DENY_OUTSIDE_LAB"
    assert _stamped_lab_lease_active(missing) is False


@pytest.mark.parametrize("tool_name", ["sqlmap", "commix"])
@pytest.mark.parametrize(
    "scenario",
    ["production", "lab_lease", "missing_lease"],
)
def test_destructive_tool_policy_production_lab_missing_lease(
    tool_name: str, scenario: str
):
    """Production keeps approval; LAB+lease allow-all; missing lease deny."""
    if scenario == "production":
        decision = resolve_tool_policy_from_options(
            tool_name,
            {"execution_mode": "production"},
            target="https://prod.example/",
        )
        assert decision.allowed is False
        assert decision.requires_approval is True
        assert decision.lab_lease_active is False
        assert (
            _lab_tool_dispatch_allowed(
                tool_name,
                {"execution_mode": "production"},
                target="https://prod.example/",
                tenant_id="t-1",
            )
            is True
        )
        return

    if scenario == "lab_lease":
        lease = _usable_lease()
        options = _lab_options_with_lease(lease)
        decision = resolve_tool_policy_from_options(
            tool_name,
            options,
            target="https://app.lab.argus/",
            tenant_id="t-1",
            engagement_id="e-1",
        )
        assert decision.allowed is True
        assert decision.requires_approval is False
        assert decision.lab_lease_active is True
        assert (
            _lab_tool_dispatch_allowed(
                tool_name,
                options,
                target="https://app.lab.argus/",
                tenant_id="t-1",
            )
            is True
        )
        return

    options = {
        "execution_mode": "lab_unrestricted",
        "tenant_id": "t-1",
        "engagement_id": "e-1",
    }
    decision = resolve_tool_policy_from_options(
        tool_name,
        options,
        target="https://app.lab.argus/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert decision.allowed is False
    assert decision.lab_lease_active is False
    assert decision.deny_code == "DENY_OUTSIDE_LAB"
    assert (
        _lab_tool_dispatch_allowed(
            tool_name,
            options,
            target="https://app.lab.argus/",
            tenant_id="t-1",
        )
        is False
    )


def test_run_threat_modeling_and_reporting_accept_scan_options():
    tm_params = inspect.signature(run_threat_modeling).parameters
    assert "scan_options" in tm_params
    assert tm_params["scan_options"].default is None
    assert "tenant_id" in tm_params

    rp_params = inspect.signature(run_reporting).parameters
    assert "scan_options" in rp_params
    assert rp_params["scan_options"].default is None
    assert "tenant_id" in rp_params


@pytest.mark.asyncio
async def test_run_threat_modeling_stamps_execution_mode_context():
    options = {"execution_mode": "production", "tenant_id": "t-1"}
    with (
        patch("src.orchestration.handlers.NVDClient") as mock_nvd,
        patch(
            "src.orchestration.handlers.ai_threat_modeling",
            new_callable=AsyncMock,
        ) as mock_ai,
    ):
        mock_nvd.return_value.query = AsyncMock(return_value={"vulnerabilities": []})
        mock_ai.return_value = ThreatModelOutput(threat_model={"threats": []})
        await run_threat_modeling(
            ["22/tcp ssh"],
            scan_id="s-tm-1",
            tenant_id="t-1",
            scan_options=options,
        )
    assert "execution_mode_context" in options
    assert options["execution_mode_context"]["mode"] == "production"
    mock_ai.assert_called_once()
    assert mock_ai.await_args.kwargs.get("scan_options") is options


@pytest.mark.asyncio
async def test_run_reporting_stamps_execution_mode_context():
    lease = _usable_lease()
    options = _lab_options_with_lease(lease)
    with patch(
        "src.orchestration.handlers.ai_reporting",
        new_callable=AsyncMock,
    ) as mock_ai:
        mock_ai.return_value = ReportingOutput(report={"summary": {}})
        await run_reporting(
            "https://app.lab.argus/",
            None,
            None,
            None,
            None,
            None,
            scan_id="s-rep-1",
            tenant_id="t-1",
            scan_options=options,
        )
    assert options["execution_mode_context"]["lab_lease_active"] is True
    assert options["execution_mode_context"]["mode"] == "lab_unrestricted"
    mock_ai.assert_called_once()
    assert mock_ai.await_args.kwargs.get("scan_options") is options


def test_pipeline_has_eight_named_phases():
    assert len(_PHASE_NAMES) == 8
    assert _PHASE_NAMES == [
        "source_analysis",
        "recon",
        "quick_fuzz",
        "threat_modeling",
        "vuln_analysis",
        "exploitation",
        "post_exploitation",
        "reporting",
    ]


@pytest.mark.parametrize("phase_name", _PHASE_NAMES)
@pytest.mark.parametrize("scenario", _GATE_SCENARIOS)
def test_phase_mutating_tool_gate_matrix(phase_name: str, scenario: str):
    """8 phases × production keeps gate / LAB+lease allow-all / missing lease deny."""
    options = _attach_phase_execution_mode(
        _options_for_scenario(scenario),
        tenant_id="t-1",
        scan_id=f"s-{phase_name}-{scenario}",
        engagement_id="e-1",
    )
    ctx = options["execution_mode_context"]
    target = _target_for_scenario(scenario)
    decision = resolve_tool_policy_from_options(
        _MUTATING_TOOL,
        options,
        target=target,
        tenant_id="t-1",
        engagement_id="e-1",
    )
    dispatch_ok = _lab_tool_dispatch_allowed(
        _MUTATING_TOOL,
        options,
        target=target,
        tenant_id="t-1",
    )

    if scenario == "production":
        assert ctx["mode"] == "production"
        assert ctx["lab_lease_active"] is False
        assert decision.allowed is False
        assert decision.requires_approval is True
        assert decision.lab_lease_active is False
        assert dispatch_ok is True
        return

    if scenario == "lab_lease":
        assert ctx["mode"] == "lab_unrestricted"
        assert ctx["lab_lease_active"] is True
        assert decision.allowed is True
        assert decision.requires_approval is False
        assert decision.lab_lease_active is True
        assert dispatch_ok is True
        return

    assert ctx["lab_lease_active"] is False
    assert ctx["deny_code"] == "DENY_OUTSIDE_LAB"
    assert decision.allowed is False
    assert decision.lab_lease_active is False
    assert decision.deny_code == "DENY_OUTSIDE_LAB"
    assert dispatch_ok is False


def test_lab_lease_no_argus_rate_or_payload_family_cap():
    """LAB + valid lease: mutating tool has no ARGUS rate / payload-family cap."""
    lease = _usable_lease()
    options = _attach_phase_execution_mode(
        _lab_options_with_lease(lease),
        tenant_id="t-1",
        scan_id="s-nocap",
        engagement_id="e-1",
    )
    assert options["execution_mode_context"]["lab_lease_active"] is True

    decision = resolve_tool_policy_from_options(
        _MUTATING_TOOL,
        options,
        target="https://app.lab.argus/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert decision.allowed is True
    assert decision.requires_approval is False
    lab = tool_policy_to_lab(decision)
    assert lab.allowed_payloads == "*"
    assert lab.allowed_tools == "*"
    assert lab.allowed_actions == "*"
    assert lab.allowed_protocols == "*"
    assert lab.budget == "unlimited"
    assert lab.requires_approval is False
    assert lease.policy.allowed_payloads == "*"
    assert lease.policy.budget == "unlimited"

    tenant_uuid = uuid4()
    engine = PolicyEngine(
        TenantPolicy(
            tenant_id=tenant_uuid,
            plan_tier=PlanTier.FREE,
            banned_tools=frozenset({_MUTATING_TOOL}),
            banned_families=frozenset({"demo_sqli"}),
            rate_limits={
                _MUTATING_TOOL: RateLimit(window_seconds=60, max_per_window=1),
            },
        )
    )
    pe = engine.evaluate(
        PolicyContext(
            tenant_id=tenant_uuid,
            phase=PolicyScanPhase.EXPLOITATION,
            risk_level=RiskLevel.DESTRUCTIVE,
            tool_id=_MUTATING_TOOL,
            family_id="demo_sqli",
            target="https://app.lab.argus/",
            has_ownership_proof=False,
            recent_invocations=999,
            lab_lease_active=bool(options["execution_mode_context"]["lab_lease_active"]),
        )
    )
    assert pe.allowed is True
    assert pe.requires_approval is False
    assert pe.failure_summary is None


def test_lab_outside_boundary_denies_before_dispatch():
    """LAB with manifest but target outside scope: deny before tool dispatch."""
    options = _attach_phase_execution_mode(
        {
            "execution_mode": "lab_unrestricted",
            "tenant_id": "t-1",
            "engagement_id": "e-1",
            "lab_scope": _manifest().to_storage_dict(),
            "k8s_namespace": "argus-lab-42",
            "vm_network_id": "labnet-42",
        },
        tenant_id="t-1",
        scan_id="s-oob",
        engagement_id="e-1",
    )
    assert options["execution_mode_context"]["lab_lease_active"] is False
    assert (
        _lab_tool_dispatch_allowed(
            _MUTATING_TOOL,
            options,
            target="https://evil.example/",
            tenant_id="t-1",
        )
        is False
    )
    decision = resolve_tool_policy_from_options(
        _MUTATING_TOOL,
        options,
        target="https://evil.example/",
        tenant_id="t-1",
        engagement_id="e-1",
    )
    assert decision.allowed is False
    assert decision.lab_lease_active is False
    assert decision.deny_code == "DENY_OUTSIDE_LAB"
