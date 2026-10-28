"""The three DWM gates — all required; each failure yields the right status."""

from __future__ import annotations

from src.intel.dark_web.contracts import DarkWebReportStatus
from src.intel.dark_web.gates import evaluate_dark_web_gate, resolve_entitlement

_ENABLED = {"dark_web": {"enabled": True}}


def test_all_three_gates_pass() -> None:
    d = evaluate_dark_web_gate(_ENABLED, settings_enabled=True, tenant_entitled=True)
    assert d.allowed is True
    assert d.status == DarkWebReportStatus.NOT_COLLECTED


def test_global_off_disables() -> None:
    d = evaluate_dark_web_gate(_ENABLED, settings_enabled=False, tenant_entitled=True)
    assert d.allowed is False
    assert d.status == DarkWebReportStatus.DISABLED


def test_not_opted_in_disables() -> None:
    d = evaluate_dark_web_gate({"dark_web": {"enabled": False}}, settings_enabled=True, tenant_entitled=True)
    assert d.allowed is False
    assert d.status == DarkWebReportStatus.DISABLED


def test_not_entitled() -> None:
    d = evaluate_dark_web_gate(_ENABLED, settings_enabled=True, tenant_entitled=False)
    assert d.allowed is False
    assert d.status == DarkWebReportStatus.NOT_ENTITLED


def test_entitlement_fails_closed_when_unknown() -> None:
    # No server-side entitlement resolved -> DENY (never fall open).
    assert resolve_entitlement() is False
    assert resolve_entitlement(tenant_entitled=None) is False


def test_entitlement_respects_resolved_value() -> None:
    assert resolve_entitlement(tenant_entitled=True) is True
    assert resolve_entitlement(tenant_entitled=False) is False


def test_gate_not_entitled_when_entitlement_unknown() -> None:
    # global + opt-in pass, but entitlement unknown -> NOT_ENTITLED (fail closed).
    d = evaluate_dark_web_gate(_ENABLED, settings_enabled=True, tenant_entitled=None)
    assert d.allowed is False
    assert d.status == DarkWebReportStatus.NOT_ENTITLED


def test_prefilter_allows_without_entitlement() -> None:
    from src.intel.dark_web.gates import pipeline_prefilter_allows

    allowed, status, flags = pipeline_prefilter_allows(_ENABLED, settings_enabled=True)
    assert allowed is True
    assert status == DarkWebReportStatus.NOT_COLLECTED
    assert flags["enabled"] is True


def test_gate_carries_flags() -> None:
    d = evaluate_dark_web_gate(
        {"dark_web": {"enabled": True, "include_findings": False}},
        settings_enabled=True,
        tenant_entitled=True,
    )
    assert d.flags["enabled"] is True
    assert d.flags["include_findings"] is False
