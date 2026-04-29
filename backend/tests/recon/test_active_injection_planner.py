"""Golden / deterministic tests for P2-003 injection planner."""

from __future__ import annotations

from src.recon.vulnerability_analysis.active_scan.injection_planner import (
    ActiveInjectionPlannerFlags,
    build_injection_plan,
    build_injection_plan_from_settings,
    injection_plan_deterministic_fingerprint,
)
from src.recon.vulnerability_analysis.active_scan.input_surface_inventory import (
    InputSurfaceInventory,
    InputSurfaceItem,
)


def _fixture_inventory() -> InputSurfaceInventory:
    return InputSurfaceInventory(
        items=[
            InputSurfaceItem(
                surface_id="s1",
                url="https://beta.example/api?q=2",
                method="get",
                param_name="q",
                location="query",
                source="test",
                evidence_ref="e1",
            ),
            InputSurfaceItem(
                surface_id="s2",
                url="https://alpha.example/login",
                method="POST",
                param_name="user",
                location="form",
                source="test",
                evidence_ref="e2",
            ),
        ]
    )


def test_build_injection_plan_sort_order() -> None:
    inv = _fixture_inventory()
    flags = ActiveInjectionPlannerFlags(
        lab_destructive_execution_allowed=False,
        oast_enabled=False,
        destructive_tool_ids=frozenset({"sqlmap", "commix"}),
    )
    steps = build_injection_plan(inv, mode="standard", flags=flags)
    keys = [(s.family, s.target_url, s.method, s.param, s.tool) for s in steps]
    assert keys == sorted(keys, key=lambda t: (t[0].lower(), t[1].lower(), t[2].upper(), t[3].lower(), t[4].lower()))


def test_build_injection_plan_golden_fingerprint() -> None:
    inv = _fixture_inventory()
    flags = ActiveInjectionPlannerFlags(
        lab_destructive_execution_allowed=False,
        oast_enabled=False,
        destructive_tool_ids=frozenset({"sqlmap", "commix"}),
    )
    steps = build_injection_plan(inv, mode="standard", flags=flags)
    fp = injection_plan_deterministic_fingerprint(steps)
    assert fp == (
        "2e8dde13159e803e5776d9911e952cbb26185a820ac011608d3ee026b7c773b6"
    )


def test_oast_disabled_emits_rows() -> None:
    inv = _fixture_inventory()
    flags = ActiveInjectionPlannerFlags(
        lab_destructive_execution_allowed=False,
        oast_enabled=False,
        destructive_tool_ids=frozenset({"sqlmap"}),
    )
    steps = build_injection_plan(inv, mode="deep", flags=flags)
    oast = [s for s in steps if s.family == "oast_ssrf"]
    assert oast
    assert all(s.not_assessed_reason == "oast_disabled" for s in oast)


def test_lab_family_blocked_without_lab_chain() -> None:
    inv = _fixture_inventory()
    flags = ActiveInjectionPlannerFlags(
        lab_destructive_execution_allowed=False,
        oast_enabled=True,
        destructive_tool_ids=frozenset({"sqlmap", "commix"}),
    )
    steps = build_injection_plan(inv, mode="lab", flags=flags)
    blocked = [s for s in steps if s.family == "rce_commix"]
    assert blocked
    assert all(s.not_assessed_reason == "lab_execution_not_authorized" for s in blocked)
    assert all(s.approval_status == "blocked" for s in blocked)


def test_build_injection_plan_from_settings_smoke(monkeypatch: object) -> None:
    from src.core import config as core_config

    monkeypatch.setattr(core_config.settings, "argus_active_injection_mode", "quick", raising=False)
    monkeypatch.setattr(core_config.settings, "argus_oast_enabled", False, raising=False)
    steps = build_injection_plan_from_settings(_fixture_inventory())
    assert steps
    assert all(s.family in {"xss", "sqli", "headers"} for s in steps if not s.not_assessed_reason)
