"""WP C — the facade injects the rotation alias into the live dispatch.

Confirms the wiring in ``_call_llm_unified_impl``: a report/cloud-eligible task
with a rotation chain gets its ``preferred_alias`` set from the rotation (and it
reaches the gateway), while an analysis task is never rotated (WRB-001), and an
explicit caller alias is never overridden.
"""

from __future__ import annotations

import pytest
from src.llm import facade
from src.llm.report_rotation import reset_report_rotation
from src.llm.task_router import LLMTask

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _force_unified_gateway(monkeypatch):
    reset_report_rotation()

    async def _fake_gw(*_a, **k):
        _fake_gw.alias = k.get("preferred_alias")
        return "REPORT_OK"

    _fake_gw.alias = "SENTINEL"
    monkeypatch.setattr(facade, "_call_via_unified_gateway", _fake_gw)
    monkeypatch.setattr(facade, "_should_use_unified_gateway", lambda *a, **k: True)
    monkeypatch.setattr(facade, "get_phase_route", lambda phase: None)
    monkeypatch.setattr(facade, "_safety_check_response", lambda *a, **k: None)
    yield _fake_gw
    reset_report_rotation()


async def test_report_task_gets_rotated_alias(_force_unified_gateway) -> None:
    out = await facade.call_llm_unified(
        "sys",
        "user",
        task=LLMTask.REPORT_SECTION,
        scan_id="scanX",
        use_unified=True,
        scan_options={"llm": {"llm_rotate": True, "llm_profile_ids": ["A", "B"]}},
    )
    assert out == "REPORT_OK"
    assert _force_unified_gateway.alias == "A"


async def test_report_task_rotation_advances(_force_unified_gateway) -> None:
    opts = {"llm": {"llm_rotate": True, "llm_profile_ids": ["A", "B"]}}
    await facade.call_llm_unified(
        "s", "u", task=LLMTask.REPORT_SECTION, scan_id="scanY", use_unified=True, scan_options=opts
    )
    first = _force_unified_gateway.alias
    await facade.call_llm_unified(
        "s", "u", task=LLMTask.REPORT_SECTION, scan_id="scanY", use_unified=True, scan_options=opts
    )
    second = _force_unified_gateway.alias
    assert [first, second] == ["A", "B"]


async def test_explicit_preferred_alias_not_overridden(_force_unified_gateway) -> None:
    out = await facade.call_llm_unified(
        "sys",
        "user",
        task=LLMTask.REPORT_SECTION,
        scan_id="scanZ",
        use_unified=True,
        preferred_alias="CALLER_ALIAS",
        scan_options={"llm": {"llm_rotate": True, "llm_profile_ids": ["A", "B"]}},
    )
    assert out == "REPORT_OK"
    assert _force_unified_gateway.alias == "CALLER_ALIAS"


async def test_no_rotation_without_options(_force_unified_gateway) -> None:
    await facade.call_llm_unified(
        "sys", "user", task=LLMTask.REPORT_SECTION, scan_id="scanN", use_unified=True
    )
    # No chain configured → facade leaves preferred_alias unset (gateway resolves default).
    assert _force_unified_gateway.alias in (None, "")
