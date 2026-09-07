"""Regression: run_quick_fuzz must not pass a list into QuickFuzzOutput.tech_stack.

Block 1.1 added ReconOutput.technologies (a list). run_quick_fuzz previously
fell back to recon_output["technologies"] for the dict-typed tech_stack, which
made QuickFuzzOutput validation fail with dict_type on a live scan. tech_stack
must stay a dict regardless of the technologies list.
"""

from __future__ import annotations

import pytest
from src.orchestration import handlers
from src.orchestration.phases import QuickFuzzOutput


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(handlers, "_attach_phase_execution_mode", lambda opts, **_: opts or {})

    async def _fake_qf(*_args, **_kwargs):
        return {"findings": [], "fuzz_results": [], "candidates": []}

    # run_quick_fuzz imports the fuzzer lazily from this module path.
    monkeypatch.setattr(
        "src.recon.quick_fuzz.quick_fuzzer.run_quick_fuzz", _fake_qf, raising=False
    )


@pytest.mark.asyncio
async def test_technologies_list_does_not_break_tech_stack():
    out = await handlers.run_quick_fuzz(
        "https://alleksy.com",
        recon_output={"technologies": ["Nginx", "Cloudflare"], "assets": []},
    )
    assert isinstance(out, QuickFuzzOutput)
    assert out.tech_stack == {}  # list technologies must NOT leak into tech_stack


@pytest.mark.asyncio
async def test_dict_tech_stack_preserved():
    out = await handlers.run_quick_fuzz(
        "https://alleksy.com",
        recon_output={"tech_stack": {"web_server": "nginx"}, "technologies": ["Nginx"]},
    )
    assert out.tech_stack == {"web_server": "nginx"}


@pytest.mark.asyncio
async def test_no_recon_output_is_empty_dict():
    out = await handlers.run_quick_fuzz("https://alleksy.com", recon_output=None)
    assert out.tech_stack == {}
    assert out.baseline_responses == {}
