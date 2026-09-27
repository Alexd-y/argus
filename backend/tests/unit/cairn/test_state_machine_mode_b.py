"""Phase 9 Mode-B — engine=cairn call-site decision helpers (no DB).

Guards the state-machine wiring: the Cairn engine only takes over when BOTH
settings.cairn_enabled and scan_options.engine == "cairn" (both off by default), so a
normal pipeline scan is never affected. When active, only REPORTING runs in the loop.
"""

from __future__ import annotations

import pytest
from src.orchestration import state_machine as sm
from src.orchestration.phases import ScanPhase


def test_inactive_by_default(monkeypatch) -> None:
    monkeypatch.setattr(sm.settings, "cairn_enabled", False, raising=False)
    assert sm._cairn_engine_active({"engine": "cairn"}) is False
    assert sm._cairn_engine_active({"engine": "pipeline"}) is False
    assert sm._cairn_engine_active(None) is False


def test_active_only_when_enabled_and_engine_cairn(monkeypatch) -> None:
    monkeypatch.setattr(sm.settings, "cairn_enabled", True, raising=False)
    assert sm._cairn_engine_active({"engine": "cairn"}) is True
    assert sm._cairn_engine_active({"engine": "pipeline"}) is False
    assert sm._cairn_engine_active({}) is False


def test_skips_every_phase_but_reporting_when_active(monkeypatch) -> None:
    monkeypatch.setattr(sm.settings, "cairn_enabled", True, raising=False)
    opts = {"engine": "cairn"}
    non_reporting = [p for p in ScanPhase if p is not ScanPhase.REPORTING]
    assert non_reporting, "expected several non-reporting phases"
    for phase in non_reporting:
        assert sm._cairn_skips_phase(opts, phase) is True
    # reporting always runs, even in cairn mode
    assert sm._cairn_skips_phase(opts, ScanPhase.REPORTING) is False


@pytest.mark.parametrize("phase", list(ScanPhase))
def test_pipeline_mode_never_skips(monkeypatch, phase) -> None:
    monkeypatch.setattr(sm.settings, "cairn_enabled", True, raising=False)
    # engine=pipeline (default) → no phase is skipped by the Cairn branch
    assert sm._cairn_skips_phase({"engine": "pipeline"}, phase) is False
