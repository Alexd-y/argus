"""Phase 15 — dual local LLM: fail-closed cloud switch, qwythos config, AWS routing."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from src.core.config import Settings


def test_qwythos_and_cloud_flag_defaults() -> None:
    s = Settings(_env_file=None)
    assert s.llm_cloud_disabled is False  # default preserves existing behaviour
    assert s.qwythos_model
    assert s.qwythos_max_context == 32768
    assert s.qwythos_timeout_sec == 1800


def test_cloud_fallback_disabled_switch(monkeypatch) -> None:
    from src.llm import facade
    from src.llm.task_router import LLMTask

    # By default report tasks allow cloud fallback ...
    monkeypatch.setattr(facade.settings, "llm_cloud_disabled", False, raising=False)
    assert facade._cloud_fallback_allowed(LLMTask.REPORT_SECTION) is True
    # ... and Cairn analysis tasks never do.
    assert facade._cloud_fallback_allowed(LLMTask.CAIRN_REASON) is False

    # With the fail-closed switch on, NO task reaches cloud — report tasks included.
    monkeypatch.setattr(facade.settings, "llm_cloud_disabled", True, raising=False)
    assert facade._cloud_fallback_allowed(LLMTask.REPORT_SECTION) is False
    assert facade._cloud_fallback_allowed(LLMTask.EXECUTIVE_SUMMARY) is False
    assert facade._cloud_fallback_allowed(LLMTask.CAIRN_REASON) is False


def test_remediation_and_closure_conclusions_use_cloud_by_default(monkeypatch) -> None:
    """Operator requirement: report conclusions on found/exploited vulns + remediation
    conclusions route to the cloud LLM API by default."""
    from src.llm import facade
    from src.llm.task_router import LLMTask

    monkeypatch.setattr(facade.settings, "llm_cloud_disabled", False, raising=False)
    assert facade._cloud_fallback_allowed(LLMTask.REMEDIATION_PLAN) is True
    assert facade._cloud_fallback_allowed(LLMTask.CLOSURE_ASSESSMENT) is True
    assert facade._cloud_fallback_allowed(LLMTask.EXECUTIVE_SUMMARY) is True


def test_valhalla_remediation_enabled_by_default() -> None:
    assert Settings(_env_file=None).valhalla_llm_remediation_enabled is True


def test_aws_dual_local_routing_yaml_is_valid() -> None:
    from src.llm.phase_routing import _VALID_FALLBACKS, _VALID_MODES

    path = (
        Path(__file__).resolve().parents[3] / "config" / "llm" / "phase_routing.aws-dual-local.yaml"
    )
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["version"] == "2026-09-argus-aws-dual-local-v1"
    phases = data["phases"]
    assert {"recon", "vuln_analysis", "exploitation", "reporting"} <= set(phases)
    for phase, spec in phases.items():
        assert spec["mode"] in _VALID_MODES, f"{phase} bad mode {spec['mode']}"
        assert spec["fallback"] in _VALID_FALLBACKS, f"{phase} bad fallback {spec['fallback']}"
        # No phase in the all-local profile routes primary to cloud.
        assert spec["mode"] != "cloud", f"{phase} must not route to cloud in dual-local"


@pytest.mark.parametrize("phase", ["exploitation", "post_exploitation"])
def test_offensive_phases_prefer_wrb(phase: str) -> None:
    path = (
        Path(__file__).resolve().parents[3] / "config" / "llm" / "phase_routing.aws-dual-local.yaml"
    )
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["phases"][phase]["mode"] == "wrb"
    assert data["phases"][phase]["fallback"] == "qwythos"
