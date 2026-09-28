"""Phase E.1 — granular cloud carve-out for report tasks under ``llm_cloud_disabled``.

WRB-001 keeps cloud disabled for pentest analysis, but report generation
(executive summary / cost summary / remediation plan / closure assessment /
report section) is an explicit exception so disabling cloud for analysis does not
silently blank the Valhalla report's mandatory LLM conclusions.
"""

from __future__ import annotations

import pytest
from src.core.config import settings
from src.llm.facade import _REPORT_CLOUD_TASKS, _cloud_fallback_allowed
from src.llm.task_router import LLMTask

_REPORT_TASKS = (
    LLMTask.REPORT_SECTION,
    LLMTask.EXECUTIVE_SUMMARY,
    LLMTask.COST_SUMMARY,
    LLMTask.CLOSURE_ASSESSMENT,
    LLMTask.REMEDIATION_PLAN,
)

_PENTEST_TASKS = (
    LLMTask.ORCHESTRATION,
    LLMTask.THREAT_MODELING,
)


def test_report_tasks_are_in_carveout_set() -> None:
    for task in _REPORT_TASKS:
        assert task in _REPORT_CLOUD_TASKS


def test_cloud_enabled_normal_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_cloud_disabled", False)
    for task in _REPORT_TASKS:
        assert _cloud_fallback_allowed(task) is True


def test_report_tasks_survive_cloud_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_cloud_disabled", True)
    monkeypatch.setattr(settings, "llm_cloud_enabled_for_reports", True)
    for task in _REPORT_TASKS:
        assert _cloud_fallback_allowed(task) is True
    # Pentest analysis tasks stay fail-closed (never in the fallback set).
    for task in _PENTEST_TASKS:
        assert _cloud_fallback_allowed(task) is False


def test_air_gapped_disables_report_cloud_too(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_cloud_disabled", True)
    monkeypatch.setattr(settings, "llm_cloud_enabled_for_reports", False)
    for task in _REPORT_TASKS:
        assert _cloud_fallback_allowed(task) is False
