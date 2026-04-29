"""Fail-closed destructive tool policy and injection gate smoke tests (mocks only; no MinIO)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from src.core import config as core_config
from src.recon.mcp.policy import TOOL_APPROVAL_POLICY_ID, evaluate_tool_approval_policy
from src.reports.report_quality_gate import evaluate_injection_finding_rules


def test_destructive_fail_closed_no_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core_config.settings, "argus_lab_mode", False, raising=False)
    d = evaluate_tool_approval_policy("sqlmap", scan_approval_flags=None)
    assert d.allowed is False
    assert d.policy_id == TOOL_APPROVAL_POLICY_ID
    assert d.reason == "requires_lab_mode"

    monkeypatch.setattr(core_config.settings, "argus_lab_mode", True, raising=False)
    monkeypatch.setattr(
        core_config.settings, "argus_destructive_lab_mode", True, raising=False
    )
    d2 = evaluate_tool_approval_policy("sqlmap", scan_approval_flags=None)
    assert d2.allowed is False
    assert d2.reason == "requires_approval"

    d3 = evaluate_tool_approval_policy("sqlmap", scan_approval_flags={})
    assert d3.allowed is False
    assert d3.reason == "requires_approval"


def test_gating_logs_requires_approval() -> None:
    with patch("src.recon.mcp.policy.logger") as log:
        evaluate_tool_approval_policy("commix", scan_approval_flags=None)
    info_calls = [c for c in log.info.call_args_list if c.kwargs.get("extra", {}).get("event") == "destructive_requires_approval"]
    assert len(info_calls) >= 1
    extra = info_calls[0].kwargs["extra"]
    assert extra.get("requires_approval") is True
    assert extra.get("scan_approval_flags_absent") is True
    assert "argus_lab_mode" in extra


def test_injection_finding_no_evidence_refs_warns() -> None:
    f = {
        "title": "Test injection",
        "cwe": "CWE-89",
        "confidence": "likely",
        "evidence_refs": [],
        "proof_of_concept": {"request_url": "https://example.com/?x=1"},
    }
    rules = evaluate_injection_finding_rules(f)
    assert any("missing_evidence_refs" in r for r in rules)
