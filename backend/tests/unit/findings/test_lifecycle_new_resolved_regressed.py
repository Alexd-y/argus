"""Finding lifecycle demo: new → resolved → regressed (DoD §22)."""

from __future__ import annotations

from src.findings.diff import DiffStatus, FindingDiffService
from src.findings.lifecycle import (
    FindingLifecycleService,
    FindingState,
    LogicalFinding,
)
from src.findings.retest import RetestResultKind


def test_new_resolved_regressed_demo() -> None:
    service = FindingLifecycleService()
    finding = LogicalFinding(
        finding_key="demo-sqli-login",
        tenant_id="t-1",
        engagement_id="e-1",
        state=FindingState.CANDIDATE,
        title="SQLi login",
    )
    baseline = {"demo-sqli-login": finding.model_copy()}
    service.propose_resolved_candidate(finding, coverage_equivalent=True)
    service.confirm_resolved_via_retest(finding)
    assert finding.state is FindingState.RESOLVED
    fixed = {"demo-sqli-login": finding.model_copy()}
    service.mark_regressed(finding)
    assert finding.state is FindingState.REGRESSED
    current = {"demo-sqli-login": finding}

    new_entries = FindingDiffService().diff(baseline={}, current=baseline)
    assert new_entries[0].status is DiffStatus.NEW
    resolved_entries = FindingDiffService().diff(baseline=baseline, current=fixed)
    assert resolved_entries[0].status in {DiffStatus.CHANGED, DiffStatus.RESOLVED}
    regressed_entries = FindingDiffService().diff(baseline=fixed, current=current)
    assert regressed_entries[0].status is DiffStatus.REGRESSED
    assert RetestResultKind.STILL_PRESENT.value == "still_present"
