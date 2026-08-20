"""Unit tests for the adaptive LoopReport -> scan-artifact transformation layer.

Verifies the bridge that lets the adaptive driver produce the same artifact
contract as the linear FSM: confirmed actions become conservative findings
(SUSPECTED tier — never over-claimed), non-confirmed actions produce nothing, and
the aggregate maps to a typed VulnAnalysisOutput + append-only timeline entries.
"""

from __future__ import annotations

import json

from src.orchestration.adaptive_artifacts import (
    action_record_to_finding,
    adaptive_coverage_result,
    loop_report_timeline_entries,
    loop_report_to_findings,
    loop_report_to_vuln_output,
)
from src.orchestration.adaptive_loop import (
    ActionProposal,
    ActionRecord,
    LoopReport,
    VerifyOutcome,
)
from src.orchestration.evidence_tier import EvidenceTier
from src.orchestration.phases import VulnAnalysisOutput


def _record(
    tool: str,
    target: str = "https://t.tld/x",
    *,
    outcome: VerifyOutcome = VerifyOutcome.CONFIRMED,
    param: str = "q",
    location: str = "query",
    surface_id: str = "surf_1",
    exit_code: int = 0,
    evidence: str = "signal observed",
    vuln_type: str | None = None,
) -> ActionRecord:
    metadata: dict[str, object] = {
        "param_name": param,
        "location": location,
        "surface_id": surface_id,
        "url": target,
    }
    if vuln_type:
        metadata["vuln_type"] = vuln_type
    return ActionRecord(
        proposal=ActionProposal(
            node_id=f"input:{tool}:{param}", tool=tool, target=target, metadata=metadata
        ),
        outcome=outcome,
        exit_code=exit_code,
        evidence=evidence,
    )


def _report(records: list[ActionRecord]) -> LoopReport:
    confirmed = sum(1 for r in records if r.outcome == VerifyOutcome.CONFIRMED)
    rejected = sum(1 for r in records if r.outcome == VerifyOutcome.REJECTED)
    inconclusive = sum(1 for r in records if r.outcome == VerifyOutcome.INCONCLUSIVE)
    return LoopReport(
        actions_run=len(records),
        confirmed=confirmed,
        rejected=rejected,
        inconclusive=inconclusive,
        stopped_reason="no_more_actions",
        coverage={
            "parameter_coverage": 1.0,
            "endpoint_coverage": 1.0,
            "node_count": 4,
            "edge_count": 4,
            "untested_inputs": 0,
        },
        trace=records,
    )


class TestActionRecordToFinding:
    def test_confirmed_sqlmap_finding(self) -> None:
        f = action_record_to_finding(_record("sqlmap"))
        assert f is not None
        assert f["severity"] == "high"
        assert f["cwe"] == "CWE-89"
        assert "SQL Injection" in f["title"]
        assert f["evidence_tier"] == int(EvidenceTier.SUSPECTED)  # never over-claim
        assert f["parameter"] == "q"
        assert f["evidence_refs"] == ["surf_1"]
        assert f["proof_of_concept"]["tool"] == "sqlmap"
        assert f["proof_of_concept"]["evidence"] == "signal observed"
        assert f["source"] == "adaptive_loop"
        assert f["adaptive"] is True
        assert f["exploit_demonstrated"] is False

    def test_rejected_and_inconclusive_produce_none(self) -> None:
        assert (
            action_record_to_finding(_record("sqlmap", outcome=VerifyOutcome.REJECTED, exit_code=1))
            is None
        )
        assert (
            action_record_to_finding(_record("sqlmap", outcome=VerifyOutcome.INCONCLUSIVE)) is None
        )

    def test_unknown_tool_defaults_to_info_no_cwe(self) -> None:
        f = action_record_to_finding(_record("weirdtool"))
        assert f is not None
        assert f["severity"] == "info"
        assert "cwe" not in f

    def test_explicit_vuln_type_used_for_unknown_tool(self) -> None:
        f = action_record_to_finding(_record("weirdtool", vuln_type="IDOR"))
        assert f is not None
        assert "IDOR" in f["title"]
        assert f["severity"] == "medium"

    def test_known_tool_wins_over_metadata_hint(self) -> None:
        # A catalogued tool's mapping is authoritative over a free-text hint.
        f = action_record_to_finding(_record("sqlmap", vuln_type="xss"))
        assert f is not None
        assert f["cwe"] == "CWE-89"

    def test_no_param_still_produces_finding(self) -> None:
        rec = ActionRecord(
            proposal=ActionProposal(
                node_id="n",
                tool="nuclei",
                target="https://t.tld/",
                metadata={"url": "https://t.tld/"},
            ),
            outcome=VerifyOutcome.CONFIRMED,
            exit_code=0,
            evidence="x",
        )
        f = action_record_to_finding(rec)
        assert f is not None
        assert "parameter" not in f
        assert f["url"] == "https://t.tld/"


class TestLoopReportAggregation:
    def test_findings_filter_non_confirmed(self) -> None:
        report = _report(
            [
                _record("sqlmap", param="a"),
                _record("dalfox", param="b", outcome=VerifyOutcome.REJECTED, exit_code=1),
                _record("nuclei", param="c", outcome=VerifyOutcome.INCONCLUSIVE),
                _record("commix", param="d"),
            ]
        )
        findings = loop_report_to_findings(report)
        assert len(findings) == 2  # only the 2 confirmed
        params = {f.get("parameter") for f in findings}
        assert params == {"a", "d"}

    def test_vuln_output_is_typed_with_coverage(self) -> None:
        report = _report([_record("sqlmap", param="a"), _record("dalfox", param="b")])
        out = loop_report_to_vuln_output(report)
        assert isinstance(out, VulnAnalysisOutput)
        assert len(out.findings) == 2
        assert len(out.coverage_results) == 1
        cov = out.coverage_results[0]
        assert cov["kind"] == "adaptive_loop"
        assert cov["actions_run"] == 2
        assert cov["confirmed"] == 2
        assert cov["parameter_coverage"] == 1.0

    def test_coverage_result_shape(self) -> None:
        report = _report([_record("sqlmap")])
        cov = adaptive_coverage_result(report)
        assert cov["stopped_reason"] == "no_more_actions"
        assert cov["node_count"] == 4

    def test_timeline_entries_one_per_action(self) -> None:
        report = _report(
            [
                _record("sqlmap", param="a"),
                _record("dalfox", param="b", outcome=VerifyOutcome.REJECTED, exit_code=1),
            ]
        )
        entries = loop_report_timeline_entries(report)
        assert len(entries) == 2
        assert all(e["kind"] == "adaptive_action" for e in entries)
        outcomes = {e["outcome"] for e in entries}
        assert outcomes == {"confirmed", "rejected"}

    def test_vuln_output_findings_are_json_serializable(self) -> None:
        report = _report([_record("sqlmap"), _record("commix", param="d")])
        out = loop_report_to_vuln_output(report)
        dumped = out.model_dump(mode="json")
        assert json.loads(json.dumps(dumped)) == dumped
