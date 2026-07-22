"""P7-WSTG-007: executed-scenario coverage.

Verifies the ScenarioStatus→CoverageStatus mapping across all seven honest
states, that *running a scenario is not coverage* (an executed scenario with no
confirmed finding is EXECUTED_NO_FINDING, never CONFIRMED_FINDING), and that
finding/evidence linkage is carried through.
"""

from __future__ import annotations

from src.playbooks.actions import HttpExchange, HttpRequestSpec, HttpResponse
from src.playbooks.cleanup import CleanupOutcome
from src.playbooks.evidence import build_evidence_bundle
from src.playbooks.executor import ScenarioResult
from src.playbooks.lifecycle import ScenarioState, ScenarioStatus
from src.playbooks.oracles import OracleResult, OracleVerdict
from src.playbooks.schema import HttpMethod, OracleType
from src.pipeline.contracts.finding_dto import ConfidenceLevel
from src.reports.scenario_coverage import (
    CoverageStatus,
    build_scenario_coverage,
    build_scenario_coverage_record,
    map_scenario_status,
)


def _bundle() -> object:
    baseline = HttpExchange(
        request=HttpRequestSpec(method=HttpMethod.GET, url="https://t/api/users/1"),
        response=HttpResponse(status=200, body='{"email":"owner@example.com"}'),
    )
    mutated = HttpExchange(
        request=HttpRequestSpec(method=HttpMethod.GET, url="https://t/api/users/1"),
        response=HttpResponse(status=200, body='{"email":"owner@example.com"}'),
    )
    return build_evidence_bundle(baseline, mutated)


def _confirmed_result() -> ScenarioResult:
    planned = ScenarioState(status=ScenarioStatus.PLANNED)
    running = planned.transition(ScenarioStatus.RUNNING)
    confirmed = running.transition(ScenarioStatus.CONFIRMED, reason="cross-user read")
    cleaned = confirmed.transition(ScenarioStatus.CLEANUP_COMPLETE)
    return ScenarioResult(
        playbook_id="idor.cross-user-read",
        state=cleaned,
        executed=True,
        oracle_results=(
            OracleResult(
                oracle_type=OracleType.AUTHZ,
                verdict=OracleVerdict.FINDING,
                confidence=ConfidenceLevel.CONFIRMED,
                reason="attacker read the victim's email",
                differing_fields=[],
            ),
        ),
        evidence=_bundle(),
        cleanup=CleanupOutcome(status=ScenarioStatus.CLEANUP_COMPLETE, reason=None),
        history=(planned, running, confirmed, cleaned),
    )


def _rejected_result() -> ScenarioResult:
    planned = ScenarioState(status=ScenarioStatus.PLANNED)
    running = planned.transition(ScenarioStatus.RUNNING)
    rejected = running.transition(
        ScenarioStatus.REJECTED, reason="attacker request properly denied"
    )
    cleaned = rejected.transition(ScenarioStatus.CLEANUP_COMPLETE)
    return ScenarioResult(
        playbook_id="idor.cross-user-read",
        state=cleaned,
        executed=True,
        oracle_results=(
            OracleResult(
                oracle_type=OracleType.AUTHZ,
                verdict=OracleVerdict.NO_FINDING,
                confidence=ConfidenceLevel.CONFIRMED,
                reason="properly denied",
                differing_fields=[],
            ),
        ),
        evidence=_bundle(),
        cleanup=CleanupOutcome(status=ScenarioStatus.CLEANUP_COMPLETE, reason=None),
        history=(planned, running, rejected, cleaned),
    )


def test_status_mapping_covers_seven_states() -> None:
    assert map_scenario_status(ScenarioStatus.SKIPPED_NOT_APPLICABLE) is (
        CoverageStatus.NOT_APPLICABLE
    )
    assert map_scenario_status(ScenarioStatus.PLANNED) is CoverageStatus.NOT_RUN
    assert map_scenario_status(ScenarioStatus.WAITING_APPROVAL) is CoverageStatus.BLOCKED
    assert map_scenario_status(ScenarioStatus.PARTIAL) is CoverageStatus.PARTIAL
    assert map_scenario_status(ScenarioStatus.CONFIRMED) is (CoverageStatus.CONFIRMED_FINDING)
    assert map_scenario_status(ScenarioStatus.REJECTED) is (CoverageStatus.EXECUTED_NO_FINDING)
    assert map_scenario_status(ScenarioStatus.CLEANUP_FAILED) is CoverageStatus.ERROR


def test_execution_is_not_coverage() -> None:
    """An executed scenario with no confirmed finding is EXECUTED_NO_FINDING."""
    record = build_scenario_coverage_record(
        _rejected_result(),
        wstg=["WSTG-ATHZ-04"],
        cwe=[639],
    )
    assert record.executed is True
    assert record.coverage_status is CoverageStatus.EXECUTED_NO_FINDING
    assert record.coverage_status is not CoverageStatus.CONFIRMED_FINDING
    assert record.evidence_sufficient is False


def test_confirmed_scenario_links_findings() -> None:
    record = build_scenario_coverage_record(
        _confirmed_result(),
        wstg=["WSTG-ATHZ-04"],
        cwe=[639],
        owasp_api=["API1:2023"],
        finding_ids=["find-001"],
    )
    assert record.coverage_status is CoverageStatus.CONFIRMED_FINDING
    assert record.evidence_sufficient is True
    assert record.finding_ids == ["find-001"]
    assert record.wstg == ["WSTG-ATHZ-04"]


def test_not_applicable_when_flagged() -> None:
    record = build_scenario_coverage_record(_confirmed_result(), applicable=False)
    assert record.coverage_status is CoverageStatus.NOT_APPLICABLE


def test_execution_error_maps_to_error() -> None:
    planned = ScenarioState(status=ScenarioStatus.PLANNED)
    running = planned.transition(ScenarioStatus.RUNNING)
    rejected = running.transition(ScenarioStatus.REJECTED, reason="execution error: ActionError")
    cleaned = rejected.transition(ScenarioStatus.CLEANUP_COMPLETE)
    result = ScenarioResult(
        playbook_id="authn.bypass",
        state=cleaned,
        executed=True,
        history=(planned, running, rejected, cleaned),
    )
    record = build_scenario_coverage_record(result)
    assert record.coverage_status is CoverageStatus.ERROR
    assert record.skip_or_error_reason


def test_aggregate_reports_version_and_counts() -> None:
    records = [
        build_scenario_coverage_record(_confirmed_result(), finding_ids=["f1"]),
        build_scenario_coverage_record(_rejected_result()),
    ]
    block = build_scenario_coverage(records)
    assert block["wstg_version"] == "4.2"
    assert block["total_scenarios"] == 2
    assert block["executed"] == 2
    assert block["confirmed_findings"] == 1
    assert block["by_status"][CoverageStatus.EXECUTED_NO_FINDING.value] == 1
    assert block["by_status"][CoverageStatus.CONFIRMED_FINDING.value] == 1
    assert len(block["records"]) == 2
