"""P7-WSTG-007 (fix G-3): FindingDTO scenario extension + confirmation bridge.

Covers:
* back-compat — an existing producer that never sets ``scenario_context`` still
  builds a valid FindingDTO (all new fields Optional, SI-7);
* SI-3 — baseline/mutated request & response are redacted before reaching the
  DTO (no secrets persisted);
* the end-to-end bridge — a VA ``CONFIRMED`` scenario projects onto a
  ``VALIDATED`` FindingDTO carrying scenario_id / approval_id / evidence links.
"""

from __future__ import annotations

from uuid import uuid4

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    ScenarioContextDTO,
)
from src.playbooks.actions import HttpExchange, HttpRequestSpec, HttpResponse
from src.playbooks.cleanup import CleanupOutcome
from src.playbooks.evidence import build_evidence_bundle
from src.playbooks.executor import ScenarioResult
from src.playbooks.lifecycle import ScenarioState, ScenarioStatus
from src.playbooks.oracles import OracleResult, OracleVerdict
from src.playbooks.schema import HttpMethod, OracleType
from src.reports.finding_bridge import (
    map_confirmation_status,
    project_scenario_to_finding,
)
from src.schemas.vulnerability_analysis.schemas import (
    FindingStatus as VAFindingStatus,
)

_SECRET_TOKEN = "SUPERSECRET_BEARER_abc123"
_SECRET_PASSWORD = "hunter2_password"


def _base_finding(**overrides: object) -> FindingDTO:
    kwargs: dict[str, object] = {
        "id": uuid4(),
        "tenant_id": uuid4(),
        "scan_id": uuid4(),
        "asset_id": uuid4(),
        "tool_run_id": uuid4(),
        "category": FindingCategory.IDOR,
        "cwe": [639],
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cvss_v3_score": 6.5,
        "confidence": ConfidenceLevel.CONFIRMED,
        "status": FindingStatus.NEW,
    }
    kwargs.update(overrides)
    return FindingDTO(**kwargs)  # type: ignore[arg-type]


def _confirmed_result(*, approval_id: object = None) -> ScenarioResult:
    # Baseline / mutated exchanges carry secrets that MUST be redacted (SI-3).
    baseline = HttpExchange(
        request=HttpRequestSpec(
            method=HttpMethod.GET,
            url="https://t/api/users/2001",
            headers={"Authorization": f"Bearer {_SECRET_TOKEN}"},
            body=f'{{"password":"{_SECRET_PASSWORD}"}}',
        ),
        response=HttpResponse(status=200, body='{"email":"victim@example.com"}'),
    )
    mutated = HttpExchange(
        request=HttpRequestSpec(
            method=HttpMethod.GET,
            url="https://t/api/users/2001",
            headers={"Authorization": f"Bearer {_SECRET_TOKEN}"},
        ),
        response=HttpResponse(status=200, body='{"email":"victim@example.com"}'),
    )
    bundle = build_evidence_bundle(baseline, mutated)

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
        evidence=bundle,
        cleanup=CleanupOutcome(status=ScenarioStatus.CLEANUP_COMPLETE, reason=None),
        approval_id=approval_id,  # type: ignore[arg-type]
        history=(planned, running, confirmed, cleaned),
    )


# ---------------------------------------------------------------------------
# Back-compat (SI-7)
# ---------------------------------------------------------------------------


def test_finding_without_scenario_context_is_valid() -> None:
    """Existing producers that never set scenario_context stay valid."""
    finding = _base_finding()
    assert finding.scenario_context is None


def test_finding_round_trip_with_scenario_context() -> None:
    ctx = ScenarioContextDTO(scenario_id="idor.cross-user-read", scenario_version="2")
    finding = _base_finding(scenario_context=ctx)
    restored = FindingDTO.model_validate_json(finding.model_dump_json())
    assert restored == finding
    assert restored.scenario_context is not None
    assert restored.scenario_context.scenario_id == "idor.cross-user-read"


# ---------------------------------------------------------------------------
# Status mapping
# ---------------------------------------------------------------------------


def test_confirmation_status_mapping() -> None:
    assert map_confirmation_status(VAFindingStatus.CONFIRMED) is FindingStatus.VALIDATED
    assert map_confirmation_status(VAFindingStatus.REJECTED) is (FindingStatus.FALSE_POSITIVE)
    assert map_confirmation_status(VAFindingStatus.HYPOTHESIS) is FindingStatus.NEW
    assert map_confirmation_status(VAFindingStatus.PARTIALLY_CONFIRMED) is (FindingStatus.NEW)


# ---------------------------------------------------------------------------
# Bridge (G-3, end-to-end)
# ---------------------------------------------------------------------------


def test_bridge_projects_confirmed_scenario() -> None:
    approval = uuid4()
    evidence_id = uuid4()
    base = _base_finding()

    finding = project_scenario_to_finding(
        base,
        confirmation_status=VAFindingStatus.CONFIRMED,
        scenario_result=_confirmed_result(approval_id=approval),
        playbook_run_id=uuid4(),
        source_principal="attacker",
        target_principal="owner",
        role="user",
        evidence_ids=[evidence_id],
    )

    assert finding.status is FindingStatus.VALIDATED
    assert finding.scenario_context is not None
    ctx = finding.scenario_context
    assert ctx.scenario_id == "idor.cross-user-read"
    assert ctx.approval_id == str(approval)
    assert ctx.source_principal == "attacker"
    assert ctx.target_principal == "owner"
    assert ctx.cleanup_status == ScenarioStatus.CLEANUP_COMPLETE.value
    assert ctx.oracle_result and "authz=finding" in ctx.oracle_result
    assert evidence_id in finding.evidence_ids
    # Base finding is untouched (frozen / immutable).
    assert base.scenario_context is None
    assert base.status is FindingStatus.NEW


def test_bridge_redacts_baseline_and_mutated() -> None:
    """SI-3: request/response secrets never reach the DTO."""
    finding = project_scenario_to_finding(
        _base_finding(),
        confirmation_status=VAFindingStatus.CONFIRMED,
        scenario_result=_confirmed_result(),
    )
    ctx = finding.scenario_context
    assert ctx is not None
    blob = " ".join(
        part or ""
        for part in (
            ctx.baseline_request,
            ctx.baseline_response,
            ctx.mutated_request,
            ctx.mutated_response,
        )
    )
    assert _SECRET_TOKEN not in blob
    assert _SECRET_PASSWORD not in blob
    assert "[REDACTED]" in blob
    assert ctx.redactions_applied > 0


def test_rejected_scenario_projects_false_positive() -> None:
    result = _confirmed_result()
    finding = project_scenario_to_finding(
        _base_finding(),
        confirmation_status=VAFindingStatus.REJECTED,
        scenario_result=result,
    )
    assert finding.status is FindingStatus.FALSE_POSITIVE
