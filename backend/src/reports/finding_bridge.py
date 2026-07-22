"""Confirmation → evidence → FindingDTO bridge (P7-WSTG-007, fix G-3).

ARGUS carries two different "finding" contracts:

* the VA confirmation contract
  (:class:`src.schemas.vulnerability_analysis.schemas.FindingStatus` —
  ``hypothesis / partially_confirmed / confirmed / rejected``), produced by
  :mod:`src.recon.vulnerability_analysis.confirmation_policy`; and
* the pipeline transport DTO
  (:class:`src.pipeline.contracts.finding_dto.FindingDTO` with its own
  ``new / validated / false_positive / ...`` status).

Before P7 the bridge between them was not end-to-end: a scenario *confirmed* by
the confirmation policy never surfaced as a ``FindingDTO`` carrying its scenario
provenance. This module closes that gap.

:func:`project_scenario_to_finding` takes a confirmed VA status and the
executed :class:`~src.playbooks.executor.ScenarioResult` and returns a new
``FindingDTO`` whose :class:`~src.pipeline.contracts.finding_dto.ScenarioContextDTO`
is populated (scenario id/version, principals, oracle verdict, cleanup status,
approval id) and whose ``evidence_ids`` are linked.

SECURITY (SI-3): baseline / mutated request & response payloads are **always**
passed through the single redaction implementation in
:mod:`src.playbooks.evidence` before they are written into the DTO. Redaction is
idempotent, so a payload that a :class:`~src.playbooks.evidence.EvidenceBundle`
already redacted stays redacted — there is no unredacted persistence path.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from uuid import UUID

from src.pipeline.contracts.finding_dto import (
    FindingDTO,
    FindingStatus,
    ScenarioContextDTO,
)
from src.playbooks.actions import HttpExchange
from src.playbooks.evidence import EvidenceBundle, redact
from src.playbooks.executor import ScenarioResult
from src.playbooks.schema import Playbook
from src.schemas.vulnerability_analysis.schemas import (
    FindingStatus as VAFindingStatus,
)

# VA confirmation status → pipeline FindingDTO status. Exhaustive over
# VAFindingStatus; a newly added member must be mapped here explicitly.
_VA_TO_DTO_STATUS: dict[VAFindingStatus, FindingStatus] = {
    VAFindingStatus.CONFIRMED: FindingStatus.VALIDATED,
    VAFindingStatus.REJECTED: FindingStatus.FALSE_POSITIVE,
    VAFindingStatus.PARTIALLY_CONFIRMED: FindingStatus.NEW,
    VAFindingStatus.HYPOTHESIS: FindingStatus.NEW,
}


def map_confirmation_status(status: VAFindingStatus) -> FindingStatus:
    """Project a VA confirmation status onto the pipeline FindingDTO status."""
    try:
        return _VA_TO_DTO_STATUS[status]
    except KeyError as exc:  # pragma: no cover - guards a new unmapped enum member
        raise ValueError(f"unmapped VA finding status: {status!r}") from exc


def _redacted_json(part: object) -> str:
    """Serialise a request/response model to redaction-safe canonical JSON.

    ``part`` is an ``HttpRequestSpec`` / ``HttpResponse`` (or any pydantic
    model). Its dumped mapping is run through :func:`src.playbooks.evidence.redact`
    so cookies / Authorization / token / password / otp values never reach the
    DTO (SI-3), then serialised deterministically.
    """
    if hasattr(part, "model_dump"):
        data = part.model_dump(mode="json")
    else:  # pragma: no cover - defensive; callers pass pydantic models
        data = part
    return json.dumps(redact(data), sort_keys=True, separators=(",", ":"))


def _exchange_pair(bundle: EvidenceBundle | None) -> tuple[HttpExchange, HttpExchange] | None:
    if bundle is None:
        return None
    return bundle.baseline, bundle.mutated


def _oracle_summary(result: ScenarioResult) -> tuple[str | None, str | None]:
    """Return ``(oracle_result, state_check)`` summaries from oracle verdicts."""
    if not result.oracle_results:
        return None, None
    verdicts = "; ".join(f"{o.oracle_type.value}={o.verdict.value}" for o in result.oracle_results)
    differing = sorted({field for o in result.oracle_results for field in o.differing_fields})
    state_check = ", ".join(differing) if differing else None
    return verdicts[:4000], (state_check[:4000] if state_check else None)


def _provenance(playbook: Playbook | None) -> str | None:
    if playbook is None:
        return None
    prov = playbook.provenance
    return prov.source_url or prov.note or None


def _merge_evidence_ids(
    existing: Sequence[UUID],
    added: Sequence[UUID] | None,
) -> list[UUID]:
    """Merge evidence id lists, de-duplicating while preserving order."""
    merged: list[UUID] = list(existing)
    seen = set(merged)
    for evidence_id in added or ():
        if evidence_id not in seen:
            merged.append(evidence_id)
            seen.add(evidence_id)
    return merged


def build_scenario_context(
    *,
    scenario_result: ScenarioResult,
    playbook: Playbook | None = None,
    playbook_run_id: UUID | None = None,
    source_principal: str | None = None,
    target_principal: str | None = None,
    role: str | None = None,
) -> ScenarioContextDTO:
    """Assemble a redacted :class:`ScenarioContextDTO` from a scenario result."""
    pair = _exchange_pair(scenario_result.evidence)
    baseline_request = baseline_response = None
    mutated_request = mutated_response = None
    response_diff: dict[str, object] | None = None
    redactions = 0
    if pair is not None and scenario_result.evidence is not None:
        baseline, mutated = pair
        baseline_request = _redacted_json(baseline.request)
        baseline_response = _redacted_json(baseline.response)
        mutated_request = _redacted_json(mutated.request)
        mutated_response = _redacted_json(mutated.response)
        response_diff = scenario_result.evidence.diff.model_dump(mode="json")
        redactions = scenario_result.evidence.redactions_applied

    oracle_result, state_check = _oracle_summary(scenario_result)
    cleanup_status = scenario_result.cleanup.status.value if scenario_result.cleanup else None
    approval_id = str(scenario_result.approval_id) if scenario_result.approval_id else None

    return ScenarioContextDTO(
        scenario_id=scenario_result.playbook_id,
        scenario_version=str(playbook.version) if playbook else None,
        playbook_run_id=str(playbook_run_id) if playbook_run_id else None,
        source_principal=source_principal,
        target_principal=target_principal,
        role=role,
        baseline_request=baseline_request,
        baseline_response=baseline_response,
        mutated_request=mutated_request,
        mutated_response=mutated_response,
        response_diff=response_diff,
        state_check=state_check,
        oracle_result=oracle_result,
        cleanup_status=cleanup_status,
        provenance=_provenance(playbook),
        approval_id=approval_id,
        redactions_applied=min(redactions, 100_000),
    )


def project_scenario_to_finding(
    base: FindingDTO,
    *,
    confirmation_status: VAFindingStatus,
    scenario_result: ScenarioResult,
    playbook: Playbook | None = None,
    playbook_run_id: UUID | None = None,
    source_principal: str | None = None,
    target_principal: str | None = None,
    role: str | None = None,
    evidence_ids: Sequence[UUID] | None = None,
) -> FindingDTO:
    """Return a new ``FindingDTO`` enriched with confirmed-scenario provenance.

    The confirmation status is projected onto the DTO status (a VA ``CONFIRMED``
    scenario becomes a ``VALIDATED`` finding), the scenario context is attached
    with redacted evidence, and any ``evidence_ids`` are linked (de-duplicated).
    The input ``base`` is left unchanged (``FindingDTO`` is frozen).
    """
    context = build_scenario_context(
        scenario_result=scenario_result,
        playbook=playbook,
        playbook_run_id=playbook_run_id,
        source_principal=source_principal,
        target_principal=target_principal,
        role=role,
    )
    return base.model_copy(
        update={
            "status": map_confirmation_status(confirmation_status),
            "evidence_ids": _merge_evidence_ids(base.evidence_ids, evidence_ids),
            "scenario_context": context,
        }
    )


__all__ = [
    "build_scenario_context",
    "map_confirmation_status",
    "project_scenario_to_finding",
]
