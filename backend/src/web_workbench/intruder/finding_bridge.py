"""Intruder flagged-result → ``FindingDTO`` bridge (WB-P4b, pure/offline).

Lifts a *flagged* (interesting) Intruder request result into the canonical
pipeline :class:`~src.pipeline.contracts.finding_dto.FindingDTO` so Intruder
findings flow through the same reporting/enrichment path as every other tool —
no bespoke "intruder finding" contract downstream.

This module is **pure**: no I/O, no network, no DB. Identity fields
(``tenant_id``/``scan_id``/``asset_id``/``tool_run_id``) are supplied by the
caller (the WB-P4b runner/worker) that owns the run context; evidence
persistence and ``evidence_ids`` linkage happen in the infra-gated layer.

A grep/status flag is a *candidate*, not a proof: findings are emitted at
``evidence_tier=SUSPECTED`` / ``confidence=SUSPECTED`` and ``status=NEW`` — a
human / FP-verifier promotes them. The category and CWE are taken from the
attack's declared intent (``payload_config``/``config``) with a fail-closed
generic default so an unclassified attack still yields a valid, conservative
finding.
"""

from __future__ import annotations

from collections.abc import Mapping
from uuid import UUID, uuid4

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    EvidenceTier,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    RemediationDTO,
)
from src.web_workbench.intruder.repository import IntruderRequestDTO

#: Conservative representative CVSS v3.1 vector/score for a suspected candidate.
_SUSPECTED_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
_SUSPECTED_CVSS_SCORE = 5.3

#: Fail-closed generic CWE when the attack declares none (CWE-20: improper input
#: validation) — always a valid, non-empty ``cwe`` list.
_DEFAULT_CWE = 20


def _category_from(config: Mapping[str, object] | None) -> FindingCategory:
    if not config:
        return FindingCategory.OTHER
    finding = config.get("finding")
    if isinstance(finding, Mapping):
        raw = finding.get("category")
        if isinstance(raw, str):
            try:
                return FindingCategory(raw)
            except ValueError:
                return FindingCategory.OTHER
    return FindingCategory.OTHER


def _cwe_from(config: Mapping[str, object] | None) -> list[int]:
    if config:
        finding = config.get("finding")
        if isinstance(finding, Mapping):
            raw = finding.get("cwe")
            if isinstance(raw, (list, tuple)):
                cwes = [int(v) for v in raw if isinstance(v, int) and v > 0]
                if cwes:
                    return cwes
    return [_DEFAULT_CWE]


def flagged_request_to_finding(
    request: IntruderRequestDTO,
    *,
    tenant_id: UUID,
    scan_id: UUID,
    asset_id: UUID,
    tool_run_id: UUID,
    attack_name: str,
    attack_config: Mapping[str, object] | None = None,
    finding_id: UUID | None = None,
) -> FindingDTO:
    """Project one flagged Intruder request onto a canonical ``FindingDTO``.

    Raises :class:`ValueError` if ``request`` is not flagged (only interesting
    results become findings — fail-closed against over-reporting).
    """
    if not request.flagged:
        raise ValueError("only a flagged request may be bridged to a finding")

    status_part = f"HTTP {request.status_code}" if request.status_code is not None else "no status"
    length_part = (
        f"{request.response_length} bytes" if request.response_length is not None else "n/a"
    )
    summary = (
        f"Intruder attack {attack_name!r} flagged request #{request.request_index} "
        f"(payload {request.payload_label or request.payload_index}); "
        f"response {status_part}, {length_part}. Manual verification required."
    )
    return FindingDTO(
        id=finding_id or uuid4(),
        tenant_id=tenant_id,
        scan_id=scan_id,
        asset_id=asset_id,
        tool_run_id=tool_run_id,
        category=_category_from(attack_config),
        cwe=_cwe_from(attack_config),
        cvss_v3_vector=_SUSPECTED_CVSS_VECTOR,
        cvss_v3_score=_SUSPECTED_CVSS_SCORE,
        confidence=ConfidenceLevel.SUSPECTED,
        status=FindingStatus.NEW,
        evidence_tier=EvidenceTier.SUSPECTED,
        remediation=RemediationDTO(summary=summary[:2000]),
    )


__all__ = ["flagged_request_to_finding"]
