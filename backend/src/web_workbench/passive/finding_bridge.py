"""Passive finding → ``FindingDTO`` bridge (WB-P5b, pure/offline).

Lifts a :class:`~src.web_workbench.passive.analyzer.PassiveFinding` (produced by
the offline passive analyzer, WB-P5a) into the canonical pipeline
:class:`~src.pipeline.contracts.finding_dto.FindingDTO` so passive hygiene results
flow through the same reporting/enrichment path as active findings — no bespoke
"passive finding" contract downstream.

This module is **pure**: no I/O, no network, no DB. Identity fields
(``tenant_id``/``scan_id``/``asset_id``/``tool_run_id``) are supplied by the
caller (the WB-P5b scanner orchestrator) that owns the run context; evidence
persistence and ``evidence_ids`` linkage happen in the infra-gated layer.

Passive findings never claim exploitation: their ``evidence_tier`` is
``INFORMATIONAL`` (config hygiene) or ``SUSPECTED`` (reflection candidate), and
status is always ``NEW`` (a human/FP-verifier promotes them). CWE and a
representative CVSS v3.1 vector are derived from stable per-code / per-severity
tables (fail-closed on an unknown code).
"""

from __future__ import annotations

from uuid import UUID, uuid4

from src.pipeline.contracts.finding_dto import (
    EvidenceTier,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    RemediationDTO,
)
from src.web_workbench.passive.analyzer import PassiveFinding, PassiveSeverity

#: Representative CVSS v3.1 (vector, base score) per coarse passive severity.
#: Vectors are canonical and their scores are the standard CVSS values, so the
#: DTO carries a defensible — if conservative — severity signal.
_SEVERITY_CVSS: dict[PassiveSeverity, tuple[str, float]] = {
    PassiveSeverity.INFO: ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
    PassiveSeverity.LOW: ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    PassiveSeverity.MEDIUM: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    PassiveSeverity.HIGH: ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
}


class _CodeMeta:
    __slots__ = ("cwe", "evidence_tier")

    def __init__(self, cwe: tuple[int, ...], evidence_tier: EvidenceTier) -> None:
        self.cwe = cwe
        self.evidence_tier = evidence_tier


#: Per-check CWE mapping + evidence tier. Reflection is a SUSPECTED candidate;
#: every other passive check is INFORMATIONAL configuration hygiene.
_CODE_META: dict[str, _CodeMeta] = {
    "missing-hsts": _CodeMeta((319,), EvidenceTier.INFORMATIONAL),
    "missing-nosniff": _CodeMeta((693,), EvidenceTier.INFORMATIONAL),
    "missing-csp": _CodeMeta((693,), EvidenceTier.INFORMATIONAL),
    "clickjacking": _CodeMeta((1021,), EvidenceTier.INFORMATIONAL),
    "cookie-missing-secure": _CodeMeta((614,), EvidenceTier.INFORMATIONAL),
    "cookie-missing-httponly": _CodeMeta((1004,), EvidenceTier.INFORMATIONAL),
    "cookie-missing-samesite": _CodeMeta((1275,), EvidenceTier.INFORMATIONAL),
    "version-disclosure": _CodeMeta((200,), EvidenceTier.INFORMATIONAL),
    "cors-wildcard-credentials": _CodeMeta((942,), EvidenceTier.INFORMATIONAL),
    "reflected-input": _CodeMeta((79,), EvidenceTier.SUSPECTED),
}


def _meta_for(code: str) -> _CodeMeta:
    try:
        return _CODE_META[code]
    except KeyError as exc:  # fail-closed: an unmapped passive code is a bug.
        raise ValueError(f"unmapped passive finding code: {code!r}") from exc


def _cvss_for(severity: PassiveSeverity) -> tuple[str, float]:
    try:
        return _SEVERITY_CVSS[severity]
    except KeyError as exc:  # pragma: no cover - guards a new unmapped severity.
        raise ValueError(f"unmapped passive severity: {severity!r}") from exc


def _remediation(finding: PassiveFinding) -> RemediationDTO:
    summary = (
        f"{finding.title}: {finding.detail} (evidence: {finding.evidence}; at {finding.location})"
    )
    return RemediationDTO(summary=summary[:2000])


def passive_finding_to_dto(
    finding: PassiveFinding,
    *,
    tenant_id: UUID,
    scan_id: UUID,
    asset_id: UUID,
    tool_run_id: UUID,
    finding_id: UUID | None = None,
) -> FindingDTO:
    """Project one :class:`PassiveFinding` onto a canonical ``FindingDTO``.

    ``finding_id`` defaults to a fresh UUID; callers may pass a deterministic id
    for idempotent re-ingestion. Category/confidence are carried from the passive
    finding; CWE/CVSS/tier come from the stable maps above.
    """
    meta = _meta_for(finding.code)
    cvss_vector, cvss_score = _cvss_for(finding.severity)
    category: FindingCategory = finding.category
    return FindingDTO(
        id=finding_id or uuid4(),
        tenant_id=tenant_id,
        scan_id=scan_id,
        asset_id=asset_id,
        tool_run_id=tool_run_id,
        category=category,
        cwe=list(meta.cwe),
        cvss_v3_vector=cvss_vector,
        cvss_v3_score=cvss_score,
        confidence=finding.confidence,
        status=FindingStatus.NEW,
        evidence_tier=meta.evidence_tier,
        remediation=_remediation(finding),
    )


def passive_findings_to_dtos(
    findings: list[PassiveFinding],
    *,
    tenant_id: UUID,
    scan_id: UUID,
    asset_id: UUID,
    tool_run_id: UUID,
) -> list[FindingDTO]:
    """Project a batch of passive findings (fresh UUID per finding)."""
    return [
        passive_finding_to_dto(
            finding,
            tenant_id=tenant_id,
            scan_id=scan_id,
            asset_id=asset_id,
            tool_run_id=tool_run_id,
        )
        for finding in findings
    ]


__all__ = [
    "passive_finding_to_dto",
    "passive_findings_to_dtos",
]
