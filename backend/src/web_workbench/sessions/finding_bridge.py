"""Authorization finding → ``FindingDTO`` bridge (WB-P6b, pure/offline).

Lifts an :class:`~src.web_workbench.checks.authorization_analyzer.
AuthorizationFinding` (a proven cross-user read classified IDOR / BFLA /
unauth-access) into the canonical pipeline
:class:`~src.pipeline.contracts.finding_dto.FindingDTO`, so access-control
findings flow through the same reporting/enrichment path as every other tool.

This module is **pure**: no I/O, no network, no DB. Identity fields
(``tenant_id``/``scan_id``/``asset_id``/``tool_run_id``) are supplied by the
caller (the WB-P6b runner/worker) that owns the run context; evidence
persistence and ``evidence_ids`` linkage happen in the infra-gated layer.

SECURITY (SI-3): the source finding already carries only field *paths* and a URL
object-id token — never response values or secrets — and this bridge propagates
only those. A proven cross-user read is strong evidence, so findings are emitted
at ``evidence_tier=CONFIRMED``; ``confidence`` is carried from the oracle verdict.
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
from src.web_workbench.checks.authorization_analyzer import AuthorizationFinding, AuthzClass


class _ClassMeta:
    __slots__ = ("category", "cwe")

    def __init__(self, category: FindingCategory, cwe: tuple[int, ...]) -> None:
        self.category = category
        self.cwe = cwe


#: Category + CWE per access-control classification.
#: CWE-639 (IDOR), CWE-862 (missing authorization / BFLA), CWE-306 (missing
#: authentication for critical function / unauth access).
_CLASS_META: dict[AuthzClass, _ClassMeta] = {
    AuthzClass.IDOR: _ClassMeta(FindingCategory.IDOR, (639,)),
    AuthzClass.BFLA: _ClassMeta(FindingCategory.AUTH, (862,)),
    AuthzClass.UNAUTH_ACCESS: _ClassMeta(FindingCategory.AUTH, (306,)),
}

#: Representative CVSS v3.1 for a proven broken-access-control read: network,
#: low complexity, confidentiality high (base 7.5).
_BAC_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
_BAC_CVSS_SCORE = 7.5


def _meta_for(classification: AuthzClass) -> _ClassMeta:
    try:
        return _CLASS_META[classification]
    except KeyError as exc:  # fail-closed: an unmapped class is a bug.
        raise ValueError(f"unmapped authorization class: {classification!r}") from exc


def authorization_finding_to_dto(
    finding: AuthorizationFinding,
    *,
    tenant_id: UUID,
    scan_id: UUID,
    asset_id: UUID,
    tool_run_id: UUID,
    finding_id: UUID | None = None,
) -> FindingDTO:
    """Project one :class:`AuthorizationFinding` onto a canonical ``FindingDTO``."""
    meta = _meta_for(finding.classification)
    object_part = f" object-id={finding.object_id}" if finding.object_id else ""
    fields_part = (
        f" differing fields: {', '.join(finding.differing_fields)}"
        if finding.differing_fields
        else ""
    )
    summary = (
        f"Broken access control ({finding.classification.value}) at {finding.location} "
        f"as principal {finding.principal!r}: {finding.reason}{object_part}.{fields_part}"
    )
    return FindingDTO(
        id=finding_id or uuid4(),
        tenant_id=tenant_id,
        scan_id=scan_id,
        asset_id=asset_id,
        tool_run_id=tool_run_id,
        category=meta.category,
        cwe=list(meta.cwe),
        cvss_v3_vector=_BAC_CVSS_VECTOR,
        cvss_v3_score=_BAC_CVSS_SCORE,
        confidence=finding.confidence,
        status=FindingStatus.NEW,
        evidence_tier=EvidenceTier.CONFIRMED,
        remediation=RemediationDTO(summary=summary[:2000]),
    )


__all__ = ["authorization_finding_to_dto"]
