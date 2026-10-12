"""Declared conversions between report-layer evidence rows and ``EvidenceDTO``.

R-5.2.1 / R-5.2.4. The chain by which a piece of evidence travels to the report:

    PlaybookEvidenceBundle.to_evidence_dto   collection -> contract (DIFF kind;
        (src.playbooks.evidence)             already defined there)
    EvidenceRow        <-> EvidenceDTO       materialized persisted row
    EvidenceRowData    <-> EvidenceDTO       report read-projection

Each link converts to/from the canonical :class:`EvidenceDTO`. That DTO is a
minimal wave-1 contract, so the fields a layer carries that the DTO does not
model are declared explicitly below (``*_DTO_LOSSY``) with their rationale,
co-located with the conversion — not in prose documentation. The round-trip
test (``tests/unit/reports/test_evidence_dto_links.py``) fills every model field
and asserts each survives unless it is in the declared lossy set, so a field
added later that nobody threads through fails the test instead of vanishing
silently.

Scope (wave 1): this formalizes the report-materialization path plus the
existing collection link. The other Evidence* representations (recon
HttpEvidence / ScreenshotEvidence / ReconEvidenceBundle, QuickEvidenceDTO,
VaEvidenceBundle) are backlog for the chain — see
``docs/develop/TZ-provability-and-report-completeness.md`` §5.2.
"""

from __future__ import annotations

from uuid import UUID

from src.pipeline.contracts.finding_dto import EvidenceDTO, EvidenceKind
from src.reports.data_collector import EvidenceRowData
from src.reports.evidence_materializer import EvidenceRow

# EvidenceRow is the persisted row (1:1 with models.Evidence). It carries
# tenant/scan identity and storage metadata that the minimal EvidenceDTO does
# not model in wave 1; on the way back those come from the caller's context, not
# from the DTO. (The DTO's tool_run_id / kind / sha256 / created_at are likewise
# not on EvidenceRow — they are supplied when building the DTO.)
EVIDENCE_ROW_DTO_LOSSY: frozenset[str] = frozenset(
    {"tenant_id", "scan_id", "content_type", "description"}
)

# EvidenceRowData is a read projection of the evidence table for the report. Its
# human ``description`` is not modeled by the DTO and is re-supplied by context.
EVIDENCE_ROWDATA_DTO_LOSSY: frozenset[str] = frozenset({"description"})


def evidence_row_to_dto(
    row: EvidenceRow,
    *,
    tool_run_id: UUID,
    kind: EvidenceKind,
    sha256: str,
) -> EvidenceDTO:
    """Project an :class:`EvidenceRow` onto the canonical ``EvidenceDTO``."""
    return EvidenceDTO(
        id=UUID(row.id),
        finding_id=UUID(row.finding_id),
        tool_run_id=tool_run_id,
        kind=kind,
        s3_key=row.object_key,
        sha256=sha256,
    )


def evidence_row_from_dto(
    dto: EvidenceDTO,
    *,
    tenant_id: str,
    scan_id: str,
    content_type: str,
    description: str,
) -> EvidenceRow:
    """Rebuild an :class:`EvidenceRow` from a ``EvidenceDTO`` plus row context."""
    return EvidenceRow(
        id=str(dto.id),
        tenant_id=tenant_id,
        scan_id=scan_id,
        finding_id=str(dto.finding_id),
        object_key=dto.s3_key,
        content_type=content_type,
        description=description,
    )


def evidence_rowdata_to_dto(
    row: EvidenceRowData,
    *,
    id: UUID,
    tool_run_id: UUID,
    kind: EvidenceKind,
    sha256: str,
) -> EvidenceDTO:
    """Project an :class:`EvidenceRowData` onto the canonical ``EvidenceDTO``."""
    return EvidenceDTO(
        id=id,
        finding_id=UUID(row.finding_id),
        tool_run_id=tool_run_id,
        kind=kind,
        s3_key=row.object_key,
        sha256=sha256,
    )


def evidence_rowdata_from_dto(
    dto: EvidenceDTO,
    *,
    description: str | None,
) -> EvidenceRowData:
    """Rebuild an :class:`EvidenceRowData` from a ``EvidenceDTO`` plus context."""
    return EvidenceRowData(
        finding_id=str(dto.finding_id),
        object_key=dto.s3_key,
        description=description,
    )


__all__ = [
    "EVIDENCE_ROWDATA_DTO_LOSSY",
    "EVIDENCE_ROW_DTO_LOSSY",
    "evidence_row_from_dto",
    "evidence_row_to_dto",
    "evidence_rowdata_from_dto",
    "evidence_rowdata_to_dto",
]
