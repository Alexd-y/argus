"""R-5.2.1 / R-5.2.4 — layer<->EvidenceDTO conversions lose no field silently.

Introspection-based (no hypothesis dependency): fill every model field with a
distinct, type-valid value, convert to EvidenceDTO and back, and assert every
field survives except those in the conversion's declared lossy set. A field
added later that is not threaded through fails this test instead of vanishing.
"""

from __future__ import annotations

import ast
import dataclasses
import pathlib
from uuid import NAMESPACE_URL, uuid4, uuid5

from src.pipeline.contracts.finding_dto import EvidenceKind
from src.reports.data_collector import EvidenceRowData
from src.reports.evidence_dto_links import (
    EVIDENCE_ROW_DTO_LOSSY,
    EVIDENCE_ROWDATA_DTO_LOSSY,
    evidence_row_from_dto,
    evidence_row_to_dto,
    evidence_rowdata_from_dto,
    evidence_rowdata_to_dto,
)
from src.reports.evidence_materializer import EvidenceRow

_SENTINEL = "<lost>"


def _valid_value(name: str) -> str:
    """A distinct, type-valid filler for a (string) field, keyed by name."""
    if name in ("id", "finding_id"):
        return str(uuid5(NAMESPACE_URL, name))  # valid, distinct UUID string
    if name in ("object_key", "s3_key"):
        return "argus/scan/run/poc.json"  # matches EvidenceDTO's s3_key pattern
    return f"val-{name}"


def _filled_evidence_row() -> EvidenceRow:
    return EvidenceRow(**{f.name: _valid_value(f.name) for f in dataclasses.fields(EvidenceRow)})


def _filled_evidence_rowdata() -> EvidenceRowData:
    return EvidenceRowData(**{name: _valid_value(name) for name in EvidenceRowData.model_fields})


def test_evidence_row_roundtrip_only_loses_declared_fields() -> None:
    row = _filled_evidence_row()
    dto = evidence_row_to_dto(row, tool_run_id=uuid4(), kind=EvidenceKind.RAW_OUTPUT, sha256="a" * 64)

    # With no context re-supplied, exactly the declared lossy fields differ.
    rebuilt = evidence_row_from_dto(
        dto, tenant_id=_SENTINEL, scan_id=_SENTINEL, content_type=_SENTINEL, description=_SENTINEL
    )
    lost = {
        f.name
        for f in dataclasses.fields(EvidenceRow)
        if getattr(rebuilt, f.name) != getattr(row, f.name)
    }
    assert lost == EVIDENCE_ROW_DTO_LOSSY

    # With context re-supplied, the round-trip is exact — nothing dropped.
    exact = evidence_row_from_dto(
        dto,
        tenant_id=row.tenant_id,
        scan_id=row.scan_id,
        content_type=row.content_type,
        description=row.description,
    )
    assert exact == row


def test_evidence_rowdata_roundtrip_only_loses_declared_fields() -> None:
    row = _filled_evidence_rowdata()
    dto = evidence_rowdata_to_dto(
        row, id=uuid4(), tool_run_id=uuid4(), kind=EvidenceKind.RAW_OUTPUT, sha256="a" * 64
    )

    rebuilt = evidence_rowdata_from_dto(dto, description=_SENTINEL)
    lost = {
        name
        for name in EvidenceRowData.model_fields
        if getattr(rebuilt, name) != getattr(row, name)
    }
    assert lost == EVIDENCE_ROWDATA_DTO_LOSSY

    exact = evidence_rowdata_from_dto(dto, description=row.description)
    assert exact == row


def test_dto_core_fields_survive_both_links() -> None:
    # finding_id / s3_key (object_key) are carried by the DTO and must be exact.
    row = _filled_evidence_row()
    dto = evidence_row_to_dto(row, tool_run_id=uuid4(), kind=EvidenceKind.HAR, sha256="b" * 64)
    assert str(dto.finding_id) == row.finding_id
    assert dto.s3_key == row.object_key
    assert str(dto.id) == row.id


def test_playbook_bundle_link_exists() -> None:
    # The collection->contract link (DIFF kind) is part of the declared chain.
    from src.playbooks.evidence import PlaybookEvidenceBundle

    assert hasattr(PlaybookEvidenceBundle, "to_evidence_dto")


def test_no_duplicate_evidence_bundle_class_definitions() -> None:
    """R-5.2.1 acceptance: no two `class EvidenceBundle` definitions remain."""
    import src.reports.evidence_materializer as _anchor

    src_dir = pathlib.Path(_anchor.__file__).resolve().parents[1]
    hits: list[str] = []
    for path in src_dir.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "EvidenceBundle":
                hits.append(str(path.relative_to(src_dir)))
    assert hits == [], f"duplicate `class EvidenceBundle` definitions remain: {hits}"
