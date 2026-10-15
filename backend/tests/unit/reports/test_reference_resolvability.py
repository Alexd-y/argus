"""Wave 4 / Stage 3 — reference resolvability (R-6.2.2 / R-6.2.3).

A ``[CL-…]`` / ``[E-…]`` marker is a promise the reader can trace the claim to a
specific finding/evidence row. These prove the gate now *resolves* each marker against
the report's minted labels — a dangling reference is a BLOCK, not cosmetic — and that
the reference index gained the reverse lookup that makes it possible.
"""

from __future__ import annotations

from src.reports.evidence_references import build_evidence_reference_index
from src.reports.prose_gate import (
    ProseSeverity,
    check_output_consistency,
    extract_reference_labels,
    unresolvable_references,
)


def _index():
    return build_evidence_reference_index(
        [
            {"finding_id": "F-1", "evidence_ids": ["ev-a", "ev-b"]},
            {"finding_id": "F-2", "evidence_ids": ["ev-c"]},
        ]
    )


def test_index_mints_labels_and_reverse_resolves() -> None:
    idx = _index()
    labels = idx.known_labels()
    assert "CL-0001" in labels and "CL-0002" in labels
    assert "E-0001" in labels and "E-0003" in labels
    assert idx.resolve_label("CL-0001") == "F-1"
    assert idx.resolve_label("E-0003") == "ev-c"
    assert idx.resolve_label("E-9999") is None
    assert idx.resolve_label("cl-0002") == "F-2"  # case-insensitive


def test_extract_reference_labels_handles_multi_label_markers() -> None:
    text = "The flaw [CL-0001 / E-0002] is confirmed; see also [E-0003]."
    assert extract_reference_labels(text) == ["CL-0001", "E-0002", "E-0003"]


def test_unresolvable_references_returns_only_dangling() -> None:
    known = {"CL-0001", "E-0002"}
    text = "ok [CL-0001]; dangling [E-9999]; also dangling [CL-4242]."
    assert unresolvable_references(text, known) == ["E-9999", "CL-4242"]
    # Everything resolves → empty.
    assert unresolvable_references("fine [CL-0001] [E-0002]", known) == []


def test_output_consistency_blocks_dangling_reference() -> None:
    idx = _index()
    text = "The injection [E-9999] was exploited."  # E-9999 not minted
    violations = check_output_consistency(
        text, known_reference_labels=idx.known_labels(), section="executive_summary"
    )
    dangling = [v for v in violations if v.rule == "unresolvable_reference"]
    assert len(dangling) == 1
    assert dangling[0].severity == ProseSeverity.BLOCK


def test_output_consistency_accepts_resolvable_reference() -> None:
    idx = _index()
    text = "The injection [E-0001] against [CL-0001] was exploited."
    violations = check_output_consistency(text, known_reference_labels=idx.known_labels())
    assert [v for v in violations if v.rule == "unresolvable_reference"] == []


def test_resolvability_check_is_opt_in() -> None:
    # Without known_reference_labels the check does not run (backward compatible).
    text = "Dangling [E-9999] everywhere."
    violations = check_output_consistency(text)
    assert [v for v in violations if v.rule == "unresolvable_reference"] == []
