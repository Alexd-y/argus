"""R-5.1.1 — ``EvidenceTier`` has a single canonical definition.

Guards the wave-1 canonicalization: the enum and its label/description tables
live only in :mod:`src.pipeline.contracts.finding_dto`, and
``src.orchestration.evidence_tier`` re-exports *the very same objects* (not a
value-compatible copy). A future re-introduction of a second ``class
EvidenceTier`` in ``src/`` fails :func:`test_single_class_definition_in_src`.
"""

from __future__ import annotations

import ast
import pathlib

from src.orchestration import evidence_tier as legacy
from src.pipeline.contracts import finding_dto as canonical

# src/ root, derived from a known module's location (robust to this test's path).
_SRC = pathlib.Path(canonical.__file__).resolve().parents[2]


def test_tier_is_the_same_object_from_both_import_paths() -> None:
    assert legacy.EvidenceTier is canonical.EvidenceTier
    assert legacy.EVIDENCE_TIER_LABELS is canonical.EVIDENCE_TIER_LABELS
    assert legacy.EVIDENCE_TIER_DESCRIPTIONS is canonical.EVIDENCE_TIER_DESCRIPTIONS


def test_tier_values_are_one_to_four() -> None:
    tier = canonical.EvidenceTier
    assert tier.INFORMATIONAL == 1
    assert tier.SUSPECTED == 2
    assert tier.CONFIRMED == 3
    assert tier.EXPLOITED == 4
    assert {int(t) for t in tier} == {1, 2, 3, 4}


def test_enum_is_ordered_by_increasing_strength() -> None:
    tier = canonical.EvidenceTier
    ordered = sorted(tier, key=int)
    assert ordered == [
        tier.INFORMATIONAL,
        tier.SUSPECTED,
        tier.CONFIRMED,
        tier.EXPLOITED,
    ]
    # Natural comparisons must reflect strength.
    assert tier.EXPLOITED > tier.CONFIRMED > tier.SUSPECTED > tier.INFORMATIONAL


def test_label_and_description_tables_are_total() -> None:
    for member in canonical.EvidenceTier:
        assert member in canonical.EVIDENCE_TIER_LABELS
        assert member in canonical.EVIDENCE_TIER_DESCRIPTIONS
        assert canonical.EVIDENCE_TIER_LABELS[member].strip()
        assert canonical.EVIDENCE_TIER_DESCRIPTIONS[member].strip()


def test_single_class_definition_in_src() -> None:
    """Exactly one ``class EvidenceTier`` across all of ``src/`` (R-5.1.1)."""
    definitions: list[str] = []
    for path in _SRC.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "EvidenceTier":
                definitions.append(str(path.relative_to(_SRC)).replace("\\", "/"))
    assert definitions == ["pipeline/contracts/finding_dto.py"], definitions
