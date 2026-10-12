"""R-5.1.3 / R-5.1.5 — derived scales are total, consistent, and one-way.

The canonical tier is the single source of truth; confidence / validation /
evidence-quality / evidence-gate are derived from it by total, monotonic
functions. This also pins the string-alias consolidation: the modules that used
to re-declare the scale import the one shared definition.
"""

from __future__ import annotations

import ast
import importlib
import pathlib

from src.pipeline.contracts import evidence_scales as scales
from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    EvidenceTier,
    ValidationState,
)

_TIERS_ASCENDING = [
    EvidenceTier.INFORMATIONAL,
    EvidenceTier.SUSPECTED,
    EvidenceTier.CONFIRMED,
    EvidenceTier.EXPLOITED,
]

_CONFIDENCE_RANK = {
    ConfidenceLevel.SUSPECTED: 0,
    ConfidenceLevel.LIKELY: 1,
    ConfidenceLevel.CONFIRMED: 2,
    ConfidenceLevel.EXPLOITABLE: 3,
}
_VALIDATION_RANK = {
    ValidationState.REJECTED: -1,
    ValidationState.INCONCLUSIVE: 0,
    ValidationState.SUSPECTED: 1,
    ValidationState.CONFIRMED: 2,
}
_QUALITY_RANK = {"none": 0, "weak": 1, "moderate": 2, "strong": 3}
_GATE_RANK = {"inconclusive": 0, "candidate": 1, "observed": 2, "validated": 3}


def test_every_derivation_is_total() -> None:
    for tier in EvidenceTier:
        assert isinstance(scales.confidence_for_tier(tier), ConfidenceLevel)
        assert isinstance(scales.validation_for_tier(tier), ValidationState)
        assert scales.evidence_quality_for_tier(tier) in _QUALITY_RANK
        assert scales.evidence_gate_for_tier(tier) in _GATE_RANK


def test_derivations_are_monotonic_in_tier() -> None:
    # A stronger tier must never yield a weaker derived value.
    def ranks(fn, rank):
        return [rank[fn(t)] for t in _TIERS_ASCENDING]

    for seq in (
        ranks(scales.confidence_for_tier, _CONFIDENCE_RANK),
        ranks(scales.validation_for_tier, _VALIDATION_RANK),
        ranks(scales.evidence_quality_for_tier, _QUALITY_RANK),
        ranks(scales.evidence_gate_for_tier, _GATE_RANK),
    ):
        assert seq == sorted(seq), seq


def test_no_reverse_mapping_is_exported() -> None:
    # Only tier -> scale directions exist (R-5.1.3: "Обратного отображения нет").
    for name in dir(scales):
        assert not name.endswith("_to_tier")
        assert "tier_for_" not in name


def test_string_alias_is_consolidated() -> None:
    # Cheap sanity: the exported names resolve to the shared alias. NOTE: because
    # ``typing.Literal`` interns identical-argument Literals, ``is`` alone cannot
    # detect a same-order re-declared copy — that anti-pattern is caught by the
    # AST guard below, not here.
    from src.api import schemas as api_schemas
    from src.recon.vulnerability_analysis.active_scan import (
        injection_findings_normalize as inj,
    )
    from src.reports import evidence_gates, report_quality_gate
    from src.schemas.vulnerability_analysis import schemas as va_schemas

    assert report_quality_gate.EvidenceQuality is scales.EvidenceQualityName
    assert va_schemas.EvidenceQuality is scales.EvidenceQualityName
    assert api_schemas.FindingEvidenceQualityLiteral is scales.EvidenceQualityName
    assert inj.EvidenceQualityName is scales.EvidenceQualityName
    assert report_quality_gate.EvidenceClassification is scales.EvidenceGateName
    assert api_schemas.FindingEvidenceClassificationLiteral is scales.EvidenceGateName
    assert evidence_gates.EvidenceGate is scales.EvidenceGateName


# --- Robust consolidation guard (R-5.1.3) ------------------------------------
#
# ``typing.Literal['none','weak','moderate','strong']`` interns to the SAME object
# wherever it is written, so an ``is`` check cannot catch a re-introduced local
# copy. This AST guard instead forbids any module below from re-declaring the
# scale as a local ``Literal[...]`` and requires it to import the shared alias.
_QUALITY_MEMBERS = frozenset({"none", "weak", "moderate", "strong"})
_GATE_MEMBERS = frozenset({"validated", "observed", "candidate", "inconclusive"})

#: consumer module -> alias names it must import from evidence_scales.
_CONSUMERS: dict[str, frozenset[str]] = {
    "src.reports.report_quality_gate": frozenset({"EvidenceQualityName", "EvidenceGateName"}),
    "src.schemas.vulnerability_analysis.schemas": frozenset({"EvidenceQualityName"}),
    "src.api.schemas": frozenset({"EvidenceQualityName", "EvidenceGateName"}),
    "src.recon.vulnerability_analysis.active_scan.injection_findings_normalize": frozenset(
        {"EvidenceQualityName"}
    ),
    "src.reports.evidence_gates": frozenset({"EvidenceGateName"}),
}


def _literal_members(subscript: ast.Subscript) -> frozenset[str]:
    sl = subscript.slice
    elts = sl.elts if isinstance(sl, ast.Tuple) else [sl]
    return frozenset(e.value for e in elts if isinstance(e, ast.Constant) and isinstance(e.value, str))


def test_no_local_literal_copies_of_the_scale() -> None:
    for mod_path, required in _CONSUMERS.items():
        module = importlib.import_module(mod_path)
        tree = ast.parse(pathlib.Path(module.__file__).read_text(encoding="utf-8"))

        for node in ast.walk(tree):
            value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
            if (
                isinstance(value, ast.Subscript)
                and isinstance(value.value, ast.Name)
                and value.value.id == "Literal"
            ):
                members = _literal_members(value)
                assert members != _QUALITY_MEMBERS, (
                    f"{mod_path}:{node.lineno} re-declares the evidence-quality scale as a local "
                    "Literal; import EvidenceQualityName from evidence_scales instead (R-5.1.3)."
                )
                assert members != _GATE_MEMBERS, (
                    f"{mod_path}:{node.lineno} re-declares the evidence-gate scale as a local "
                    "Literal; import EvidenceGateName from evidence_scales instead (R-5.1.3)."
                )

        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module == "src.pipeline.contracts.evidence_scales"
            for alias in node.names
        }
        assert required <= imported, (
            f"{mod_path} must import {set(required)} from evidence_scales; got {imported}"
        )


def test_informational_tier_floors() -> None:
    assert scales.confidence_for_tier(EvidenceTier.INFORMATIONAL) is ConfidenceLevel.SUSPECTED
    assert scales.validation_for_tier(EvidenceTier.INFORMATIONAL) is ValidationState.INCONCLUSIVE
    assert scales.evidence_quality_for_tier(EvidenceTier.INFORMATIONAL) == "weak"
    assert scales.evidence_gate_for_tier(EvidenceTier.INFORMATIONAL) == "candidate"
