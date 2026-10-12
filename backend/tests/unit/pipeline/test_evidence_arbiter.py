"""R-5.1.2 / R-5.1.6 — the artifact-driven evidence-tier arbiter.

Covers all four tiers, proves the empty-artifacts floor is INFORMATIONAL
regardless of any other input, and proves a language-model judgement can never
lift the tier (there is no parameter through which one could).
"""

from __future__ import annotations

import inspect
from uuid import uuid4

import pytest
from src.pipeline.contracts.evidence_arbiter import (
    ArbiterVerdict,
    DowngradeReason,
    EvidenceRequirement,
    adjudicate,
)
from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    EvidenceDTO,
    EvidenceKind,
    EvidenceTier,
    FindingCategory,
    FindingDTO,
    FindingStatus,
)


def _ev(kind: EvidenceKind) -> EvidenceDTO:
    return EvidenceDTO(
        id=uuid4(),
        finding_id=uuid4(),
        tool_run_id=uuid4(),
        kind=kind,
        s3_key=f"argus/scan/run/{kind.value}.bin",
        sha256="a" * 64,
    )


def test_empty_artifacts_is_informational() -> None:
    verdict = adjudicate(artifacts=[])
    assert verdict.tier is EvidenceTier.INFORMATIONAL
    assert DowngradeReason.NO_ARTIFACTS in verdict.reasons
    assert verdict.satisfied == frozenset()


@pytest.mark.parametrize("kind", [EvidenceKind.RAW_OUTPUT, EvidenceKind.PARSED, EvidenceKind.DIFF])
def test_non_exchange_artifact_is_suspected(kind: EvidenceKind) -> None:
    # An artifact exists but it is not a saved request/response exchange, so the
    # honest ceiling is SUSPECTED (this is why wave 2 wiring RAW_OUTPUT for every
    # tool run does not silently promote everything to CONFIRMED).
    verdict = adjudicate(artifacts=[_ev(kind)])
    assert verdict.tier is EvidenceTier.SUSPECTED
    assert DowngradeReason.NO_RAW_EXCHANGE in verdict.reasons
    assert EvidenceRequirement.RAW_EXCHANGE not in verdict.satisfied


@pytest.mark.parametrize("kind", [EvidenceKind.HAR, EvidenceKind.PCAP])
def test_raw_exchange_is_confirmed(kind: EvidenceKind) -> None:
    verdict = adjudicate(artifacts=[_ev(kind)])
    assert verdict.tier is EvidenceTier.CONFIRMED
    assert EvidenceRequirement.RAW_EXCHANGE in verdict.satisfied
    assert DowngradeReason.NO_IMPACT_PROOF in verdict.reasons


def test_impact_without_exchange_is_only_suspected() -> None:
    # An effect was observed (OAST callback) but the exchange that caused it was
    # not saved — not enough for CONFIRMED.
    verdict = adjudicate(artifacts=[_ev(EvidenceKind.OAST_CALLBACK)])
    assert verdict.tier is EvidenceTier.SUSPECTED
    assert EvidenceRequirement.IMPACT_PROOF in verdict.satisfied
    assert DowngradeReason.NO_RAW_EXCHANGE in verdict.reasons


@pytest.mark.parametrize("impact", [EvidenceKind.SCREENSHOT, EvidenceKind.OAST_CALLBACK, EvidenceKind.VIDEO])
def test_raw_exchange_plus_impact_is_exploited(impact: EvidenceKind) -> None:
    verdict = adjudicate(artifacts=[_ev(EvidenceKind.HAR), _ev(impact)])
    assert verdict.tier is EvidenceTier.EXPLOITED
    assert verdict.satisfied == {
        EvidenceRequirement.RAW_EXCHANGE,
        EvidenceRequirement.IMPACT_PROOF,
    }


def test_all_four_tiers_are_reachable() -> None:
    tiers = {
        adjudicate(artifacts=[]).tier,
        adjudicate(artifacts=[_ev(EvidenceKind.DIFF)]).tier,
        adjudicate(artifacts=[_ev(EvidenceKind.HAR)]).tier,
        adjudicate(artifacts=[_ev(EvidenceKind.HAR), _ev(EvidenceKind.SCREENSHOT)]).tier,
    }
    assert tiers == set(EvidenceTier)


def test_wave3_gates_are_always_recorded_as_pending() -> None:
    # Even an EXPLOITED verdict honestly records that negative control and
    # repeatability were not checked (those gates land in wave 3).
    for artifacts in (
        [],
        [_ev(EvidenceKind.DIFF)],
        [_ev(EvidenceKind.HAR)],
        [_ev(EvidenceKind.HAR), _ev(EvidenceKind.SCREENSHOT)],
    ):
        verdict = adjudicate(artifacts=artifacts)
        assert DowngradeReason.NEGATIVE_CONTROL_NOT_CHECKED in verdict.reasons
        assert DowngradeReason.REPEATABILITY_NOT_CHECKED in verdict.reasons


def test_verdict_is_frozen() -> None:
    verdict = adjudicate(artifacts=[])
    assert isinstance(verdict, ArbiterVerdict)
    # Frozen dataclass: mutation raises FrozenInstanceError (a subclass of
    # AttributeError).
    with pytest.raises(AttributeError):
        verdict.tier = EvidenceTier.EXPLOITED  # type: ignore[misc]


# --- R-5.1.6: a model judgement can never raise the tier ---------------------


def test_adjudicate_signature_takes_no_model_judgement() -> None:
    params = set(inspect.signature(adjudicate).parameters)
    # Only artifacts (and the forward-compat vuln_class) are inputs. No
    # confidence / opinion / assessment parameter exists at all.
    assert params == {"artifacts", "vuln_class"}
    for banned in ("confidence", "opinion", "assessment", "status", "verdict"):
        assert banned not in params


@pytest.mark.parametrize(
    "confidence",
    [
        ConfidenceLevel.SUSPECTED,
        ConfidenceLevel.LIKELY,
        ConfidenceLevel.CONFIRMED,
        ConfidenceLevel.EXPLOITABLE,
    ],
)
def test_model_opinion_with_zero_artifacts_stays_informational(
    confidence: ConfidenceLevel,
) -> None:
    # A finding the model is maximally confident about, but with no collected
    # artifacts, must still adjudicate to INFORMATIONAL (R-5.1.6).
    finding = FindingDTO(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        asset_id=uuid4(),
        tool_run_id=uuid4(),
        category=FindingCategory.XSS,
        cwe=[79],
        confidence=confidence,
        status=FindingStatus.NEW,
    )
    # The model's opinion is not even an input; the arbiter sees only artifacts.
    verdict = adjudicate(artifacts=[], vuln_class=finding.category.value)
    assert verdict.tier is EvidenceTier.INFORMATIONAL
