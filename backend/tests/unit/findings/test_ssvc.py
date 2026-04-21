"""ARG-044 — full CISA SSVC v2.1 (deployer) decision tree coverage.

This file replaces the Cycle 1 SSVC tests after the formal v2.1 matrix
landed in :mod:`src.findings.ssvc`. The v2.1 deployer tree drops the
``Exposure`` axis and uses 4 axes (``Exploitation`` × ``Automatable`` ×
``TechnicalImpact`` × ``MissionWellbeing``) for a total of ``3 × 2 × 2 ×
3 = 36`` leaves. Every leaf in :data:`DECISION_MATRIX` is exercised here
with the exact reference outcome so a future matrix mutation cannot
silently regress prioritisation.

Tests:

1. **Per-leaf assertions** — one parametrised test per (Exploitation,
   Automatable, TechnicalImpact, MissionWellbeing) tuple.
2. **Totality** — :func:`evaluate_ssvc` returns a valid
   :class:`SSVCDecision` for every input combination.
3. **Monotonicity** — increasing severity along any axis never lowers
   the decision (Track < Track* < Attend < Act).
4. **Outcome surjectivity** — every outcome appears at least once.
5. ``derive_ssvc_inputs`` projects FindingDTO → SsvcInputs correctly.
6. Legacy ``ssvc_decide`` shim still routes through the v2.1 matrix.
"""

from __future__ import annotations

from collections.abc import Callable
from itertools import product

import pytest

from src.findings.ssvc import (
    DECISION_MATRIX,
    Automatable,
    Exploitation,
    MissionWellbeing,
    SSVCDecision,
    SSVCExploitation,
    SSVCExposure,
    SSVCMissionImpact,
    SSVCTechnicalImpact,
    SsvcInputs,
    TechnicalImpact,
    derive_ssvc_inputs,
    evaluate_ssvc,
    ssvc_decide,
)
from src.pipeline.contracts.finding_dto import FindingCategory, FindingDTO

# ---------------------------------------------------------------------------
# Canonical reference matrix (verbatim CISA SSVC v2.1 deployer tree)
# ---------------------------------------------------------------------------

# Mapped one-to-one with src/findings/ssvc.py::_RAW_MATRIX. Keeping a copy
# here makes regressions visible as test-file diffs (rather than silently
# accepting whatever the production module decides to return).
_REFERENCE_MATRIX: dict[
    tuple[Exploitation, Automatable, TechnicalImpact, MissionWellbeing],
    SSVCDecision,
] = {
    # === Exploitation: NONE ===
    (Exploitation.NONE, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.HIGH): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.HIGH): SSVCDecision.TRACK_STAR,
    (Exploitation.NONE, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.HIGH): SSVCDecision.ATTEND,
    (Exploitation.NONE, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK_STAR,
    (Exploitation.NONE, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.HIGH): SSVCDecision.ATTEND,
    # === Exploitation: POC ===
    (Exploitation.POC, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.POC, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK,
    (Exploitation.POC, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.HIGH): SSVCDecision.TRACK_STAR,
    (Exploitation.POC, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.POC, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK_STAR,
    (Exploitation.POC, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.HIGH): SSVCDecision.ATTEND,
    (Exploitation.POC, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.POC, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK_STAR,
    (Exploitation.POC, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.HIGH): SSVCDecision.ATTEND,
    (Exploitation.POC, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.LOW): SSVCDecision.TRACK_STAR,
    (Exploitation.POC, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.MEDIUM): SSVCDecision.ATTEND,
    (Exploitation.POC, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.HIGH): SSVCDecision.ACT,
    # === Exploitation: ACTIVE ===
    (Exploitation.ACTIVE, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.ACTIVE, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK_STAR,
    (Exploitation.ACTIVE, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.HIGH): SSVCDecision.ATTEND,
    (Exploitation.ACTIVE, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.LOW): SSVCDecision.TRACK_STAR,
    (Exploitation.ACTIVE, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.MEDIUM): SSVCDecision.ATTEND,
    (Exploitation.ACTIVE, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.HIGH): SSVCDecision.ACT,
    (Exploitation.ACTIVE, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.LOW): SSVCDecision.ATTEND,
    (Exploitation.ACTIVE, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.MEDIUM): SSVCDecision.ATTEND,
    (Exploitation.ACTIVE, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.HIGH): SSVCDecision.ACT,
    (Exploitation.ACTIVE, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.LOW): SSVCDecision.ATTEND,
    (Exploitation.ACTIVE, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.MEDIUM): SSVCDecision.ACT,
    (Exploitation.ACTIVE, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.HIGH): SSVCDecision.ACT,
}


def _id(e: Exploitation, a: Automatable, t: TechnicalImpact, m: MissionWellbeing) -> str:
    return f"{e.value}-{a.value}-{t.value}-{m.value}"


# ---------------------------------------------------------------------------
# 1. Per-leaf assertions — one parametrised test per matrix entry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exploitation", "automatable", "technical_impact", "mission_wellbeing", "expected"),
    [
        (e, a, t, m, _REFERENCE_MATRIX[(e, a, t, m)])
        for e, a, t, m in product(
            Exploitation, Automatable, TechnicalImpact, MissionWellbeing
        )
    ],
    ids=[
        _id(e, a, t, m)
        for e, a, t, m in product(
            Exploitation, Automatable, TechnicalImpact, MissionWellbeing
        )
    ],
)
def test_decision_matrix_leaf(
    exploitation: Exploitation,
    automatable: Automatable,
    technical_impact: TechnicalImpact,
    mission_wellbeing: MissionWellbeing,
    expected: SSVCDecision,
) -> None:
    """Every leaf of the 36-cell SSVC v2.1 matrix returns its reference outcome."""
    decision = evaluate_ssvc(
        exploitation=exploitation,
        automatable=automatable,
        technical_impact=technical_impact,
        mission_wellbeing=mission_wellbeing,
    )
    assert decision is expected


def test_decision_matrix_size() -> None:
    """Sanity check: the production matrix has the documented 36 leaves."""
    assert len(DECISION_MATRIX) == 36
    assert set(DECISION_MATRIX) == set(_REFERENCE_MATRIX)


# ---------------------------------------------------------------------------
# 2. Totality
# ---------------------------------------------------------------------------


def test_evaluate_ssvc_is_total() -> None:
    """Every closed-enum input combination returns a valid SSVCDecision."""
    for e, a, t, m in product(
        Exploitation, Automatable, TechnicalImpact, MissionWellbeing
    ):
        out = evaluate_ssvc(
            exploitation=e,
            automatable=a,
            technical_impact=t,
            mission_wellbeing=m,
        )
        assert isinstance(out, SSVCDecision)


# ---------------------------------------------------------------------------
# 3. Monotonicity along each axis
# ---------------------------------------------------------------------------


_SEVERITY_RANK: dict[SSVCDecision, int] = {
    SSVCDecision.TRACK: 0,
    SSVCDecision.TRACK_STAR: 1,
    SSVCDecision.ATTEND: 2,
    SSVCDecision.ACT: 3,
}


def test_monotonic_in_exploitation() -> None:
    """ACTIVE >= POC >= NONE for every (auto, tech, mission) profile."""
    for a, t, m in product(Automatable, TechnicalImpact, MissionWellbeing):
        none_dec = evaluate_ssvc(
            exploitation=Exploitation.NONE,
            automatable=a,
            technical_impact=t,
            mission_wellbeing=m,
        )
        poc_dec = evaluate_ssvc(
            exploitation=Exploitation.POC,
            automatable=a,
            technical_impact=t,
            mission_wellbeing=m,
        )
        active_dec = evaluate_ssvc(
            exploitation=Exploitation.ACTIVE,
            automatable=a,
            technical_impact=t,
            mission_wellbeing=m,
        )
        assert _SEVERITY_RANK[poc_dec] >= _SEVERITY_RANK[none_dec]
        assert _SEVERITY_RANK[active_dec] >= _SEVERITY_RANK[poc_dec]


def test_monotonic_in_automatable() -> None:
    """YES >= NO for every (exploitation, tech, mission) profile."""
    for e, t, m in product(Exploitation, TechnicalImpact, MissionWellbeing):
        no_dec = evaluate_ssvc(
            exploitation=e,
            automatable=Automatable.NO,
            technical_impact=t,
            mission_wellbeing=m,
        )
        yes_dec = evaluate_ssvc(
            exploitation=e,
            automatable=Automatable.YES,
            technical_impact=t,
            mission_wellbeing=m,
        )
        assert _SEVERITY_RANK[yes_dec] >= _SEVERITY_RANK[no_dec]


def test_monotonic_in_technical_impact() -> None:
    """TOTAL >= PARTIAL for every (exploitation, auto, mission) profile."""
    for e, a, m in product(Exploitation, Automatable, MissionWellbeing):
        partial_dec = evaluate_ssvc(
            exploitation=e,
            automatable=a,
            technical_impact=TechnicalImpact.PARTIAL,
            mission_wellbeing=m,
        )
        total_dec = evaluate_ssvc(
            exploitation=e,
            automatable=a,
            technical_impact=TechnicalImpact.TOTAL,
            mission_wellbeing=m,
        )
        assert _SEVERITY_RANK[total_dec] >= _SEVERITY_RANK[partial_dec]


def test_monotonic_in_mission_wellbeing() -> None:
    """HIGH >= MEDIUM >= LOW for every (exploitation, auto, tech) profile."""
    for e, a, t in product(Exploitation, Automatable, TechnicalImpact):
        low_dec = evaluate_ssvc(
            exploitation=e,
            automatable=a,
            technical_impact=t,
            mission_wellbeing=MissionWellbeing.LOW,
        )
        med_dec = evaluate_ssvc(
            exploitation=e,
            automatable=a,
            technical_impact=t,
            mission_wellbeing=MissionWellbeing.MEDIUM,
        )
        high_dec = evaluate_ssvc(
            exploitation=e,
            automatable=a,
            technical_impact=t,
            mission_wellbeing=MissionWellbeing.HIGH,
        )
        assert _SEVERITY_RANK[med_dec] >= _SEVERITY_RANK[low_dec]
        assert _SEVERITY_RANK[high_dec] >= _SEVERITY_RANK[med_dec]


# ---------------------------------------------------------------------------
# 4. Outcome surjectivity
# ---------------------------------------------------------------------------


def test_every_outcome_is_reachable() -> None:
    """Every SSVCDecision label appears at least once in the matrix."""
    seen: set[SSVCDecision] = set()
    for e, a, t, m in product(
        Exploitation, Automatable, TechnicalImpact, MissionWellbeing
    ):
        seen.add(
            evaluate_ssvc(
                exploitation=e,
                automatable=a,
                technical_impact=t,
                mission_wellbeing=m,
            )
        )
    assert seen == set(SSVCDecision)


# ---------------------------------------------------------------------------
# 5. derive_ssvc_inputs — projection from FindingDTO + intel signals
# ---------------------------------------------------------------------------


def test_derive_kev_listed_marks_active(
    make_finding: Callable[..., FindingDTO],
) -> None:
    finding = make_finding(category=FindingCategory.RCE, cvss_v3_score=9.0)
    inputs = derive_ssvc_inputs(
        finding,
        kev_listed=True,
        public_exploit_known=False,
        mission_wellbeing=MissionWellbeing.HIGH,
    )
    assert inputs.exploitation is Exploitation.ACTIVE
    assert inputs.automatable is Automatable.YES  # RCE ∈ automatable set
    assert inputs.technical_impact is TechnicalImpact.TOTAL  # 9.0 >= 7.0
    assert inputs.mission_wellbeing is MissionWellbeing.HIGH


def test_derive_public_exploit_known_marks_poc(
    make_finding: Callable[..., FindingDTO],
) -> None:
    finding = make_finding(category=FindingCategory.MISCONFIG, cvss_v3_score=5.0)
    inputs = derive_ssvc_inputs(
        finding,
        kev_listed=False,
        public_exploit_known=True,
    )
    assert inputs.exploitation is Exploitation.POC
    assert inputs.automatable is Automatable.NO
    assert inputs.technical_impact is TechnicalImpact.PARTIAL
    # Default Mission Wellbeing is MEDIUM when the caller does not supply one.
    assert inputs.mission_wellbeing is MissionWellbeing.MEDIUM


def test_derive_no_signal_marks_none(
    make_finding: Callable[..., FindingDTO],
) -> None:
    finding = make_finding(category=FindingCategory.INFO, cvss_v3_score=0.5)
    inputs = derive_ssvc_inputs(
        finding,
        kev_listed=False,
        public_exploit_known=False,
        mission_wellbeing=MissionWellbeing.LOW,
    )
    assert inputs.exploitation is Exploitation.NONE
    assert inputs.technical_impact is TechnicalImpact.PARTIAL
    assert inputs.mission_wellbeing is MissionWellbeing.LOW


@pytest.mark.parametrize(
    "category",
    [
        FindingCategory.RCE,
        FindingCategory.SQLI,
        FindingCategory.SSRF,
        FindingCategory.LFI,
        FindingCategory.XXE,
    ],
)
def test_derive_marks_known_automatable_categories(
    make_finding: Callable[..., FindingDTO], category: FindingCategory
) -> None:
    finding = make_finding(category=category, cvss_v3_score=4.0)
    inputs = derive_ssvc_inputs(
        finding,
        kev_listed=False,
        public_exploit_known=False,
    )
    assert inputs.automatable is Automatable.YES


@pytest.mark.parametrize(
    "category",
    [FindingCategory.MISCONFIG, FindingCategory.INFO, FindingCategory.CRYPTO],
)
def test_derive_marks_non_automatable_categories(
    make_finding: Callable[..., FindingDTO], category: FindingCategory
) -> None:
    finding = make_finding(category=category, cvss_v3_score=4.0)
    inputs = derive_ssvc_inputs(
        finding,
        kev_listed=False,
        public_exploit_known=False,
    )
    assert inputs.automatable is Automatable.NO


def test_derive_kev_overrides_public_exploit(
    make_finding: Callable[..., FindingDTO],
) -> None:
    """KEV is the strongest signal — must dominate ``public_exploit_known``."""
    finding = make_finding(category=FindingCategory.RCE, cvss_v3_score=9.0)
    inputs = derive_ssvc_inputs(
        finding,
        kev_listed=True,
        public_exploit_known=True,
    )
    assert inputs.exploitation is Exploitation.ACTIVE


def test_ssvc_inputs_dataclass_is_frozen() -> None:
    """SsvcInputs must be immutable — protects deterministic ranking."""
    inp = SsvcInputs(
        exploitation=Exploitation.NONE,
        automatable=Automatable.NO,
        technical_impact=TechnicalImpact.PARTIAL,
        mission_wellbeing=MissionWellbeing.LOW,
    )
    with pytest.raises(Exception):
        inp.exploitation = Exploitation.ACTIVE  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 6. Legacy ssvc_decide shim still routes through v2.1
# ---------------------------------------------------------------------------


def test_legacy_ssvc_decide_routes_to_v21_matrix() -> None:
    """The 5-axis legacy API delegates to evaluate_ssvc and ignores Exposure."""
    a = ssvc_decide(
        exploitation=SSVCExploitation.ACTIVE,
        exposure=SSVCExposure.OPEN,
        automatable=True,
        technical_impact=SSVCTechnicalImpact.TOTAL,
        mission_well_being=SSVCMissionImpact.HIGH,
    )
    b = ssvc_decide(
        exploitation=SSVCExploitation.ACTIVE,
        exposure=SSVCExposure.SMALL,
        automatable=True,
        technical_impact=SSVCTechnicalImpact.TOTAL,
        mission_well_being=SSVCMissionImpact.HIGH,
    )
    expected = evaluate_ssvc(
        exploitation=Exploitation.ACTIVE,
        automatable=Automatable.YES,
        technical_impact=TechnicalImpact.TOTAL,
        mission_wellbeing=MissionWellbeing.HIGH,
    )
    assert a is expected
    assert b is expected  # Exposure is now a no-op argument.


def test_legacy_enum_aliases_match_v21() -> None:
    """SSVC* legacy enum aliases must point at the v2.1 enums."""
    assert SSVCExploitation is Exploitation
    assert SSVCTechnicalImpact is TechnicalImpact
    assert SSVCMissionImpact is MissionWellbeing


@pytest.mark.parametrize("exp", list(SSVCExploitation))
def test_keyword_only_call_required(exp: SSVCExploitation) -> None:
    """ssvc_decide is keyword-only; positional args must raise TypeError."""
    with pytest.raises(TypeError):
        ssvc_decide(  # type: ignore[call-arg, misc]
            exp,
            SSVCExposure.OPEN,
            True,
            SSVCTechnicalImpact.TOTAL,
            SSVCMissionImpact.HIGH,
        )


def test_decision_matrix_is_immutable() -> None:
    """DECISION_MATRIX is exposed as a MappingProxy — must reject mutations."""
    with pytest.raises(TypeError):
        DECISION_MATRIX[  # type: ignore[index]
            (
                Exploitation.NONE,
                Automatable.NO,
                TechnicalImpact.PARTIAL,
                MissionWellbeing.LOW,
            )
        ] = SSVCDecision.ACT
