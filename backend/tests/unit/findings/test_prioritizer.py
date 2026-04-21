"""Unit tests for :mod:`src.findings.prioritizer`."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from dataclasses import dataclass
from typing import Optional
from uuid import uuid4

from src.findings.prioritizer import (
    FindingPrioritizer,
    Prioritizer,
    PriorityComponent,
    PriorityScore,
    PriorityTier,
)
from src.pipeline.contracts.finding_dto import FindingCategory, FindingDTO, SSVCDecision


@pytest.fixture
def prioritizer() -> Prioritizer:
    return Prioritizer()


# ---------------------------------------------------------------------------
# Tier mapping
# ---------------------------------------------------------------------------


def test_p0_critical_when_all_signals_max(
    prioritizer: Prioritizer, make_finding: Callable[..., FindingDTO]
) -> None:
    finding = make_finding(
        category=FindingCategory.RCE,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_v3_score=9.8,
        epss_score=0.95,
        kev_listed=True,
        ssvc_decision=SSVCDecision.ACT,
    )
    score = prioritizer.prioritize(finding)
    assert score.tier is PriorityTier.P0_CRITICAL
    assert score.score >= 90.0
    assert score.score <= 100.0


def test_p4_info_when_all_signals_zero(
    prioritizer: Prioritizer, make_finding: Callable[..., FindingDTO]
) -> None:
    finding = make_finding(
        cvss_v3_score=0.0,
        epss_score=None,
        kev_listed=False,
        ssvc_decision=SSVCDecision.TRACK,
    )
    score = prioritizer.prioritize(finding)
    assert score.tier is PriorityTier.P4_INFO
    assert score.score == pytest.approx(3.75, abs=0.01)


def test_p3_low_when_track_only(
    prioritizer: Prioritizer, make_finding: Callable[..., FindingDTO]
) -> None:
    finding = make_finding(
        category=FindingCategory.MISCONFIG,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        cvss_v3_score=5.4,
        epss_score=None,
        kev_listed=False,
        ssvc_decision=SSVCDecision.TRACK,
    )
    score = prioritizer.prioritize(finding)
    assert score.tier is PriorityTier.P3_LOW
    assert 20.0 <= score.score < 40.0


def test_p4_when_low_cvss_and_track_only(
    prioritizer: Prioritizer, make_finding: Callable[..., FindingDTO]
) -> None:
    finding = make_finding(
        category=FindingCategory.MISCONFIG,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
        cvss_v3_score=3.1,
        epss_score=None,
        kev_listed=False,
        ssvc_decision=SSVCDecision.TRACK,
    )
    score = prioritizer.prioritize(finding)
    assert score.tier is PriorityTier.P4_INFO


def test_p1_high_when_kev_and_high_cvss(
    prioritizer: Prioritizer, make_finding: Callable[..., FindingDTO]
) -> None:
    finding = make_finding(
        category=FindingCategory.RCE,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_v3_score=8.2,
        epss_score=0.5,
        kev_listed=True,
        ssvc_decision=SSVCDecision.ATTEND,
    )
    score = prioritizer.prioritize(finding)
    assert score.tier in {PriorityTier.P1_HIGH, PriorityTier.P0_CRITICAL}


def test_breakdown_sums_to_score(
    prioritizer: Prioritizer, make_finding: Callable[..., FindingDTO]
) -> None:
    finding = make_finding(
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_v3_score=9.8,
        epss_score=0.95,
        kev_listed=True,
        ssvc_decision=SSVCDecision.ACT,
    )
    score = prioritizer.prioritize(finding)
    total = sum(score.breakdown.values())
    assert score.score == pytest.approx(min(total, 100.0), abs=0.05)


def test_idempotent(
    prioritizer: Prioritizer, make_finding: Callable[..., FindingDTO]
) -> None:
    finding = make_finding(
        cvss_v3_score=5.5,
        epss_score=0.42,
        kev_listed=False,
        ssvc_decision=SSVCDecision.TRACK_STAR,
    )
    a = prioritizer.prioritize(finding)
    b = prioritizer.prioritize(finding)
    assert a == b


# ---------------------------------------------------------------------------
# Component-level edge cases
# ---------------------------------------------------------------------------


def test_breakdown_keys_complete(
    prioritizer: Prioritizer, make_finding: Callable[..., FindingDTO]
) -> None:
    score = prioritizer.prioritize(make_finding())
    assert set(score.breakdown.keys()) == {
        PriorityComponent.CVSS,
        PriorityComponent.EPSS,
        PriorityComponent.KEV,
        PriorityComponent.SSVC,
    }


def test_breakdown_components_within_caps(
    prioritizer: Prioritizer, make_finding: Callable[..., FindingDTO]
) -> None:
    finding = make_finding(
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_v3_score=10.0,
        epss_score=1.0,
        kev_listed=True,
        ssvc_decision=SSVCDecision.ACT,
    )
    score = prioritizer.prioritize(finding)
    assert score.breakdown[PriorityComponent.CVSS] == pytest.approx(40.0, abs=0.01)
    assert score.breakdown[PriorityComponent.EPSS] == pytest.approx(25.0, abs=0.01)
    assert score.breakdown[PriorityComponent.KEV] == pytest.approx(20.0, abs=0.01)
    assert score.breakdown[PriorityComponent.SSVC] == pytest.approx(15.0, abs=0.01)


def test_no_kev_zero_contribution(
    prioritizer: Prioritizer, make_finding: Callable[..., FindingDTO]
) -> None:
    score = prioritizer.prioritize(make_finding(kev_listed=False))
    assert score.breakdown[PriorityComponent.KEV] == pytest.approx(0.0)


def test_none_epss_zero_contribution(
    prioritizer: Prioritizer, make_finding: Callable[..., FindingDTO]
) -> None:
    score = prioritizer.prioritize(make_finding(epss_score=None))
    assert score.breakdown[PriorityComponent.EPSS] == pytest.approx(0.0)


@pytest.mark.parametrize(
    ("decision", "expected_weight"),
    [
        (SSVCDecision.ACT, 15.0),
        (SSVCDecision.ATTEND, 11.25),
        (SSVCDecision.TRACK_STAR, 7.5),
        (SSVCDecision.TRACK, 3.75),
    ],
)
def test_ssvc_component_weights(
    prioritizer: Prioritizer,
    make_finding: Callable[..., FindingDTO],
    decision: SSVCDecision,
    expected_weight: float,
) -> None:
    score = prioritizer.prioritize(make_finding(ssvc_decision=decision))
    assert score.breakdown[PriorityComponent.SSVC] == pytest.approx(
        expected_weight, abs=0.01
    )


def test_score_is_clamped_to_100(
    prioritizer: Prioritizer, make_finding: Callable[..., FindingDTO]
) -> None:
    finding = make_finding(
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_v3_score=10.0,
        epss_score=1.0,
        kev_listed=True,
        ssvc_decision=SSVCDecision.ACT,
    )
    score = prioritizer.prioritize(finding)
    assert 0.0 <= score.score <= 100.0
    assert isinstance(score, PriorityScore)


def test_score_dto_is_frozen(
    prioritizer: Prioritizer, make_finding: Callable[..., FindingDTO]
) -> None:
    score = prioritizer.prioritize(make_finding())
    with pytest.raises(Exception):
        score.score = 0.0  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ARG-044 — FindingPrioritizer (deterministic ordinal ranker)
# ---------------------------------------------------------------------------


def test_rank_findings_kev_dominates_ssvc(
    make_finding: Callable[..., FindingDTO],
) -> None:
    """KEV-listed Track must rank above non-KEV Act."""
    kev_track = make_finding(
        cvss_v3_score=4.0,
        epss_score=0.1,
        kev_listed=True,
        ssvc_decision=SSVCDecision.TRACK,
    )
    no_kev_act = make_finding(
        cvss_v3_score=9.8,
        epss_score=0.99,
        kev_listed=False,
        ssvc_decision=SSVCDecision.ACT,
    )
    ranked = FindingPrioritizer.rank_findings([no_kev_act, kev_track])
    assert ranked[0].id == kev_track.id
    assert ranked[1].id == no_kev_act.id


def test_rank_findings_ssvc_breaks_when_kev_ties(
    make_finding: Callable[..., FindingDTO],
) -> None:
    """When both findings share KEV status, SSVC drives ordering."""
    high_ssvc = make_finding(
        cvss_v3_score=5.0, kev_listed=False, ssvc_decision=SSVCDecision.ACT
    )
    low_ssvc = make_finding(
        cvss_v3_score=9.0, kev_listed=False, ssvc_decision=SSVCDecision.TRACK
    )
    ranked = FindingPrioritizer.rank_findings([low_ssvc, high_ssvc])
    assert ranked[0].id == high_ssvc.id


def test_rank_findings_cvss_breaks_when_kev_and_ssvc_tie(
    make_finding: Callable[..., FindingDTO],
) -> None:
    high_cvss = make_finding(
        cvss_v3_score=9.5,
        kev_listed=False,
        ssvc_decision=SSVCDecision.ATTEND,
        epss_score=None,
    )
    low_cvss = make_finding(
        cvss_v3_score=4.2,
        kev_listed=False,
        ssvc_decision=SSVCDecision.ATTEND,
        epss_score=None,
    )
    ranked = FindingPrioritizer.rank_findings([low_cvss, high_cvss])
    assert ranked[0].id == high_cvss.id


def test_rank_findings_epss_breaks_when_kev_ssvc_cvss_tie(
    make_finding: Callable[..., FindingDTO],
) -> None:
    high_epss = make_finding(
        cvss_v3_score=7.5,
        kev_listed=False,
        ssvc_decision=SSVCDecision.ATTEND,
        epss_score=0.85,
    )
    low_epss = make_finding(
        cvss_v3_score=7.5,
        kev_listed=False,
        ssvc_decision=SSVCDecision.ATTEND,
        epss_score=0.05,
    )
    ranked = FindingPrioritizer.rank_findings([low_epss, high_epss])
    assert ranked[0].id == high_epss.id


def test_rank_findings_id_hash_breaks_complete_tie(
    make_finding: Callable[..., FindingDTO],
) -> None:
    a = make_finding(
        cvss_v3_score=5.0,
        kev_listed=False,
        ssvc_decision=SSVCDecision.TRACK,
        epss_score=0.1,
    )
    b = make_finding(
        cvss_v3_score=5.0,
        kev_listed=False,
        ssvc_decision=SSVCDecision.TRACK,
        epss_score=0.1,
    )
    ranked1 = FindingPrioritizer.rank_findings([a, b])
    ranked2 = FindingPrioritizer.rank_findings([b, a])
    # Same multiset → same ordering regardless of input order.
    assert [f.id for f in ranked1] == [f.id for f in ranked2]


def test_rank_findings_empty_input_returns_empty() -> None:
    assert FindingPrioritizer.rank_findings([]) == []


def test_rank_findings_byte_stable_across_invocations(
    make_finding: Callable[..., FindingDTO],
) -> None:
    """Two invocations on the same multiset return the exact same order."""
    findings = [
        make_finding(
            cvss_v3_score=float(i),
            epss_score=float(i) / 10.0,
            kev_listed=(i % 2 == 0),
            ssvc_decision=list(SSVCDecision)[i % 4],
        )
        for i in range(1, 8)
    ]
    a = [f.id for f in FindingPrioritizer.rank_findings(findings)]
    b = [f.id for f in FindingPrioritizer.rank_findings(findings)]
    c = [f.id for f in FindingPrioritizer.rank_findings(list(reversed(findings)))]
    assert a == b == c


def test_top_n_returns_first_n_findings(
    make_finding: Callable[..., FindingDTO],
) -> None:
    findings = [
        make_finding(
            cvss_v3_score=float(i), kev_listed=(i == 5), ssvc_decision=SSVCDecision.TRACK
        )
        for i in range(1, 6)
    ]
    top2 = FindingPrioritizer.top_n(findings, 2)
    assert len(top2) == 2
    # findings[4] has KEV → must be first.
    assert top2[0].id == findings[4].id


def test_top_n_zero_returns_empty_list(
    make_finding: Callable[..., FindingDTO],
) -> None:
    assert FindingPrioritizer.top_n([make_finding()], 0) == []
    assert FindingPrioritizer.top_n([make_finding()], -1) == []


def test_rank_findings_with_keys_exposes_rank_tuple(
    make_finding: Callable[..., FindingDTO],
) -> None:
    finding = make_finding(
        cvss_v3_score=7.0,
        epss_score=0.42,
        kev_listed=True,
        ssvc_decision=SSVCDecision.ACT,
    )
    ranked = FindingPrioritizer.rank_findings_with_keys([finding])
    assert len(ranked) == 1
    rf = ranked[0]
    kev, ssvc, cvss, epss, _id_hash = rf.rank_key
    assert kev == 1
    assert ssvc == 4  # ACT rank
    assert cvss == pytest.approx(7.0)
    assert epss == pytest.approx(0.42)


@dataclass(frozen=True)
class _FakeApiFinding:
    """Duck-typed stand-in for the API ``Finding`` schema."""

    title: str
    cwe: str
    cvss: float
    epss_score: Optional[float]
    epss_percentile: Optional[float]
    kev_listed: bool
    ssvc_decision: Optional[str]


def test_rank_objects_handles_duck_typed_findings() -> None:
    """``FindingPrioritizer.rank_objects`` should rank API ``Finding`` objects."""
    a = _FakeApiFinding(
        title="A",
        cwe="CWE-79",
        cvss=4.0,
        epss_score=0.1,
        epss_percentile=0.2,
        kev_listed=True,
        ssvc_decision=SSVCDecision.TRACK.value,
    )
    b = _FakeApiFinding(
        title="B",
        cwe="CWE-78",
        cvss=9.8,
        epss_score=0.9,
        epss_percentile=0.95,
        kev_listed=False,
        ssvc_decision=SSVCDecision.ACT.value,
    )
    ordered = FindingPrioritizer.rank_objects([b, a])
    # KEV-listed `a` wins despite lower CVSS / SSVC.
    assert ordered[0].title == "A"


def test_rank_objects_falls_back_to_default_when_attrs_missing() -> None:
    """Missing intel attrs should not raise; defaults to zero-priority bucket."""

    @dataclass(frozen=True)
    class Bare:
        title: str
        cwe: str

    objs = [Bare(title="z", cwe="CWE-1"), Bare(title="a", cwe="CWE-2")]
    ranked = FindingPrioritizer.rank_objects(objs)
    # Both have identical priority signals; tie-break should be deterministic.
    a = FindingPrioritizer.rank_objects(objs)
    b = FindingPrioritizer.rank_objects(objs)
    assert [o.title for o in a] == [o.title for o in b]
    assert {o.title for o in ranked} == {"z", "a"}


def test_rank_objects_handles_string_ssvc() -> None:
    """SSVC string values should map back through the enum."""
    obj = _FakeApiFinding(
        title="Stringly typed",
        cwe="CWE-79",
        cvss=5.0,
        epss_score=None,
        epss_percentile=None,
        kev_listed=False,
        ssvc_decision="invalid_ssvc",
    )
    out = FindingPrioritizer.rank_objects([obj])
    assert out[0].title == "Stringly typed"


def test_rank_objects_id_extractor_is_used() -> None:
    """Custom ``id_extractor`` should drive the tie-break hash."""

    @dataclass(frozen=True)
    class Tied:
        ident: str
        kev_listed: bool = False
        ssvc_decision: Optional[str] = None
        cvss_v3_score: float = 0.0
        epss_score: Optional[float] = None
        epss_percentile: Optional[float] = None

    a = Tied(ident="alpha")
    b = Tied(ident="bravo")

    by_a = FindingPrioritizer.rank_objects([a, b], id_extractor=lambda o: o.ident)
    by_b = FindingPrioritizer.rank_objects([b, a], id_extractor=lambda o: o.ident)
    assert [o.ident for o in by_a] == [o.ident for o in by_b]


def test_rank_findings_uses_epss_score_when_percentile_missing(
    make_finding: Callable[..., FindingDTO],
) -> None:
    """If percentile is None, raw EPSS score should still drive tie-break."""
    a = make_finding(cvss_v3_score=5.0, epss_score=0.9)
    b = make_finding(cvss_v3_score=5.0, epss_score=0.1)
    ranked = FindingPrioritizer.rank_findings([b, a])
    assert ranked[0].id == a.id


def test_rank_findings_descending_full_signal_order(
    make_finding: Callable[..., FindingDTO],
) -> None:
    """A small synthetic batch must come back KEV→SSVC→CVSS→EPSS sorted."""
    everything = [
        ("kev_act", make_finding(
            cvss_v3_score=9.5, epss_score=0.95,
            kev_listed=True, ssvc_decision=SSVCDecision.ACT,
        )),
        ("kev_track", make_finding(
            cvss_v3_score=2.0, epss_score=0.0,
            kev_listed=True, ssvc_decision=SSVCDecision.TRACK,
        )),
        ("nokev_act_high_cvss", make_finding(
            cvss_v3_score=9.5, epss_score=0.5,
            kev_listed=False, ssvc_decision=SSVCDecision.ACT,
        )),
        ("nokev_track", make_finding(
            cvss_v3_score=4.0, epss_score=0.1,
            kev_listed=False, ssvc_decision=SSVCDecision.TRACK,
        )),
    ]
    findings = [f for _, f in everything]
    expected_order_ids = [
        next(f.id for label, f in everything if label == "kev_act"),
        next(f.id for label, f in everything if label == "kev_track"),
        next(f.id for label, f in everything if label == "nokev_act_high_cvss"),
        next(f.id for label, f in everything if label == "nokev_track"),
    ]
    ranked = FindingPrioritizer.rank_findings(findings)
    assert [f.id for f in ranked] == expected_order_ids


def test_rank_findings_is_pure(
    make_finding: Callable[..., FindingDTO],
) -> None:
    """Calling rank_findings must not mutate the input collection."""
    findings = [
        make_finding(cvss_v3_score=float(i), kev_listed=(i % 2 == 0))
        for i in range(1, 6)
    ]
    snapshot = list(findings)
    FindingPrioritizer.rank_findings(findings)
    assert findings == snapshot


# ---------------------------------------------------------------------------
# ARG-044 — FindingPrioritizer.rank_findings (deterministic ordinal ranker)
# ---------------------------------------------------------------------------


def test_rank_kev_first(make_finding: Callable[..., FindingDTO]) -> None:
    no_kev = make_finding(
        cvss_v3_score=9.8,
        epss_score=0.99,
        kev_listed=False,
        ssvc_decision=SSVCDecision.ACT,
    )
    kev = make_finding(
        cvss_v3_score=4.0,
        epss_score=0.05,
        kev_listed=True,
        ssvc_decision=SSVCDecision.TRACK,
    )
    out = FindingPrioritizer.rank_findings([no_kev, kev])
    assert out[0] is kev
    assert out[1] is no_kev


def test_rank_ssvc_breaks_ties_within_kev_bucket(
    make_finding: Callable[..., FindingDTO],
) -> None:
    track = make_finding(kev_listed=True, ssvc_decision=SSVCDecision.TRACK)
    act = make_finding(kev_listed=True, ssvc_decision=SSVCDecision.ACT)
    attend = make_finding(kev_listed=True, ssvc_decision=SSVCDecision.ATTEND)
    out = FindingPrioritizer.rank_findings([track, act, attend])
    assert out[0] is act
    assert out[1] is attend
    assert out[2] is track


def test_rank_cvss_after_ssvc(make_finding: Callable[..., FindingDTO]) -> None:
    a = make_finding(
        kev_listed=False, ssvc_decision=SSVCDecision.TRACK, cvss_v3_score=4.0
    )
    b = make_finding(
        kev_listed=False, ssvc_decision=SSVCDecision.TRACK, cvss_v3_score=9.0
    )
    out = FindingPrioritizer.rank_findings([a, b])
    assert out[0] is b


def test_rank_epss_after_cvss(make_finding: Callable[..., FindingDTO]) -> None:
    a = make_finding(
        kev_listed=False,
        ssvc_decision=SSVCDecision.TRACK,
        cvss_v3_score=5.0,
        epss_score=0.1,
    )
    b = make_finding(
        kev_listed=False,
        ssvc_decision=SSVCDecision.TRACK,
        cvss_v3_score=5.0,
        epss_score=0.9,
    )
    out = FindingPrioritizer.rank_findings([a, b])
    assert out[0] is b


def test_rank_id_hash_breaks_total_tie(
    make_finding: Callable[..., FindingDTO],
) -> None:
    """All other signals tied → id-hash deterministically breaks tie."""
    f1 = make_finding(finding_id=uuid4())
    f2 = make_finding(finding_id=uuid4())
    out_a = FindingPrioritizer.rank_findings([f1, f2])
    out_b = FindingPrioritizer.rank_findings([f2, f1])  # input order swapped
    assert [x.id for x in out_a] == [x.id for x in out_b]


def test_rank_findings_is_idempotent(
    make_finding: Callable[..., FindingDTO],
) -> None:
    items = [make_finding() for _ in range(10)]
    a = FindingPrioritizer.rank_findings(items)
    b = FindingPrioritizer.rank_findings(items)
    assert [x.id for x in a] == [x.id for x in b]


def test_rank_findings_empty() -> None:
    assert FindingPrioritizer.rank_findings([]) == []


def test_top_n_returns_at_most_n(
    make_finding: Callable[..., FindingDTO],
) -> None:
    items = [
        make_finding(kev_listed=True, ssvc_decision=SSVCDecision.ACT),
        make_finding(kev_listed=False, ssvc_decision=SSVCDecision.TRACK),
        make_finding(kev_listed=True, ssvc_decision=SSVCDecision.ATTEND),
    ]
    top = FindingPrioritizer.top_n(items, 2)
    assert len(top) == 2
    assert top[0].kev_listed is True


def test_top_n_zero_returns_empty(
    make_finding: Callable[..., FindingDTO],
) -> None:
    assert FindingPrioritizer.top_n([make_finding()], 0) == []


# ---------------------------------------------------------------------------
# rank_objects — duck-typed ranker for API ``Finding`` schema
# ---------------------------------------------------------------------------


@dataclass
class _ApiFindingLike:
    """Minimal object satisfying the ``rank_objects`` duck-type contract."""

    title: str
    cwe: str
    cvss_v3_score: float
    epss_percentile: Optional[float] = None
    kev_listed: bool = False
    ssvc_decision: Optional[SSVCDecision] = None


def test_rank_objects_kev_first() -> None:
    nokev = _ApiFindingLike(
        title="A", cwe="CWE-79", cvss_v3_score=9.0, kev_listed=False
    )
    kev = _ApiFindingLike(
        title="B", cwe="CWE-89", cvss_v3_score=5.0, kev_listed=True
    )
    out = FindingPrioritizer.rank_objects([nokev, kev])
    assert out[0] is kev


def test_rank_objects_handles_missing_intel_fields() -> None:
    """Objects without epss/ssvc still rank without raising."""
    a = _ApiFindingLike(title="A", cwe="CWE-89", cvss_v3_score=4.0)
    b = _ApiFindingLike(title="B", cwe="CWE-79", cvss_v3_score=8.0)
    out = FindingPrioritizer.rank_objects([a, b])
    assert out[0] is b
    assert out[1] is a


def test_rank_objects_with_id_extractor() -> None:
    """Custom id extractor controls the tie-break hash deterministically."""
    a = _ApiFindingLike(title="dup", cwe="CWE-1", cvss_v3_score=5.0)
    b = _ApiFindingLike(title="dup", cwe="CWE-1", cvss_v3_score=5.0)
    out_default = FindingPrioritizer.rank_objects([a, b])
    out_custom = FindingPrioritizer.rank_objects(
        [a, b], id_extractor=lambda o: id(o).__str__()
    )
    # Both must produce the same length / membership; ordering can differ
    # because the id extractor is different.
    assert {id(x) for x in out_default} == {id(x) for x in out_custom}


def test_rank_objects_empty() -> None:
    assert FindingPrioritizer.rank_objects([]) == []


def test_rank_objects_is_idempotent() -> None:
    items = [
        _ApiFindingLike(title=f"f-{i}", cwe="CWE-1", cvss_v3_score=float(i))
        for i in range(5)
    ]
    a = FindingPrioritizer.rank_objects(items)
    b = FindingPrioritizer.rank_objects(items)
    assert [id(x) for x in a] == [id(x) for x in b]
