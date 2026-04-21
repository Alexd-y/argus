"""Unit tests for :mod:`src.findings.correlator`."""

from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

import pytest

from src.findings.correlator import ChainSeverity, Correlator, FindingChain
from src.pipeline.contracts.finding_dto import FindingCategory, FindingDTO


@pytest.fixture
def correlator() -> Correlator:
    return Correlator()


def _with_techniques(
    make_finding: Callable[..., FindingDTO],
    *,
    asset_id,
    techniques: list[str],
    cvss_v3_score: float = 5.0,
    cvss_v3_vector: str = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
) -> FindingDTO:
    return make_finding(
        asset_id=asset_id,
        mitre_attack=techniques,
        cvss_v3_score=cvss_v3_score,
        cvss_v3_vector=cvss_v3_vector,
    )


def test_two_findings_same_asset_chain(
    correlator: Correlator, make_finding: Callable[..., FindingDTO]
) -> None:
    asset_id = uuid4()
    f_initial = _with_techniques(make_finding, asset_id=asset_id, techniques=["T1190"])
    f_exec = _with_techniques(
        make_finding,
        asset_id=asset_id,
        techniques=["T1059"],
        cvss_v3_score=8.0,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    )
    chains = correlator.correlate([f_initial, f_exec])
    assert len(chains) == 1
    chain = chains[0]
    assert isinstance(chain, FindingChain)
    assert chain.attack_techniques == ("T1190", "T1059")
    assert set(chain.findings) == {f_initial.id, f_exec.id}
    assert chain.severity is ChainSeverity.HIGH


def test_lone_finding_omitted(
    correlator: Correlator, make_finding: Callable[..., FindingDTO]
) -> None:
    finding = _with_techniques(make_finding, asset_id=uuid4(), techniques=["T1190"])
    assert correlator.correlate([finding]) == []


def test_findings_on_different_assets_not_chained(
    correlator: Correlator, make_finding: Callable[..., FindingDTO]
) -> None:
    f_a = _with_techniques(make_finding, asset_id=uuid4(), techniques=["T1190"])
    f_b = _with_techniques(make_finding, asset_id=uuid4(), techniques=["T1059"])
    assert correlator.correlate([f_a, f_b]) == []


def test_unknown_technique_filtered_out(
    correlator: Correlator, make_finding: Callable[..., FindingDTO]
) -> None:
    asset_id = uuid4()
    f_known = _with_techniques(make_finding, asset_id=asset_id, techniques=["T1190"])
    f_unknown = _with_techniques(make_finding, asset_id=asset_id, techniques=["T9999"])
    chains = correlator.correlate([f_known, f_unknown])
    assert chains == []


def test_kill_chain_order_respected(
    correlator: Correlator, make_finding: Callable[..., FindingDTO]
) -> None:
    asset_id = uuid4()
    f_exfil = _with_techniques(
        make_finding,
        asset_id=asset_id,
        techniques=["T1041"],
        cvss_v3_score=4.5,
    )
    f_initial = _with_techniques(make_finding, asset_id=asset_id, techniques=["T1190"])
    f_priv = _with_techniques(
        make_finding,
        asset_id=asset_id,
        techniques=["T1068"],
        cvss_v3_score=9.5,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    chains = correlator.correlate([f_exfil, f_initial, f_priv])
    assert len(chains) == 1
    chain = chains[0]
    assert chain.attack_techniques == ("T1190", "T1068", "T1041")
    assert chain.severity is ChainSeverity.CRITICAL


def test_empty_input(correlator: Correlator) -> None:
    assert correlator.correlate([]) == []


def test_findings_without_techniques_skipped(
    correlator: Correlator, make_finding: Callable[..., FindingDTO]
) -> None:
    asset_id = uuid4()
    bare = make_finding(asset_id=asset_id)
    chains = correlator.correlate([bare])
    assert chains == []


def test_chain_id_deterministic(
    correlator: Correlator, make_finding: Callable[..., FindingDTO]
) -> None:
    asset_id = uuid4()
    f1 = _with_techniques(make_finding, asset_id=asset_id, techniques=["T1190"])
    f2 = _with_techniques(make_finding, asset_id=asset_id, techniques=["T1059"])
    a = correlator.correlate([f1, f2])
    b = correlator.correlate([f1, f2])
    assert a[0].chain_id == b[0].chain_id


def test_chains_sorted_deterministically(
    correlator: Correlator, make_finding: Callable[..., FindingDTO]
) -> None:
    asset_a, asset_b = sorted([uuid4(), uuid4()], key=str)
    chains = correlator.correlate(
        [
            _with_techniques(make_finding, asset_id=asset_b, techniques=["T1190"]),
            _with_techniques(make_finding, asset_id=asset_b, techniques=["T1059"]),
            _with_techniques(make_finding, asset_id=asset_a, techniques=["T1190"]),
            _with_techniques(make_finding, asset_id=asset_a, techniques=["T1059"]),
        ]
    )
    assert len(chains) == 2
    assert chains[0].asset_id == asset_a
    assert chains[1].asset_id == asset_b


def test_chain_severity_low_for_info_findings(
    correlator: Correlator, make_finding: Callable[..., FindingDTO]
) -> None:
    asset_id = uuid4()
    f_a = _with_techniques(
        make_finding,
        asset_id=asset_id,
        techniques=["T1190"],
        cvss_v3_score=2.0,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
    )
    f_b = _with_techniques(
        make_finding,
        asset_id=asset_id,
        techniques=["T1059"],
        cvss_v3_score=2.0,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
    )
    chains = correlator.correlate([f_a, f_b])
    assert chains[0].severity is ChainSeverity.LOW


def test_chain_dto_is_frozen(
    correlator: Correlator, make_finding: Callable[..., FindingDTO]
) -> None:
    asset_id = uuid4()
    chains = correlator.correlate(
        [
            _with_techniques(make_finding, asset_id=asset_id, techniques=["T1190"]),
            _with_techniques(make_finding, asset_id=asset_id, techniques=["T1059"]),
        ]
    )
    assert chains
    with pytest.raises(Exception):
        chains[0].severity = ChainSeverity.LOW  # type: ignore[misc]


def test_categorical_categories_have_no_effect(
    correlator: Correlator, make_finding: Callable[..., FindingDTO]
) -> None:
    asset_id = uuid4()
    chains = correlator.correlate(
        [
            _with_techniques(
                make_finding, asset_id=asset_id, techniques=["T1190"]
            ).model_copy(update={"category": FindingCategory.RCE}),
            _with_techniques(
                make_finding, asset_id=asset_id, techniques=["T1059"]
            ).model_copy(update={"category": FindingCategory.INFO}),
        ]
    )
    assert chains and len(chains[0].findings) == 2
