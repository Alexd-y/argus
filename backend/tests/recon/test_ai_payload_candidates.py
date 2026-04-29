"""P2-006 — AI payload candidates never execute raw strings."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.core import config as core_config
from src.payloads.registry import PayloadRegistry
from src.recon.vulnerability_analysis.active_scan import ai_payload_candidates
from src.recon.vulnerability_analysis.active_scan.ai_payload_candidates import (
    PayloadCandidateClass,
    classify_payload_candidate,
    clear_payload_registry_cache,
    prepare_for_execution,
    process_ai_payload_candidates,
)


@pytest.fixture
def production_payload_registry() -> PayloadRegistry:
    here = Path(__file__).resolve()
    backend = here.parents[2]
    reg = PayloadRegistry(payloads_dir=backend / "config" / "payloads")
    reg.load()
    return reg


@pytest.fixture(autouse=True)
def _clear_registry_cache() -> None:
    clear_payload_registry_cache()
    yield
    clear_payload_registry_cache()


def test_dos_payload_candidates_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        core_config.settings,
        "argus_ai_generated_lab_payloads",
        True,
        raising=False,
    )
    fork_bomb = ":(){ :|:& };:"
    assert (
        classify_payload_candidate(fork_bomb, core_config.settings)
        == PayloadCandidateClass.REJECT
    )


def test_ai_payload_candidate_requires_signed_catalog_or_approval(
    monkeypatch: pytest.MonkeyPatch,
    production_payload_registry: PayloadRegistry,
) -> None:
    unknown = "___totally_unknown_ai_payload_candidate___"
    monkeypatch.setattr(
        core_config.settings,
        "argus_ai_generated_lab_payloads",
        False,
        raising=False,
    )
    k1, r1 = ai_payload_candidates.classify_payload_candidate_with_ref(
        unknown,
        core_config.settings,
        registry=production_payload_registry,
    )
    assert k1 == PayloadCandidateClass.REJECT
    assert r1 is None

    monkeypatch.setattr(
        core_config.settings,
        "argus_ai_generated_lab_payloads",
        True,
        raising=False,
    )
    k2, r2 = ai_payload_candidates.classify_payload_candidate_with_ref(
        unknown,
        core_config.settings,
        registry=production_payload_registry,
    )
    assert k2 == PayloadCandidateClass.REJECT
    assert r2 is None

    monkeypatch.setattr(
        ai_payload_candidates,
        "lab_destructive_execution_allowed",
        lambda _cfg: True,
    )
    k3, r3 = ai_payload_candidates.classify_payload_candidate_with_ref(
        unknown,
        core_config.settings,
        registry=production_payload_registry,
    )
    assert k3 == PayloadCandidateClass.LAB_ONLY
    assert r3 is None


def test_ai_generated_payloads_are_not_executed_directly(
    monkeypatch: pytest.MonkeyPatch,
    production_payload_registry: PayloadRegistry,
) -> None:
    safe_template = "ARGUS_SQLI_SAFE_CANARY_A"
    k, ref = ai_payload_candidates.classify_payload_candidate_with_ref(
        safe_template,
        core_config.settings,
        registry=production_payload_registry,
    )
    assert k == PayloadCandidateClass.SAFE_CATALOG
    assert ref == "sqli_safe:canary_a"

    exec_ids = prepare_for_execution(
        classification=PayloadCandidateClass.SAFE_CATALOG,
        catalog_ref=ref,
        settings=core_config.settings,
        lab_explicit_approval=False,
    )
    assert exec_ids == ["sqli_safe:canary_a"]
    assert safe_template not in exec_ids

    monkeypatch.setattr(
        ai_payload_candidates,
        "lab_destructive_execution_allowed",
        lambda _cfg: True,
    )
    monkeypatch.setattr(
        core_config.settings,
        "argus_ai_generated_lab_payloads",
        True,
        raising=False,
    )
    lab_ids = prepare_for_execution(
        classification=PayloadCandidateClass.LAB_ONLY,
        catalog_ref=None,
        settings=core_config.settings,
        lab_explicit_approval=True,
    )
    assert lab_ids == []
    raw_ai = "DROP TABLE students;--"
    batch = process_ai_payload_candidates(
        [raw_ai],
        core_config.settings,
        registry=production_payload_registry,
        lab_explicit_approval=False,
    )
    safe_ids, rejected, lab_q = batch
    assert raw_ai not in safe_ids
    assert raw_ai in rejected
    assert lab_q == []
