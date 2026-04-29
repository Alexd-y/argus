"""P2-006 — AI payload candidate pipeline (classification only; never execute raw)."""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from src.core.config import Settings
from src.payloads.registry import PayloadRegistry
from src.recon.vulnerability_analysis.active_scan.ai_payload_candidates import (
    PayloadCandidateClass,
    classify_payload_candidate,
    prepare_for_execution,
    process_ai_payload_candidates,
)

_BACKEND: Final[Path] = Path(__file__).resolve().parents[1]
_CATALOG: Final[Path] = _BACKEND / "config" / "payloads"


@pytest.fixture(scope="module")
def loaded_registry() -> PayloadRegistry:
    reg = PayloadRegistry(payloads_dir=_CATALOG)
    reg.load()
    return reg


def test_ai_payload_candidate_requires_signed_catalog_or_approval(
    loaded_registry: PayloadRegistry,
) -> None:
    settings = Settings(
        _env_file=None,
        argus_ai_generated_lab_payloads=False,
    )
    assert (
        classify_payload_candidate(
            "sqli_safe:canary_a", settings, registry=loaded_registry
        )
        is PayloadCandidateClass.SAFE_CATALOG
    )
    assert (
        classify_payload_candidate(
            "sqli_safe:not_a_real_payload_id", settings, registry=loaded_registry
        )
        is PayloadCandidateClass.REJECT
    )
    assert classify_payload_candidate("'; DROP TABLE--", settings) is PayloadCandidateClass.REJECT

    settings_lab = Settings(
        _env_file=None,
        argus_ai_generated_lab_payloads=True,
    )
    assert (
        classify_payload_candidate("LLM_PROBE_NON_CATALOG", settings_lab)
        is PayloadCandidateClass.LAB_ONLY
    )


def test_ai_generated_payloads_are_not_executed_directly(
    loaded_registry: PayloadRegistry,
) -> None:
    settings = Settings(
        _env_file=None,
        argus_ai_generated_lab_payloads=True,
        argus_lab_mode=True,
        argus_destructive_lab_mode=True,
        sandbox_enabled=True,
        argus_lab_operator_id="op",
        argus_lab_signed_approval_id="appr",
        argus_lab_allowed_targets="https://example.com",
        argus_kill_switch_required=False,
    )
    raw = "'; SELECT pg_sleep(10)--"
    out = prepare_for_execution(
        safe_catalog_ids=["sqli_safe:canary_a"],
        settings=settings,
        lab_catalog_refs=["sqli_safe:canary_b"],
        lab_raw_candidates=[raw],
        lab_explicit_approval=True,
    )
    assert raw not in out
    assert "sqli_safe:canary_a" in out
    assert "sqli_safe:canary_b" not in out

    safe, rejected, lab = process_ai_payload_candidates(
        ["sqli_safe:canary_a", raw],
        settings,
        registry=loaded_registry,
    )
    assert safe == ["sqli_safe:canary_a"]
    assert raw in rejected
    assert lab == []


def test_dos_payload_candidates_rejected() -> None:
    settings = Settings(_env_file=None, argus_ai_generated_lab_payloads=True)
    assert classify_payload_candidate("sleep(999999)", settings) is PayloadCandidateClass.REJECT
    assert classify_payload_candidate("x" * 3000, settings) is PayloadCandidateClass.REJECT
