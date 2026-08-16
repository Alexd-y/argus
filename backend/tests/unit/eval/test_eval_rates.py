"""Eval rate counters live outside the closed §18 metric alias map."""

from __future__ import annotations

from src.capabilities.coverage import can_transition_coverage, resolve_coverage_status
from src.capabilities.schemas import CoverageStatus
from src.core.unified_ai_metrics import METRIC_ALIAS_MAP
from src.eval.rates import (
    record_unknown_id_check,
    reset_eval_rates,
    snapshot_eval_rates,
)
from src.nuclei.profile_compiler import NucleiProfileCompiler
from src.nuclei.schemas import NucleiCompileRequest
from src.rag.citations import apply_citation_gate
from src.rag.schemas import CollectionName, RagCitation


def test_eval_rate_names_are_not_in_section_18_alias_map() -> None:
    for name in (
        "unknown_id_rate",
        "template_compile_rate",
        "evidence_citation_precision",
        "plan_completion_rate",
        "coverage_state_accuracy",
    ):
        assert name not in METRIC_ALIAS_MAP


def test_unknown_id_rate_and_reset() -> None:
    reset_eval_rates()
    record_unknown_id_check(unknown=False)
    record_unknown_id_check(unknown=True)
    snap = snapshot_eval_rates()
    assert snap.unknown_id_total == 2
    assert snap.unknown_id_rate == 0.5
    reset_eval_rates()
    assert snapshot_eval_rates().unknown_id_total == 0


def test_template_compile_rate_from_compiler() -> None:
    reset_eval_rates()
    ok = NucleiProfileCompiler.compile_request(
        NucleiCompileRequest(
            profile="fingerprint_safe",
            target_url="https://example.com",
        )
    )
    assert ok
    failed = NucleiProfileCompiler.compile_request(
        NucleiCompileRequest(
            profile="fingerprint_safe",
            target_url="not-a-url",
        )
    )
    assert failed == []
    snap = snapshot_eval_rates()
    assert snap.template_compile_total == 2
    assert snap.template_compile_rate == 0.5


def test_citation_precision_from_gate() -> None:
    reset_eval_rates()
    digest = "b" * 64
    citation = RagCitation(
        id="cite-1",
        chunk_id="cite-1",
        chunk_hash=digest,
        document_id="doc-1",
        source_id="src-1",
        collection=CollectionName.SCAN_EVIDENCE,
        rank=1,
        score=1.0,
        snippet="login",
    )
    apply_citation_gate(
        f"Confirmed SQL injection [cite:{digest}].",
        [citation],
    )
    apply_citation_gate("Confirmed SQL injection without a citation.", [])
    snap = snapshot_eval_rates()
    assert snap.citation_claims_total == 2
    assert snap.evidence_citation_precision == 0.5


def test_coverage_state_accuracy() -> None:
    reset_eval_rates()
    assert (
        can_transition_coverage(
            CoverageStatus.NOT_TESTED,
            CoverageStatus.COVERED_NO_FINDING,
            has_execution_evidence=False,
            has_finding=False,
        )
        is False
    )
    resolved = resolve_coverage_status(
        current=CoverageStatus.RUNNING,
        proposed=CoverageStatus.COVERED_NO_FINDING,
        execution_evidence_id="ev-1",
        tool_executed=True,
    )
    assert resolved is CoverageStatus.COVERED_NO_FINDING
    snap = snapshot_eval_rates()
    assert snap.coverage_transitions_total == 2
    assert snap.coverage_state_accuracy == 0.5
