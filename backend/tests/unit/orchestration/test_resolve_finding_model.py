"""Wave 5 / R-9.11 — producing-model attribution for findings (adoption)."""

from __future__ import annotations

from src.orchestration.state_machine import _WRB_MODEL, _resolve_finding_model


def test_explicit_source_model_wins():
    assert _resolve_finding_model({"source_model": "custom-model", "source": "active_scan"}) == (
        "custom-model"
    )


def test_llm_origin_sources_attributed_to_wrb():
    for src in ("llm_deep_review", "cairn", "adaptive_loop"):
        assert _resolve_finding_model({"source": src}) == _WRB_MODEL


def test_tool_sources_have_no_model():
    for src in ("active_scan", "httpx", "subfinder", "binary_analysis", "heuristic", "fuzzing"):
        assert _resolve_finding_model({"source": src}) == ""


def test_missing_source_is_empty():
    assert _resolve_finding_model({}) == ""
