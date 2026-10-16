"""Eval rate counters (master prompt §19.6).

Integer mirrors only — do not extend the closed §18 METRIC_ALIAS_MAP.
Rates are unknown/failed/inferred/incomplete/inaccurate over the matching total.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import Lock

_LOCK = Lock()

_unknown_id_total = 0
_unknown_id_hits = 0
_template_compile_total = 0
_template_compile_ok = 0
_citation_claims_total = 0
_citation_claims_cited = 0
_plan_steps_total = 0
_plan_steps_completed = 0
_coverage_transitions_total = 0
_coverage_transitions_accurate = 0

# Wave 5 (R-9.7) — structured-output parse quality. A NEW eval metric kept
# separate from the closed §18 mirror above (EvalRates). Measures how often an
# LLM response parsed cleanly on the first try vs only via json_extract's
# fallback heuristics vs not at all — the baseline that schema enforcement
# (stage V / R-9.9) is expected to move.
_json_parse_direct = 0
_json_parse_fallback = 0
_json_parse_failed = 0


@dataclass(frozen=True)
class EvalRates:
    unknown_id_rate: float
    template_compile_rate: float
    evidence_citation_precision: float
    plan_completion_rate: float
    coverage_state_accuracy: float
    unknown_id_total: int
    template_compile_total: int
    citation_claims_total: int
    plan_steps_total: int
    coverage_transitions_total: int


@dataclass(frozen=True)
class StructuredParseRates:
    """Wave 5 (R-9.7) structured-output parse quality over LLM responses."""

    # Clean JSON parsed on the first try — what schema enforcement should raise.
    direct_parse_rate: float
    # Recovered only via json_extract's fence/balanced fallback heuristics.
    fallback_parse_rate: float
    # Unparseable (no JSON object recovered).
    parse_failure_rate: float
    total: int


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def reset_eval_rates() -> None:
    global _unknown_id_total, _unknown_id_hits
    global _template_compile_total, _template_compile_ok
    global _citation_claims_total, _citation_claims_cited
    global _plan_steps_total, _plan_steps_completed
    global _coverage_transitions_total, _coverage_transitions_accurate
    with _LOCK:
        _unknown_id_total = 0
        _unknown_id_hits = 0
        _template_compile_total = 0
        _template_compile_ok = 0
        _citation_claims_total = 0
        _citation_claims_cited = 0
        _plan_steps_total = 0
        _plan_steps_completed = 0
        _coverage_transitions_total = 0
        _coverage_transitions_accurate = 0


def reset_structured_parse_rates() -> None:
    global _json_parse_direct, _json_parse_fallback, _json_parse_failed
    with _LOCK:
        _json_parse_direct = 0
        _json_parse_fallback = 0
        _json_parse_failed = 0


def record_json_parse(*, tier: str) -> None:
    """Record one json_extract outcome. ``tier`` ∈ {direct, fence, balanced, failed}.

    ``direct`` = clean first-try parse; ``fence``/``balanced`` = fallback
    heuristic recovery; ``failed`` = unparseable.
    """
    global _json_parse_direct, _json_parse_fallback, _json_parse_failed
    with _LOCK:
        if tier == "direct":
            _json_parse_direct += 1
        elif tier == "failed":
            _json_parse_failed += 1
        else:  # fence | balanced → fallback recovery
            _json_parse_fallback += 1


def snapshot_structured_parse_rates() -> StructuredParseRates:
    with _LOCK:
        total = _json_parse_direct + _json_parse_fallback + _json_parse_failed
        return StructuredParseRates(
            direct_parse_rate=_ratio(_json_parse_direct, total),
            fallback_parse_rate=_ratio(_json_parse_fallback, total),
            parse_failure_rate=_ratio(_json_parse_failed, total),
            total=total,
        )


def record_unknown_id_check(*, unknown: bool) -> None:
    global _unknown_id_total, _unknown_id_hits
    with _LOCK:
        _unknown_id_total += 1
        if unknown:
            _unknown_id_hits += 1


def record_template_compile(*, ok: bool) -> None:
    global _template_compile_total, _template_compile_ok
    with _LOCK:
        _template_compile_total += 1
        if ok:
            _template_compile_ok += 1


def record_citation_claim(*, cited: bool) -> None:
    global _citation_claims_total, _citation_claims_cited
    with _LOCK:
        _citation_claims_total += 1
        if cited:
            _citation_claims_cited += 1


def record_plan_step(*, completed: bool) -> None:
    global _plan_steps_total, _plan_steps_completed
    with _LOCK:
        _plan_steps_total += 1
        if completed:
            _plan_steps_completed += 1


def record_coverage_transition(*, accurate: bool) -> None:
    global _coverage_transitions_total, _coverage_transitions_accurate
    with _LOCK:
        _coverage_transitions_total += 1
        if accurate:
            _coverage_transitions_accurate += 1


def snapshot_eval_rates() -> EvalRates:
    with _LOCK:
        return EvalRates(
            unknown_id_rate=_ratio(_unknown_id_hits, _unknown_id_total),
            template_compile_rate=_ratio(_template_compile_ok, _template_compile_total),
            evidence_citation_precision=_ratio(_citation_claims_cited, _citation_claims_total),
            plan_completion_rate=_ratio(_plan_steps_completed, _plan_steps_total),
            coverage_state_accuracy=_ratio(
                _coverage_transitions_accurate, _coverage_transitions_total
            ),
            unknown_id_total=_unknown_id_total,
            template_compile_total=_template_compile_total,
            citation_claims_total=_citation_claims_total,
            plan_steps_total=_plan_steps_total,
            coverage_transitions_total=_coverage_transitions_total,
        )
