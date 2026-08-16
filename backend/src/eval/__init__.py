"""Eval package — acceptance-rate snapshots for unified AI/RAG/LAB."""

from src.eval.rates import (
    EvalRates,
    record_citation_claim,
    record_coverage_transition,
    record_plan_step,
    record_template_compile,
    record_unknown_id_check,
    reset_eval_rates,
    snapshot_eval_rates,
)

__all__ = [
    "EvalRates",
    "record_citation_claim",
    "record_coverage_transition",
    "record_plan_step",
    "record_template_compile",
    "record_unknown_id_check",
    "reset_eval_rates",
    "snapshot_eval_rates",
]
