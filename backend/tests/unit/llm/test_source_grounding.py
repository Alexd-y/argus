"""Wave 5 / R-9.10 — source grounding for claim-generating tasks."""

from __future__ import annotations

from src.llm.source_grounding import (
    filter_grounded_claims,
    grounding_instruction,
)


def test_instruction_lists_labels_and_states_the_rule():
    instr = grounding_instruction(["E-1", "CL-2", "E-1"])
    assert "GROUNDING REQUIREMENT" in instr
    assert "E-1" in instr and "CL-2" in instr
    assert "discarded" in instr


def test_instruction_truncates_long_lists():
    instr = grounding_instruction([f"E-{i}" for i in range(100)], max_listed=10)
    assert "+90 more" in instr


def test_keeps_only_resolvable_grounded_claims():
    claims = [
        "SQLi confirmed on /login [E-1].",  # grounded + resolvable → keep
        "The app looks insecure overall.",  # no reference → drop
        "XSS somewhere [E-999].",  # unresolvable label → drop
        "Auth bypass via [CL-2] and [E-1].",  # all resolvable → keep
    ]
    known = {"E-1", "CL-2"}
    res = filter_grounded_claims(claims, known)
    assert res.kept == (
        "SQLi confirmed on /login [E-1].",
        "Auth bypass via [CL-2] and [E-1].",
    )
    reasons = [r for _, r in res.dropped]
    assert "no_reference" in reasons
    assert any(r.startswith("unresolvable:") and "E-999" in r for r in reasons)
    assert res.kept_rate == 0.5


def test_empty_claims_is_zero_rate():
    res = filter_grounded_claims([], {"E-1"})
    assert res.kept == () and res.dropped == ()
    assert res.kept_rate == 0.0
