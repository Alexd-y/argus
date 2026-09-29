"""Part III Phase T — prompt-artifact stop-list + output-form/consistency validation.

Regression for R-03…R-10, R-12: the model answered but its output was published
unchecked (prompt placeholders, chat artifacts, raw JSON, insecure verify commands,
invented chains, truncated finding IDs, mismatched counters/coverage).
"""

from __future__ import annotations

import pytest
from src.reports.prose_gate import (
    StopGroup,
    blocking_violations,
    check_output_consistency,
    evaluate_prose,
    find_prompt_artifacts,
    insecure_verification_flags,
    is_raw_json_prose,
    truncated_finding_ids,
)

_FULL_ID = "34b65c07-4c4d-5f72-bc6c-124461baee00"
_TRUNC_ID = "34b65c07-4c4d-5f72-bc6c-124461ba"


# --------------------------------------------------------------------------- R-03
@pytest.mark.parametrize(
    ("text", "group"),
    [
        ("Change: [Layer] [Config/file] → [specific value]", StopGroup.PROMPT_PLACEHOLDER),
        ("- Tag each fix: [Quick Fix] / [Moderate]", StopGroup.PROMPT_PLACEHOLDER),
        ("Config uses {{ value }} here", StopGroup.PROMPT_PLACEHOLDER),
        ("Verification command (curl or tool command) for each fix", StopGroup.PROMPT_INSTRUCTION),
        (
            "Concrete configuration examples only for detected stack evidence",
            StopGroup.PROMPT_INSTRUCTION,
        ),
        ("I hope this answer helps you with your question.", StopGroup.CHAT_ARTIFACT),
        ("As an AI, I cannot browse.", StopGroup.CHAT_ARTIFACT),
        ("1. No, there is no rate limiting", StopGroup.QUESTIONNAIRE_ECHO),
        ("value with \\u2014 escape", StopGroup.RAW_JSON),
    ],
)
def test_prompt_placeholder_leak_blocked(text: str, group: StopGroup):
    hits = {g for g, _ in find_prompt_artifacts(text)}
    assert group in hits
    assert any(
        v.rule.startswith("prompt_artifact:") for v in blocking_violations(evaluate_prose(text))
    )


def test_chat_artifact_blocked():
    v = blocking_violations(evaluate_prose("Certainly! Here is the summary."))
    assert any("chat_artifact" in x.rule for x in v)


# --------------------------------------------------------------------------- R-05
def test_raw_json_in_prose_slot_blocked():
    dump = '{"remediation_roadmap": {"near_term": ["x"], "longer_term": []}}'
    assert is_raw_json_prose(dump)
    v = blocking_violations(evaluate_prose(dump, slot_type="prose"))
    assert any(x.rule == "raw_json_in_prose_slot" for x in v)
    # A structured_json slot is allowed to be JSON.
    v2 = [
        x
        for x in evaluate_prose(dump, slot_type="structured_json")
        if x.rule == "raw_json_in_prose_slot"
    ]
    assert not v2


# --------------------------------------------------------------------------- R-06
def test_insecure_verification_command_rejected():
    text = "Verify with: curl --insecure https://alleksy.com/"
    assert insecure_verification_flags(text)
    v = check_output_consistency(text, section="remediation")
    assert any(x.rule == "insecure_verification_command" for x in v)
    assert insecure_verification_flags("curl -k https://x")
    assert insecure_verification_flags("requests.get(url, verify=False)")


# --------------------------------------------------------------------------- R-07
def test_chain_claim_requires_proven_chain():
    text = "This can be chained with the DNSSEC issue to create a critical vulnerability."
    v = check_output_consistency(text, has_proven_chains=False)
    assert any(x.rule == "chain_claim_without_proven_chain" for x in v)
    # With a proven chain present, the same sentence is allowed.
    assert not check_output_consistency(text, has_proven_chains=True)


# --------------------------------------------------------------------------- R-08
def test_truncated_finding_id_rejected():
    text = f"See finding {_TRUNC_ID} for details."
    assert truncated_finding_ids(text, {_FULL_ID}) == [_TRUNC_ID]
    v = check_output_consistency(text, known_finding_ids={_FULL_ID})
    assert any(x.rule == "truncated_finding_id" for x in v)
    # Full id is accepted.
    assert not truncated_finding_ids(f"finding {_FULL_ID}", {_FULL_ID})


# --------------------------------------------------------------------------- R-10
def test_counter_mismatch_blocked():
    text = "9 finding(s) recorded. Severity totals — critical: 0, high: 0, medium: 1, low: 0, informational: 0"
    v = check_output_consistency(text)
    assert any(x.rule == "counter_mismatch" for x in v)
    ok = "3 findings recorded. critical: 1, high: 1, medium: 1, low: 0, informational: 0"
    assert not any(x.rule == "counter_mismatch" for x in check_output_consistency(ok))


# --------------------------------------------------------------------------- R-12
def test_wstg_coverage_single_value():
    text = "WSTG coverage: 17% across the catalog."
    v = check_output_consistency(text, wstg_coverage_pct=2.0833)
    assert any(x.rule == "wstg_coverage_mismatch" for x in v)
    assert not check_output_consistency("WSTG coverage: 2% here", wstg_coverage_pct=2.0)
