"""Part II Phase P — senior report prompts v2 + prose-gate rejection of generic advice."""

from __future__ import annotations

from src.orchestration.prompt_registry import (
    REPORT_AI_SENIOR_PROMPTS_VERSION,
    REPORT_AI_SYSTEM,
    REPORT_AI_SYSTEM_V2,
    report_ai_system_prompt,
)
from src.reports.prose_gate import blocking_violations, evaluate_prose


def test_v2_preamble_carries_senior_rules():
    v2 = REPORT_AI_SYSTEM_V2.lower()
    assert "twenty years" in v2
    assert "claim_id" in v2 and "evidence_id" in v2
    assert "reflection" in v2  # reflection is not XSS
    assert "compliance" in v2  # no compliance from mapping
    assert REPORT_AI_SENIOR_PROMPTS_VERSION.startswith("senior-v2")


def test_selector_defaults_to_legacy_and_opts_into_v2():
    assert report_ai_system_prompt(senior_v2=False) == REPORT_AI_SYSTEM
    v2 = report_ai_system_prompt(senior_v2=True)
    assert REPORT_AI_SYSTEM_V2 in v2
    assert REPORT_AI_SYSTEM in v2  # v2 layers on top of the legacy rules


def test_prose_gate_rejects_generic_remediation():
    # §21.3 — mock LLM returns "apply input validation" → empty-recommendation stop-list.
    text = "Remediation: input validation and output encoding across the application."
    violations = blocking_violations(evaluate_prose(text, section="remediation"))
    assert any("empty_recommendation" in v.rule for v in violations)


def test_prose_gate_rejects_best_practices_advice():
    text = "Follow security best practices to mitigate the issue."
    violations = blocking_violations(evaluate_prose(text, section="remediation"))
    assert any("empty_recommendation" in v.rule for v in violations)
