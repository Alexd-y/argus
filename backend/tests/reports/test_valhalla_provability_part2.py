"""Part II (provability) unit tests — Phases I (claims), N (prose gate), J (class rules).

Pure/unit; no Postgres, WeasyPrint or LLM required.
"""

from __future__ import annotations

from src.reports.claims import (
    Claim,
    ClaimType,
    is_registered_validator,
    resolve_evidence_ids,
    sanitized_confidence,
    validate_claim,
)
from src.reports.poc_validation import (
    ConfirmationClass,
    evaluate_class_confirmation,
    resolve_confirmation_class,
)
from src.reports.prose_gate import (
    STOP_LIST,
    StopGroup,
    blocking_violations,
    evaluate_prose,
    find_stop_phrases,
    has_reference,
)

# --------------------------------------------------------------------------- #
# Phase I — Claim contract
# --------------------------------------------------------------------------- #


def _claim(**kw) -> Claim:
    base = {
        "claim_id": "CL-0001",
        "claim_type": ClaimType.OBSERVED,
        "text": "The endpoint returns X.",
        "subject": "https://target/api",
    }
    base.update(kw)
    return Claim(**base)


def test_claim_without_evidence_blocks_release() -> None:
    v = validate_claim(_claim(claim_type=ClaimType.CONFIRMED_VULNERABILITY, evidence_ids=[]))
    assert any(x.rule == "evidence_required" for x in v)


def test_observed_with_evidence_is_clean() -> None:
    v = validate_claim(_claim(claim_type=ClaimType.OBSERVED, evidence_ids=["E-1"]))
    assert v == []


def test_derived_inference_requires_derived_from() -> None:
    v = validate_claim(_claim(claim_type=ClaimType.DERIVED_INFERENCE, derived_from=[]))
    assert any(x.rule == "derived_from_required" for x in v)


def test_certainty_modality_in_hypothesis_rejected() -> None:
    v = validate_claim(_claim(claim_type=ClaimType.HYPOTHESIS, text="Это доказано на практике."))
    assert any(x.rule == "certainty_in_non_assertive" for x in v)


def test_confidence_without_calibration_flagged_and_dropped() -> None:
    c = _claim(evidence_ids=["E-1"], confidence=0.9)
    v = validate_claim(c)
    assert any(x.rule == "confidence_without_calibration" for x in v)
    assert sanitized_confidence(c) is None
    c2 = _claim(evidence_ids=["E-1"], confidence=0.9, confidence_calibration="platt-scaled")
    assert sanitized_confidence(c2) == 0.9


def test_unregistered_validator_rejected() -> None:
    assert not is_registered_validator("mr_trust_me")
    v = validate_claim(_claim(evidence_ids=["E-1"], validator="mr_trust_me"))
    assert any(x.rule == "unregistered_validator" for x in v)
    ok = validate_claim(_claim(evidence_ids=["E-1"], validator="sandbox_replay"))
    assert ok == []


def test_high_severity_requires_reviewer() -> None:
    v = validate_claim(_claim(evidence_ids=["E-1"]), high_severity=True)
    assert any(x.rule == "reviewer_required" for x in v)
    ok = validate_claim(_claim(evidence_ids=["E-1"], reviewer="alice"), high_severity=True)
    assert ok == []


def test_cross_scope_evidence_rejected() -> None:
    claims = [_claim(evidence_ids=["E-1", "E-999"])]
    v = resolve_evidence_ids(claims, available_evidence_ids={"E-1"})
    assert any(x.rule == "unresolvable_evidence" and "E-999" in x.reason for x in v)


# --------------------------------------------------------------------------- #
# Phase N — Prose gate
# --------------------------------------------------------------------------- #


def test_prose_gate_blocks_one_phrase_from_each_group() -> None:
    for group, phrases in STOP_LIST.items():
        sample = phrases[0]
        hits = find_stop_phrases(f"prefix {sample} suffix")
        assert any(g == group for g, _ in hits), group


def test_prose_gate_blocks_absolute_safety_claim() -> None:
    v = evaluate_prose("Система полностью защищена и безопасна.", section="exec")
    assert any(x.rule == "absolute_safety_claim" for x in blocking_violations(v))


def test_paragraph_without_reference_flagged() -> None:
    text = "The search parameter is injectable and returns database errors on quotes."
    v = evaluate_prose(text, section="findings")
    assert any(x.rule == "paragraph_without_reference" for x in v)


def test_paragraph_with_reference_ok() -> None:
    text = "The search parameter is injectable and returns DB errors [CL-0042 / E-101]."
    v = evaluate_prose(text, section="findings")
    assert not any(x.rule == "paragraph_without_reference" for x in v)
    assert has_reference(text)


def test_methodology_section_allows_reference_free_prose() -> None:
    text = "Методология основана на OWASP WSTG v4.2 и NIST SP 800-115."
    v = evaluate_prose(text, section="methodology")
    assert not any(x.rule == "paragraph_without_reference" for x in v)


def test_stub_group_catches_todo() -> None:
    assert StopGroup.STUB in {g for g, _ in find_stop_phrases("TODO: finish this")}


# --------------------------------------------------------------------------- #
# Phase J — Class confirmation rules
# --------------------------------------------------------------------------- #


def test_reflection_is_not_xss() -> None:
    r = evaluate_class_confirmation(
        ConfirmationClass.XSS, {"reflection_context": "html", "payload_reflected": "<x>"}
    )
    assert r.confirmed is False and r.reason


def test_browser_execution_confirms_xss() -> None:
    r = evaluate_class_confirmation(
        ConfirmationClass.XSS, {"verified_via_browser": True, "browser_alert_text": "1"}
    )
    assert r.confirmed is True


def test_timing_without_control_is_not_sqli() -> None:
    r = evaluate_class_confirmation(ConfirmationClass.SQLI, {"timing_delta_ms": 900})
    assert r.confirmed is False
    r2 = evaluate_class_confirmation(
        ConfirmationClass.SQLI,
        {"boolean_true_response": "1", "boolean_false_response": "0"},
    )
    assert r2.confirmed is True


def test_banner_version_is_not_confirmed_cve() -> None:
    r = evaluate_class_confirmation(ConfirmationClass.CVE_VERSION, {"banner": "nginx/1.20"})
    assert r.confirmed is False
    r2 = evaluate_class_confirmation(ConfirmationClass.CVE_VERSION, {"version_inferred": True})
    assert r2.confirmed is True  # explicit "version-inferred" flag is allowed


def test_ssrf_requires_oast_canary() -> None:
    assert not evaluate_class_confirmation(ConfirmationClass.SSRF, {"status": 200}).confirmed
    assert evaluate_class_confirmation(
        ConfirmationClass.SSRF, {"oast_callback": "x.oast", "canary": "abc"}
    ).confirmed


def test_resolve_confirmation_class_from_title() -> None:
    assert resolve_confirmation_class("Reflected XSS in q") == ConfirmationClass.XSS
    assert resolve_confirmation_class("Blind SQL Injection") == ConfirmationClass.SQLI
    assert (
        resolve_confirmation_class("Missing TLS security header") == ConfirmationClass.TLS_HEADERS
    )
    assert resolve_confirmation_class("some random text") is None
