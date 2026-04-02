"""XSS-001: tests for 5 new PoC fields (context, escape_technique, verified_via_browser, browser_alert_text, payload_used)."""

from __future__ import annotations

from src.recon.vulnerability_analysis.active_scan.poc_schema import (
    PROOF_OF_CONCEPT_KEYS,
    build_proof_of_concept,
    merge_proof_of_concept,
)

_EXPECTED_KEYS = (
    "tool",
    "parameter",
    "payload",
    "request",
    "response",
    "response_snippet",
    "curl_command",
    "javascript_code",
    "screenshot_key",
    "context",
    "reflection_context",
    "escape_technique",
    "verified_via_browser",
    "verification_method",
    "browser_alert_text",
    "browser_dialog_type",
    "payload_used",
    "payload_entered",
    "payload_reflected",
)


def test_proof_of_concept_keys_contains_all_canonical() -> None:
    assert len(PROOF_OF_CONCEPT_KEYS) == 19
    for k in _EXPECTED_KEYS:
        assert k in PROOF_OF_CONCEPT_KEYS, f"missing key: {k}"


def test_proof_of_concept_keys_order_matches_canonical() -> None:
    assert PROOF_OF_CONCEPT_KEYS == _EXPECTED_KEYS


def test_build_with_new_xss_fields_returns_correct_dict() -> None:
    poc = build_proof_of_concept(
        "dalfox",
        parameter="q",
        payload="<img onerror=alert(1) src=x>",
        context="attribute",
        escape_technique="double-encoding",
        verified_via_browser=True,
        verification_method="browser",
        browser_alert_text="1",
        payload_used="<img onerror=alert(1) src=x>",
    )
    assert poc["tool"] == "dalfox"
    assert poc["parameter"] == "q"
    assert poc["context"] == "attribute"
    assert poc["escape_technique"] == "double-encoding"
    assert poc["verified_via_browser"] is True
    assert poc["verification_method"] == "browser"
    assert poc["browser_alert_text"] == "1"
    assert poc["payload_used"] == "<img onerror=alert(1) src=x>"


def test_build_without_new_kwargs_backward_compat() -> None:
    poc = build_proof_of_concept(
        "nuclei",
        parameter="id",
        payload="<script>alert(1)</script>",
        request="GET /page?id=...",
        response="<html>...",
        curl_command="curl -v https://target/page?id=...",
    )
    assert poc["tool"] == "nuclei"
    assert poc["parameter"] == "id"
    assert "context" not in poc
    assert "reflection_context" not in poc
    assert "escape_technique" not in poc
    assert "verified_via_browser" not in poc
    assert "verification_method" not in poc
    assert "browser_alert_text" not in poc
    assert "payload_used" not in poc


def test_string_trimming_new_fields() -> None:
    poc = build_proof_of_concept(
        "xsstrike",
        context="   ",
        reflection_context="   ",
        escape_technique="  ",
        browser_alert_text="   ",
        payload_used="  ",
    )
    assert "context" not in poc
    assert "reflection_context" not in poc
    assert "escape_technique" not in poc
    assert "browser_alert_text" not in poc
    assert "payload_used" not in poc


def test_string_trimming_preserves_content_after_strip() -> None:
    poc = build_proof_of_concept(
        "xsstrike",
        context="  html_body  ",
        escape_technique="  none  ",
        browser_alert_text="  XSS  ",
        payload_used="  <svg onload=alert(1)>  ",
    )
    assert poc["context"] == "html_body"
    assert poc["escape_technique"] == "none"
    assert poc["browser_alert_text"] == "XSS"
    assert poc["payload_used"] == "<svg onload=alert(1)>"


def test_verified_via_browser_bool_preserved() -> None:
    poc_true = build_proof_of_concept("t", verified_via_browser=True)
    assert poc_true["verified_via_browser"] is True

    poc_false = build_proof_of_concept("t", verified_via_browser=False)
    assert poc_false["verified_via_browser"] is False


def test_verified_via_browser_none_omitted() -> None:
    poc = build_proof_of_concept("t", verified_via_browser=None)
    assert "verified_via_browser" not in poc


def test_new_string_fields_capped_at_8000() -> None:
    long_val = "X" * 9000
    poc = build_proof_of_concept(
        "t",
        context=long_val,
        reflection_context=long_val,
        escape_technique=long_val,
        browser_alert_text=long_val,
        payload_used=long_val,
    )
    for key in (
        "context",
        "reflection_context",
        "escape_technique",
        "browser_alert_text",
        "payload_used",
    ):
        assert len(poc[key]) == 8000


def test_merge_includes_new_fields_from_overlay() -> None:
    base = build_proof_of_concept("dalfox", payload="<svg onload=alert(1)>")
    overlay = build_proof_of_concept(
        "browser_engine",
        context="script",
        reflection_context="js_string",
        escape_technique="tag-breakout",
        verified_via_browser=True,
        verification_method="browser",
        browser_alert_text="1",
        payload_used="<svg onload=alert(1)>",
    )
    merged = merge_proof_of_concept(base, overlay)
    assert merged is not None
    assert merged["tool"] == "browser_engine"
    assert merged["context"] == "script"
    assert merged["reflection_context"] == "js_string"
    assert merged["escape_technique"] == "tag-breakout"
    assert merged["verified_via_browser"] is True
    assert merged["verification_method"] == "browser"
    assert merged["browser_alert_text"] == "1"
    assert merged["payload_used"] == "<svg onload=alert(1)>"


def test_merge_prefers_longer_new_field_string() -> None:
    a = build_proof_of_concept("t", context="short")
    b = build_proof_of_concept("t", context="much longer context value")
    merged = merge_proof_of_concept(a, b)
    assert merged is not None
    assert merged["context"] == "much longer context value"

    merged_rev = merge_proof_of_concept(b, a)
    assert merged_rev is not None
    assert merged_rev["context"] == "much longer context value"


def test_merge_does_not_overwrite_verified_via_browser_with_empty() -> None:
    a = build_proof_of_concept("t", verified_via_browser=True)
    b: dict = {"tool": "t2"}
    merged = merge_proof_of_concept(a, b)
    assert merged is not None
    assert merged["verified_via_browser"] is True


def test_merge_verified_via_browser_explicit_overlay_wins_false() -> None:
    """Re-enrichment (overlay) must clear stale browser verification."""
    a = build_proof_of_concept("t", verified_via_browser=True)
    b = build_proof_of_concept("xss_engine", verified_via_browser=False)
    merged = merge_proof_of_concept(a, b)
    assert merged is not None
    assert merged["verified_via_browser"] is False


def test_build_rejects_unknown_verification_method() -> None:
    poc = build_proof_of_concept("t", verification_method="ldap")
    assert "verification_method" not in poc


def test_build_accepts_http_reflection_and_none() -> None:
    a = build_proof_of_concept("t", verification_method="http_reflection")
    assert a["verification_method"] == "http_reflection"
    b = build_proof_of_concept("t", verification_method="none")
    assert b["verification_method"] == "none"


def test_merge_verification_method_prefers_stronger() -> None:
    a = build_proof_of_concept("t", verification_method="none")
    b = build_proof_of_concept("t", verification_method="http_reflection")
    assert merge_proof_of_concept(a, b)["verification_method"] == "http_reflection"
    assert merge_proof_of_concept(b, a)["verification_method"] == "http_reflection"
    c = build_proof_of_concept("t", verification_method="browser")
    assert merge_proof_of_concept(a, c)["verification_method"] == "browser"
    assert merge_proof_of_concept(c, b)["verification_method"] == "browser"


def test_old_caller_no_new_kwargs_produces_valid_poc() -> None:
    poc = build_proof_of_concept(
        "nuclei",
        parameter="search",
        payload="<img src=x>",
        request="GET /search?q=<img src=x>",
        response="<html><img src=x></html>",
        curl_command="curl https://target/search?q=payload",
    )
    for key in poc:
        assert key in PROOF_OF_CONCEPT_KEYS, f"unexpected key: {key}"
    assert poc["tool"] == "nuclei"
    assert len(poc) >= 4
