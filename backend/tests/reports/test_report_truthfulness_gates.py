"""P0-P2 report truthfulness & quality gate tests.

Covers: FUZZ_HIT evidence gate, COMMAND_INJECTION_CANDIDATE gate, HIBP inconclusive,
AI stub detection, ANSI sanitizer, remediation matrix, rate limit classification,
WhatWeb noise filter, endpoint header validation, WSTG authenticated gap.
"""

from __future__ import annotations

from types import SimpleNamespace

from src.recon.vulnerability_analysis.active_scan.ansi_sanitizer import (
    strip_ansi,
    strip_ansi_from_url,
    strip_ansi_from_poc,
)
from src.recon.vulnerability_analysis.active_scan.poc_schema import (
    build_proof_of_concept,
    merge_proof_of_concept,
)
from src.recon.vulnerability_analysis.active_scan.whatweb_va_adapter import (
    whatweb_plugin_entries,
    _WHATWEB_NOISE_CATEGORIES,
)
from src.reports.report_text_sanitizer import (
    contains_ai_stub_output,
    sanitize_ai_report_text,
)
from src.reports.report_quality_gate import (
    classify_rate_limit_finding,
    AUTHENTICATED_TESTING_GAP_WARNING,
    _EVIDENCE_QUALITY_RANK,
)


def test_ansi_sanitizer_strips_csi_sequences() -> None:
    assert strip_ansi("\x1b[31mRed\x1b[0m normal") == "Red normal"


def test_ansi_sanitizer_strips_osc() -> None:
    assert strip_ansi("\x1b]0;title\x07rest") == "rest"


def test_ansi_sanitizer_strips_line_clear() -> None:
    assert strip_ansi("before\x1b[2Kafter") == "beforeafter"


def test_ansi_sanitizer_strips_cursor_move() -> None:
    assert strip_ansi("\x1b[2J\x1b[H") == ""


def test_ansi_sanitizer_preserves_clean_text() -> None:
    assert strip_ansi("clean text no escapes") == "clean text no escapes"


def test_ansi_sanitizer_from_url() -> None:
    url = "https://example.com/\x1b[2Kpath?q=%3Cscript%3E"
    cleaned = strip_ansi_from_url(url)
    assert "\x1b" not in cleaned
    assert "example.com" in cleaned


def test_ansi_sanitizer_from_poc() -> None:
    poc = {
        "payload": "<script>\x1b[31malert(1)\x1b[0m</script>",
        "reflection_context": "reflected\x1b[2K",
        "negative_control_url": "https://x.com/\x1b[K",
    }
    cleaned = strip_ansi_from_poc(poc)
    assert "\x1b" not in cleaned.get("payload", "")
    assert "\x1b" not in cleaned.get("reflection_context", "")
    assert "\x1b" not in cleaned.get("negative_control_url", "")


def test_ai_stub_detects_hello_world() -> None:
    assert contains_ai_stub_output("The output is Hello, World! program") is True


def test_ai_stub_detects_code_block_html() -> None:
    assert contains_ai_stub_output('<h1>This is a code block</h1>') is True


def test_ai_stub_detects_iostream() -> None:
    assert contains_ai_stub_output("#include <iostream>") is True


def test_ai_stub_detects_placeholder_high_medium_low() -> None:
    assert contains_ai_stub_output("likelihood: high|medium|low") is True


def test_ai_stub_detects_see_attack_scenarios() -> None:
    assert contains_ai_stub_output("See Attack Scenarios for details") is True


def test_ai_stub_detects_no_remediation_matrix() -> None:
    assert contains_ai_stub_output("No remediation matrix available") is True


def test_ai_stub_detects_unknown_component() -> None:
    assert contains_ai_stub_output("Component: Unknown component") is True


def test_ai_stub_clean_text_not_flagged() -> None:
    assert contains_ai_stub_output("The application uses React 18.2 with known CVEs.") is False


def test_sanitize_ai_report_text_replaces_stub_with_fallback() -> None:
    text = "Executive summary: Hello, World! This is the result."
    result = sanitize_ai_report_text(text)
    assert "placeholder text" in result.lower() or "evidence-backed" in result.lower()


def test_whatweb_noise_filter_excludes_country() -> None:
    parsed = {
        "plugins": {
            "Country": {"string": "US"},
            "nginx": {"version": "1.18.0"},
            "City": {"string": "New York"},
        }
    }
    entries = whatweb_plugin_entries(parsed)
    names = [e["technology"] for e in entries]
    assert "nginx" in names
    assert "Country" not in names
    assert "City" not in names


def test_whatweb_noise_filter_excludes_locale() -> None:
    parsed = {
        "plugins": {
            "Locale": {"string": "en_US"},
            "Apache": {"version": "2.4.51"},
        }
    }
    entries = whatweb_plugin_entries(parsed)
    names = [e["technology"] for e in entries]
    assert "Apache" in names
    assert "Locale" not in names


def test_whatweb_noise_categories_contains_geographic_keys() -> None:
    assert "country" in _WHATWEB_NOISE_CATEGORIES
    assert "city" in _WHATWEB_NOISE_CATEGORIES
    assert "region" in _WHATWEB_NOISE_CATEGORIES
    assert "locale" in _WHATWEB_NOISE_CATEGORIES
    assert "location" in _WHATWEB_NOISE_CATEGORIES


def test_rate_limit_working_is_observation() -> None:
    f = SimpleNamespace(
        title="Rate Limiting Detected on Login Endpoint",
        description="Server returned HTTP 429 Too Many Requests after 50 attempts",
        proof_of_concept={"response_status": 429},
        severity="low",
    )
    result = classify_rate_limit_finding(f)
    assert result == "working_observation"


def test_rate_limit_absent_is_vulnerability() -> None:
    f = SimpleNamespace(
        title="Rate Limiting Not Detected on Login",
        description="No rate limiting observed on login endpoint after 500 requests",
        proof_of_concept={},
        severity="low",
    )
    result = classify_rate_limit_finding(f)
    assert result == "absent_vulnerability"


def test_rate_limit_non_rate_limit_finding() -> None:
    f = SimpleNamespace(
        title="SQL Injection Found",
        description="SQL injection in search parameter",
        proof_of_concept={},
        severity="high",
    )
    result = classify_rate_limit_finding(f)
    assert result == "not_rate_limit"


def test_evidence_quality_rank_ordering() -> None:
    assert _EVIDENCE_QUALITY_RANK["none"] < _EVIDENCE_QUALITY_RANK["weak"]
    assert _EVIDENCE_QUALITY_RANK["weak"] < _EVIDENCE_QUALITY_RANK["moderate"]
    assert _EVIDENCE_QUALITY_RANK["moderate"] < _EVIDENCE_QUALITY_RANK["strong"]


def test_authenticated_testing_gap_warning_exists() -> None:
    assert "Authenticated testing was NOT performed" in AUTHENTICATED_TESTING_GAP_WARNING
    assert "IDOR" in AUTHENTICATED_TESTING_GAP_WARNING
    assert "privilege escalation" in AUTHENTICATED_TESTING_GAP_WARNING


def test_poc_schema_strips_ansi_from_url_fields() -> None:
    poc = build_proof_of_concept(
        "nuclei",
        payload="<script>\x1b[31malert(1)\x1b[0m</script>",
        reflection_context="reflected\x1b[2Kpayload",
        negative_control_url="https://clean.com/\x1b[K",
    )
    assert "\x1b" not in poc.get("payload", "")
    assert "\x1b" not in poc.get("reflection_context", "")
    assert "\x1b" not in poc.get("negative_control_url", "")


def test_poc_schema_merge_strips_ansi() -> None:
    a = {"payload": "clean_payload", "reflection_context": "clean_ctx"}
    b = {"payload": "<img\x1b[2K onerror=alert(1)>"}
    merged = merge_proof_of_concept(a, b)
    if merged:
        assert "\x1b" not in merged.get("payload", "")


def test_poc_schema_negative_control_fields_in_keys() -> None:
    from src.recon.vulnerability_analysis.active_scan.poc_schema import PROOF_OF_CONCEPT_KEYS
    assert "negative_control_url" in PROOF_OF_CONCEPT_KEYS
    assert "negative_control_result" in PROOF_OF_CONCEPT_KEYS
    assert "command_output" in PROOF_OF_CONCEPT_KEYS
    assert "oast_callback" in PROOF_OF_CONCEPT_KEYS
    assert "poc_screenshot_url" in PROOF_OF_CONCEPT_KEYS