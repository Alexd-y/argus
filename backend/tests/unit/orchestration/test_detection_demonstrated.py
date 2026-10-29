"""exploit_demonstrated is carried from a detection that IS the demonstration.

A headless-browser-verified XSS (reflected verifier / DOM-XSS sweep) and a
sqlmap-confirmed injection already prove execution; the persist step must mark
them exploit_demonstrated even when the exploitation phase's executor produced no
separate exploit (e.g. no re-confirmation tool for a client-side DOM sink).
"""

from __future__ import annotations

from src.orchestration.state_machine import _detection_demonstrated_summary


def test_browser_verified_xss_is_demonstrated() -> None:
    assert _detection_demonstrated_summary(
        {"proof_of_concept": {"tool": "dom_xss_browser", "verified_via_browser": True}}
    )
    assert _detection_demonstrated_summary(
        {"proof_of_concept": {"browser_alert_text": "ARGUSDOMXSSabc123"}}
    )


def test_sqlmap_confirmed_injection_is_demonstrated() -> None:
    assert _detection_demonstrated_summary(
        {"source_tool": "sqlmap", "proof_of_concept": {"tool": "sqlmap", "payload": "a' OR 1=1--"}}
    )
    assert _detection_demonstrated_summary(
        {"proof_of_concept": {"tool": "sqlmap", "replay_command": ["sqlmap", "-u", "x"]}}
    )


def test_non_demonstrating_findings_return_empty() -> None:
    # Missing-headers / fingerprint style findings have no execution evidence.
    assert _detection_demonstrated_summary({"proof_of_concept": {"tool": "whatweb"}}) == ""
    assert _detection_demonstrated_summary({"title": "Missing Security Headers"}) == ""
    # A dalfox *candidate* without browser verification is not a demonstration.
    assert _detection_demonstrated_summary(
        {"source_tool": "dalfox", "proof_of_concept": {"tool": "dalfox", "payload": "<x>"}}
    ) == ""
