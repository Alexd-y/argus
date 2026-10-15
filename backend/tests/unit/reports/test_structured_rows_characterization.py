"""Wave 4 / Stage 6 — characterization of the Valhalla structured-row section.

Written BEFORE the section is moved out of the valhalla_report_context monolith
(R-6.3.1/3): they pin the current behaviour of the XSS/CSRF/CMDi structured-row
builders + their shared helpers so the extraction is provably behaviour-preserving.
The imports deliberately come from the public ``valhalla_report_context`` module so
they keep passing whether the code lives in the monolith or a re-exported submodule.
"""

from __future__ import annotations

import json

from src.reports.valhalla_report_context import (
    ValhallaCmdiStructuredRowModel,
    ValhallaCsrfStructuredRowModel,
    ValhallaXssStructuredRowModel,
    _finding_id_for_risk,
    _truncate,
    build_cmdi_structured_rows_from_findings,
    build_csrf_structured_rows_from_findings,
    build_xss_structured_rows_from_findings,
    finding_qualifies_for_xss_structured_context,
    serialize_xss_structured_for_ai,
)


def test_truncate_behaviour() -> None:
    assert _truncate("short", 100) == "short"
    assert _truncate("  spaced  ", 100) == "spaced"
    out = _truncate("abcdefghij", 5)
    assert out.endswith("…") and len(out) == 5


def test_finding_id_for_risk_fallback() -> None:
    assert _finding_id_for_risk({"finding_id": "F-9"}, 3) == "F-9"
    assert _finding_id_for_risk({"id": "X-1"}, 3) == "X-1"
    assert _finding_id_for_risk({}, 7) == "finding-7"


def test_xss_qualification() -> None:
    assert finding_qualifies_for_xss_structured_context({"cwe": "CWE-79"}) is True
    assert finding_qualifies_for_xss_structured_context({"cwe": "CWE-200"}) is False
    assert (
        finding_qualifies_for_xss_structured_context(
            {"title": "Reflected XSS", "proof_of_concept": {"payload_entered": "<script>"}}
        )
        is True
    )


def test_build_xss_rows() -> None:
    findings = [
        {
            "finding_id": "F-1",
            "title": "Reflected XSS in q",
            "cwe": "CWE-79",
            "proof_of_concept": {
                "parameter": "q",
                "payload_entered": "<script>alert(1)</script>",
                "reflection_context": "html_body",
                "verified_via_browser": True,
                "browser_alert_text": "1",
                "screenshot_key": "tenant/scan/evidence/shot-1.bin",
            },
        }
    ]
    rows = build_xss_structured_rows_from_findings(findings)
    assert len(rows) == 1
    r = rows[0]
    assert isinstance(r, ValhallaXssStructuredRowModel)
    assert r.finding_id == "F-1"
    assert r.parameter == "q"
    assert r.verified_via_browser is True
    assert r.browser_alert_text == "1"
    assert "tenant/scan/evidence/shot-1.bin" in r.artifact_keys


def test_build_csrf_rows() -> None:
    findings = [
        {
            "finding_id": "F-2",
            "title": "CSRF on profile update",
            "proof_of_concept": {"endpoint": "/profile", "method": "POST", "state_changing": True},
        }
    ]
    rows = build_csrf_structured_rows_from_findings(findings)
    assert len(rows) == 1
    assert isinstance(rows[0], ValhallaCsrfStructuredRowModel)
    assert rows[0].endpoint == "/profile"
    assert rows[0].state_changing is True


def test_build_cmdi_rows() -> None:
    findings = [
        {
            "finding_id": "F-3",
            "title": "Command Injection",
            "cwe": "CWE-78",
            "proof_of_concept": {"parameter": "host", "payload": "; id", "server_proof": "uid=0"},
        }
    ]
    rows = build_cmdi_structured_rows_from_findings(findings)
    assert len(rows) == 1
    assert isinstance(rows[0], ValhallaCmdiStructuredRowModel)
    assert rows[0].parameter == "host"
    assert rows[0].payload == "; id"


def test_serialize_xss_for_ai_roundtrips() -> None:
    rows = build_xss_structured_rows_from_findings(
        [{"finding_id": "F-1", "cwe": "CWE-79", "proof_of_concept": {"parameter": "q"}}]
    )
    text = serialize_xss_structured_for_ai(rows)
    parsed = [json.loads(line) for line in text.splitlines() if line]
    assert parsed and parsed[0]["finding_id"] == "F-1"
