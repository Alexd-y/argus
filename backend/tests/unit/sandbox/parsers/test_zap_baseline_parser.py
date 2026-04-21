"""Unit tests for :mod:`src.sandbox.parsers.zap_baseline_parser` (Backlog §4.8 — ARG-029).

Pinned contracts:

* Canonical artefact ``zap_baseline.json`` overrides stdout.
* ``riskcode`` → severity (0 info, 1 low, 2 medium, 3 high) → CVSS map.
* ``confidence`` ``"0"`` (false-positive) drops the alert entirely.
* Each ``(alert × instance)`` pair becomes a separate finding.
* ``cweid`` is parsed defensively — ``"-1"``, ``""``, non-numeric all
  fall back to keyword classification.
* Title keywords route to specific categories (XSS, SQLI, CSRF, etc.).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers import zap_baseline_parser as zap_module
from src.sandbox.parsers.zap_baseline_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_zap_baseline_json,
)


def _alert(
    *,
    pluginid: str = "10202",
    name: str = "Absence of Anti-CSRF Tokens",
    riskcode: str = "1",
    confidence: str = "2",
    cweid: str = "352",
    instances: list[dict[str, Any]] | None = None,
    desc: str = "<p>No Anti-CSRF tokens were found.</p>",
    solution: str = "<p>Use a CSRF token.</p>",
) -> dict[str, Any]:
    return {
        "pluginid": pluginid,
        "alert": name,
        "name": name,
        "riskcode": riskcode,
        "riskdesc": "Low (Medium)",
        "confidence": confidence,
        "cweid": cweid,
        "wascid": "9",
        "instances": instances
        or [
            {
                "uri": "https://target.example.com/login",
                "method": "GET",
                "param": "",
                "evidence": "<form action='/login'>",
            }
        ],
        "desc": desc,
        "solution": solution,
        "reference": "https://owasp.org/csrf",
        "sourceid": "3",
    }


def _payload(
    *alerts: dict[str, Any], site_name: str = "https://target.example.com"
) -> bytes:
    document = {
        "@version": "2.14.0",
        "@generated": "Mon, 19 May 2026 10:00:00",
        "site": [{"@name": site_name, "alerts": list(alerts)}],
    }
    return json.dumps(document).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_zap_baseline_json(b"", b"", tmp_path, "zap_baseline") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "zap_baseline.json"
    canonical.write_bytes(_payload(_alert(pluginid="canonical")))
    decoy = _payload(_alert(pluginid="decoy"))
    findings = parse_zap_baseline_json(decoy, b"", tmp_path, "zap_baseline")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "canonical" in sidecar
    assert "decoy" not in sidecar


def test_false_positive_alert_dropped(tmp_path: Path) -> None:
    payload = _payload(
        _alert(confidence="0"),
        _alert(pluginid="20100", confidence="3"),
    )
    findings = parse_zap_baseline_json(payload, b"", tmp_path, "zap_baseline")
    assert len(findings) == 1


def test_riskcode_to_severity_mapping(tmp_path: Path) -> None:
    payload = _payload(
        _alert(pluginid="info", riskcode="0"),
        _alert(pluginid="low", riskcode="1"),
        _alert(pluginid="med", riskcode="2"),
        _alert(pluginid="high", riskcode="3"),
    )
    findings = parse_zap_baseline_json(payload, b"", tmp_path, "zap_baseline")
    scores = sorted(f.cvss_v3_score for f in findings)
    assert scores == pytest.approx([0.0, 3.0, 5.0, 7.5])


def test_xss_alert_routes_to_xss_with_cwe_79(tmp_path: Path) -> None:
    findings = parse_zap_baseline_json(
        _payload(_alert(name="Cross-Site Scripting (Reflected)", cweid="79")),
        b"",
        tmp_path,
        "zap_baseline",
    )
    assert findings[0].category is FindingCategory.XSS
    assert 79 in findings[0].cwe


def test_csrf_alert_routes_to_csrf_with_cwe_352(tmp_path: Path) -> None:
    findings = parse_zap_baseline_json(
        _payload(_alert(name="Absence of Anti-CSRF Tokens")),
        b"",
        tmp_path,
        "zap_baseline",
    )
    assert findings[0].category is FindingCategory.CSRF
    assert 352 in findings[0].cwe


def test_open_redirect_routes_to_open_redirect(tmp_path: Path) -> None:
    findings = parse_zap_baseline_json(
        _payload(_alert(name="Open Redirect", cweid="601")),
        b"",
        tmp_path,
        "zap_baseline",
    )
    assert findings[0].category is FindingCategory.OPEN_REDIRECT
    assert 601 in findings[0].cwe


def test_invalid_cweid_falls_back_to_keyword(tmp_path: Path) -> None:
    findings = parse_zap_baseline_json(
        _payload(_alert(name="Cross-Site Scripting (Stored)", cweid="-1")),
        b"",
        tmp_path,
        "zap_baseline",
    )
    assert findings[0].category is FindingCategory.XSS
    assert 79 in findings[0].cwe


def test_each_instance_emits_own_finding(tmp_path: Path) -> None:
    instances = [
        {"uri": "/a", "method": "GET", "param": ""},
        {"uri": "/b", "method": "POST", "param": "id"},
        {"uri": "/c", "method": "GET", "param": ""},
    ]
    payload = _payload(_alert(instances=instances))
    findings = parse_zap_baseline_json(payload, b"", tmp_path, "zap_baseline")
    assert len(findings) == 3


def test_dedup_collapses_same_pluginid_uri_method_param(tmp_path: Path) -> None:
    instances = [
        {"uri": "/a", "method": "GET", "param": ""},
        {"uri": "/a", "method": "GET", "param": ""},
    ]
    payload = _payload(_alert(instances=instances))
    findings = parse_zap_baseline_json(payload, b"", tmp_path, "zap_baseline")
    assert len(findings) == 1


def test_html_stripped_from_description(tmp_path: Path) -> None:
    parse_zap_baseline_json(
        _payload(
            _alert(
                desc="<p>Anti-<b>CSRF</b> tokens missing.</p>",
                solution="<ul><li>Add token</li></ul>",
            )
        ),
        b"",
        tmp_path,
        "zap_baseline",
    )
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "<p>" not in sidecar
    assert "<b>" not in sidecar
    assert "Anti-CSRF tokens missing" in sidecar


def test_envelope_not_object_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    canonical = tmp_path / "zap_baseline.json"
    canonical.write_bytes(b'["not", "envelope"]')
    with caplog.at_level("WARNING"):
        findings = parse_zap_baseline_json(b"", b"", tmp_path, "zap_baseline")
    assert findings == []
    assert any(
        "zap_baseline_parser_envelope_not_object"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_confidence_4_user_confirmed(tmp_path: Path) -> None:
    findings = parse_zap_baseline_json(
        _payload(_alert(confidence="4")),
        b"",
        tmp_path,
        "zap_baseline",
    )
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


def test_findings_sorted_by_severity_descending(tmp_path: Path) -> None:
    payload = _payload(
        _alert(pluginid="low", riskcode="1", name="Cookie No HttpOnly"),
        _alert(pluginid="high", riskcode="3", name="SQL Injection", cweid="89"),
        _alert(pluginid="med", riskcode="2", name="Anti-CSRF Tokens"),
    )
    findings = parse_zap_baseline_json(payload, b"", tmp_path, "zap_baseline")
    scores = [f.cvss_v3_score for f in findings]
    assert scores == sorted(scores, reverse=True)


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(zap_module, "_MAX_FINDINGS", 2)
    payload = _payload(*(_alert(pluginid=f"id-{i}") for i in range(5)))
    with caplog.at_level("WARNING"):
        findings = parse_zap_baseline_json(payload, b"", tmp_path, "zap_baseline")
    assert len(findings) == 2
    assert any(
        "zap_baseline_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_payload_with_only_false_positives_returns_empty(tmp_path: Path) -> None:
    """Cover the post-iteration ``if not records`` early-exit branch."""
    payload = _payload(_alert(confidence="0"), _alert(confidence="0"))
    assert parse_zap_baseline_json(payload, b"", tmp_path, "zap_baseline") == []


def test_site_field_not_a_list_returns_empty(tmp_path: Path) -> None:
    """Top-level ``site`` must be a list — otherwise the report is unusable."""
    document: dict[str, Any] = {"site": "scalar"}
    assert (
        parse_zap_baseline_json(
            json.dumps(document).encode("utf-8"), b"", tmp_path, "zap_baseline"
        )
        == []
    )


def test_site_entry_not_a_dict_skipped(tmp_path: Path) -> None:
    """Non-dict site entries are silently skipped."""
    document: dict[str, Any] = {"site": ["bad", {"@name": "x", "alerts": [_alert()]}]}
    findings = parse_zap_baseline_json(
        json.dumps(document).encode("utf-8"), b"", tmp_path, "zap_baseline"
    )
    assert len(findings) == 1


def test_alerts_field_not_a_list_skipped(tmp_path: Path) -> None:
    """Sites where ``alerts`` is not a list are skipped without raising."""
    document: dict[str, Any] = {"site": [{"@name": "x", "alerts": "not-a-list"}]}
    assert (
        parse_zap_baseline_json(
            json.dumps(document).encode("utf-8"), b"", tmp_path, "zap_baseline"
        )
        == []
    )


def test_alert_not_object_skipped_with_debug(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Non-object entries inside ``alerts[]`` are dropped with a debug log."""
    document: dict[str, Any] = {"site": [{"@name": "x", "alerts": ["bad", _alert()]}]}
    with caplog.at_level("DEBUG", logger=zap_module._logger.name):
        findings = parse_zap_baseline_json(
            json.dumps(document).encode("utf-8"), b"", tmp_path, "zap_baseline"
        )
    assert len(findings) == 1
    assert any(
        "zap_baseline_parser_alert_not_object" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_alert_without_instances_emits_one_placeholder(tmp_path: Path) -> None:
    """An alert without a populated ``instances[]`` still emits ONE finding so
    operators see the alert exists; uri/method/param are explicitly null."""
    raw_alert = _alert()
    raw_alert.pop("instances")
    document: dict[str, Any] = {
        "site": [{"@name": "https://target.example.com", "alerts": [raw_alert]}]
    }
    findings = parse_zap_baseline_json(
        json.dumps(document).encode("utf-8"), b"", tmp_path, "zap_baseline"
    )
    assert len(findings) == 1
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "uri" not in blob


def test_instance_entry_not_dict_skipped(tmp_path: Path) -> None:
    """Non-dict instance entries are skipped without raising."""
    raw_alert = _alert()
    raw_alert["instances"] = [
        "not-a-dict",
        {
            "uri": "https://target.example.com/login",
            "method": "GET",
            "param": "",
        },
    ]
    document: dict[str, Any] = {
        "site": [{"@name": "https://target.example.com", "alerts": [raw_alert]}]
    }
    findings = parse_zap_baseline_json(
        json.dumps(document).encode("utf-8"), b"", tmp_path, "zap_baseline"
    )
    assert len(findings) == 1


def test_unknown_alert_with_known_cweid_routes_to_misconfig(tmp_path: Path) -> None:
    """No keyword match but a valid CWE → MISCONFIG with that CWE preserved."""
    payload = _payload(_alert(name="Some Brand New Alert", cweid="611", riskcode="1"))
    findings = parse_zap_baseline_json(payload, b"", tmp_path, "zap_baseline")
    assert findings[0].category is FindingCategory.MISCONFIG
    assert 611 in findings[0].cwe


def test_long_description_truncated_with_ellipsis(tmp_path: Path) -> None:
    """Description preview must be capped at ``_MAX_DESC_PREVIEW``."""
    long_text = "abc " * 200
    payload = _payload(_alert(desc=long_text, solution="Short."))
    parse_zap_baseline_json(payload, b"", tmp_path, "zap_baseline")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["description"].endswith("…")


def test_plain_text_description_passes_through_without_html_stripper(
    tmp_path: Path,
) -> None:
    """A description without HTML chars must NOT be routed through HTMLParser."""
    payload = _payload(
        _alert(desc="Plain text description with multiple   spaces.", solution="Plain.")
    )
    parse_zap_baseline_json(payload, b"", tmp_path, "zap_baseline")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["description"] == "Plain text description with multiple spaces."
