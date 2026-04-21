"""Unit tests for :mod:`src.sandbox.parsers.terrascan_parser` (Backlog/dev1_md §4.16 — ARG-021).

Pinned contracts:

* Resolves ``artifacts_dir/terrascan.json`` first, falls back to ``stdout``.
* ``results.violations[]`` envelope (Terrascan 1.18.x).
* Severity:

  - ``HIGH`` → ``high`` (LIKELY confidence),
  - ``MEDIUM`` → ``medium`` (SUSPECTED confidence),
  - ``LOW`` → ``low`` (SUSPECTED confidence),
  - missing → ``MEDIUM`` (default), unknown → ``info``.

* Category: defaults to ``MISCONFIG``; ``Secret*`` /
  ``Credentials`` keywords route to ``SECRET_LEAK`` (CWE-798).
* Dedup: composite ``(rule_id, file, line)``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.terrascan_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_terrascan_json,
)


def _violation(
    *,
    rule_id: str = "AC_AWS_0319",
    rule_name: str = "ensureSecurityGroupNotOpenToInternet",
    description: str = "It is recommended that no security group allows unrestricted ingress access",
    severity: str | None = "HIGH",
    category: str = "Network Ports Security",
    resource_name: str = "main",
    resource_type: str = "aws_security_group",
    module_name: str = "root",
    file: str = "main.tf",
    line: int = 25,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "rule_name": rule_name,
        "description": description,
        "rule_id": rule_id,
        "category": category,
        "resource_name": resource_name,
        "resource_type": resource_type,
        "module_name": module_name,
        "file": file,
        "plan_root": "./",
        "line": line,
    }
    if severity is not None:
        record["severity"] = severity
    return record


def _payload(*violations: dict[str, Any]) -> bytes:
    envelope = {
        "results": {
            "violations": list(violations),
            "skipped_violations": [],
            "scan_summary": {"file_folder": "./", "iac_type": "terraform"},
        }
    }
    return json.dumps(envelope).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_terrascan_json(b"", b"", tmp_path, "terrascan") == []


def test_canonical_file_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "terrascan.json"
    canonical.write_bytes(_payload(_violation(rule_id="AC_AWS_0319")))
    decoy = _payload(_violation(rule_id="AC_DECOY"))
    findings = parse_terrascan_json(decoy, b"", tmp_path, "terrascan")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "AC_AWS_0319" in sidecar


def test_severity_high_likely(tmp_path: Path) -> None:
    payload = _payload(_violation(severity="HIGH"))
    findings = parse_terrascan_json(payload, b"", tmp_path, "terrascan")
    assert findings[0].cvss_v3_score == pytest.approx(7.5)
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_severity_medium_suspected(tmp_path: Path) -> None:
    payload = _payload(_violation(severity="MEDIUM"))
    findings = parse_terrascan_json(payload, b"", tmp_path, "terrascan")
    assert findings[0].cvss_v3_score == pytest.approx(5.0)
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_severity_low_suspected(tmp_path: Path) -> None:
    payload = _payload(_violation(severity="LOW"))
    findings = parse_terrascan_json(payload, b"", tmp_path, "terrascan")
    assert findings[0].cvss_v3_score == pytest.approx(3.0)
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_missing_severity_defaults_to_medium(tmp_path: Path) -> None:
    payload = _payload(_violation(severity=None))
    findings = parse_terrascan_json(payload, b"", tmp_path, "terrascan")
    assert findings[0].cvss_v3_score == pytest.approx(5.0)


def test_unknown_severity_collapses_to_info(tmp_path: Path) -> None:
    payload = _payload(_violation(severity="EXTREME"))
    findings = parse_terrascan_json(payload, b"", tmp_path, "terrascan")
    assert findings[0].cvss_v3_score == pytest.approx(0.0)


def test_default_findings_get_misconfig_category(tmp_path: Path) -> None:
    payload = _payload(_violation())
    findings = parse_terrascan_json(payload, b"", tmp_path, "terrascan")
    assert findings[0].category is FindingCategory.MISCONFIG
    assert findings[0].cwe == [16, 1032]


def test_secret_category_routes_to_secret_leak(tmp_path: Path) -> None:
    payload = _payload(_violation(category="Secrets Management"))
    findings = parse_terrascan_json(payload, b"", tmp_path, "terrascan")
    assert findings[0].category is FindingCategory.SECRET_LEAK
    assert findings[0].cwe == [798]
    assert "WSTG-ATHN-06" in findings[0].owasp_wstg


def test_credentials_category_routes_to_secret_leak(tmp_path: Path) -> None:
    payload = _payload(_violation(category="Credentials Hardcoded"))
    findings = parse_terrascan_json(payload, b"", tmp_path, "terrascan")
    assert findings[0].category is FindingCategory.SECRET_LEAK


def test_dedup_collapses_identical_record(tmp_path: Path) -> None:
    payload = _payload(
        _violation(rule_id="AC_AWS_0319", file="main.tf", line=25),
        _violation(rule_id="AC_AWS_0319", file="main.tf", line=25),
    )
    findings = parse_terrascan_json(payload, b"", tmp_path, "terrascan")
    assert len(findings) == 1


def test_findings_sorted_severity_desc(tmp_path: Path) -> None:
    payload = _payload(
        _violation(rule_id="rule-low", severity="LOW", file="a.tf", line=1),
        _violation(rule_id="rule-high", severity="HIGH", file="b.tf", line=2),
        _violation(rule_id="rule-medium", severity="MEDIUM", file="c.tf", line=3),
    )
    parse_terrascan_json(payload, b"", tmp_path, "terrascan")
    rows = [
        json.loads(line)
        for line in (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    ]
    assert [r["rule_id"] for r in rows] == ["rule-high", "rule-medium", "rule-low"]


def test_envelope_not_dict_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        findings = parse_terrascan_json(b"[]", b"", tmp_path, "terrascan")
    assert findings == []
    assert any(
        "terrascan_parser_envelope_not_dict" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_missing_rule_id_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    bad = _violation()
    bad.pop("rule_id")
    payload = _payload(bad, _violation(rule_id="AC_OK"))
    with caplog.at_level(logging.WARNING):
        findings = parse_terrascan_json(payload, b"", tmp_path, "terrascan")
    assert len(findings) == 1
    assert any(
        "terrascan_parser_violation_missing_field"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_malformed_json_returns_empty(tmp_path: Path) -> None:
    assert parse_terrascan_json(b"not-json", b"", tmp_path, "terrascan") == []


def test_no_violations_returns_empty(tmp_path: Path) -> None:
    payload = json.dumps(
        {"results": {"violations": [], "skipped_violations": []}}
    ).encode("utf-8")
    assert parse_terrascan_json(payload, b"", tmp_path, "terrascan") == []


def test_evidence_sidecar_includes_tool_id_and_kind(tmp_path: Path) -> None:
    payload = _payload(_violation(rule_id="AC_AWS_0319"))
    parse_terrascan_json(payload, b"", tmp_path, "terrascan-iac")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["tool_id"] == "terrascan-iac"
    assert blob["kind"] == "terrascan"
    assert blob["rule_id"] == "AC_AWS_0319"
