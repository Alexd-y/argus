"""Unit tests for :mod:`src.sandbox.parsers.tfsec_parser` (Backlog/dev1_md §4.16 — ARG-021).

Pinned contracts:

* Resolves ``artifacts_dir/tfsec.json`` first, falls back to ``stdout``.
* ``results[]`` envelope (tfsec 1.28.x).
* Severity:

  - ``CRITICAL`` → ``critical`` (LIKELY),
  - ``HIGH`` → ``high`` (LIKELY),
  - ``MEDIUM`` → ``medium`` (SUSPECTED),
  - ``LOW`` → ``low`` (SUSPECTED),
  - missing → ``MEDIUM``, unknown → ``info``.

* Category: every finding → ``MISCONFIG``, CWE ``[16, 1032]``.
* Dedup: composite ``(rule_id, location.filename, location.start_line)``.
* Records missing ``rule_id`` / ``location`` / ``location.filename`` are
  dropped with structured warnings.
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
from src.sandbox.parsers.tfsec_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_tfsec_json,
)


def _result(
    *,
    rule_id: str = "AVD-AWS-0001",
    long_id: str = "aws-s3-enable-bucket-encryption",
    rule_description: str = "Bucket should be encrypted",
    rule_provider: str = "aws",
    rule_service: str = "s3",
    impact: str = "Confidential data is unencrypted at rest",
    resolution: str = "Enable encryption with KMS",
    description: str = "Bucket does not have encryption enabled",
    severity: str | None = "HIGH",
    resource: str = "aws_s3_bucket.example",
    filename: str = "/repo/main.tf",
    start_line: int = 10,
    end_line: int = 15,
    location_present: bool = True,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "rule_id": rule_id,
        "long_id": long_id,
        "rule_description": rule_description,
        "rule_provider": rule_provider,
        "rule_service": rule_service,
        "impact": impact,
        "resolution": resolution,
        "links": ["https://aquasecurity.github.io/tfsec/" + long_id],
        "description": description,
        "warning": False,
        "status": 1,
        "resource": resource,
    }
    if severity is not None:
        record["severity"] = severity
    if location_present:
        record["location"] = {
            "filename": filename,
            "start_line": start_line,
            "end_line": end_line,
        }
    return record


def _payload(*results: dict[str, Any]) -> bytes:
    return json.dumps({"results": list(results)}).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_tfsec_json(b"", b"", tmp_path, "tfsec") == []


def test_canonical_file_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "tfsec.json"
    canonical.write_bytes(_payload(_result(rule_id="AVD-AWS-0001")))
    decoy = _payload(_result(rule_id="AVD-DECOY"))
    findings = parse_tfsec_json(decoy, b"", tmp_path, "tfsec")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "AVD-AWS-0001" in sidecar


def test_severity_critical_likely(tmp_path: Path) -> None:
    payload = _payload(_result(severity="CRITICAL"))
    findings = parse_tfsec_json(payload, b"", tmp_path, "tfsec")
    assert findings[0].cvss_v3_score == pytest.approx(9.0)
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_severity_high_likely(tmp_path: Path) -> None:
    payload = _payload(_result(severity="HIGH"))
    findings = parse_tfsec_json(payload, b"", tmp_path, "tfsec")
    assert findings[0].cvss_v3_score == pytest.approx(7.5)
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_severity_medium_suspected(tmp_path: Path) -> None:
    payload = _payload(_result(severity="MEDIUM"))
    findings = parse_tfsec_json(payload, b"", tmp_path, "tfsec")
    assert findings[0].cvss_v3_score == pytest.approx(5.0)
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_severity_low_suspected(tmp_path: Path) -> None:
    payload = _payload(_result(severity="LOW"))
    findings = parse_tfsec_json(payload, b"", tmp_path, "tfsec")
    assert findings[0].cvss_v3_score == pytest.approx(3.0)
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_missing_severity_defaults_to_medium(tmp_path: Path) -> None:
    payload = _payload(_result(severity=None))
    findings = parse_tfsec_json(payload, b"", tmp_path, "tfsec")
    assert findings[0].cvss_v3_score == pytest.approx(5.0)


def test_unknown_severity_collapses_to_info(tmp_path: Path) -> None:
    payload = _payload(_result(severity="HUGE"))
    findings = parse_tfsec_json(payload, b"", tmp_path, "tfsec")
    assert findings[0].cvss_v3_score == pytest.approx(0.0)


def test_findings_get_misconfig_category(tmp_path: Path) -> None:
    payload = _payload(_result())
    findings = parse_tfsec_json(payload, b"", tmp_path, "tfsec")
    assert findings[0].category is FindingCategory.MISCONFIG
    assert findings[0].cwe == [16, 1032]


def test_dedup_collapses_identical_record(tmp_path: Path) -> None:
    payload = _payload(
        _result(rule_id="AVD-AWS-0001", filename="/main.tf", start_line=10),
        _result(rule_id="AVD-AWS-0001", filename="/main.tf", start_line=10),
    )
    findings = parse_tfsec_json(payload, b"", tmp_path, "tfsec")
    assert len(findings) == 1


def test_findings_sorted_severity_desc(tmp_path: Path) -> None:
    payload = _payload(
        _result(rule_id="rule-low", severity="LOW", filename="a.tf", start_line=1),
        _result(
            rule_id="rule-crit", severity="CRITICAL", filename="b.tf", start_line=2
        ),
        _result(rule_id="rule-high", severity="HIGH", filename="c.tf", start_line=3),
        _result(rule_id="rule-med", severity="MEDIUM", filename="d.tf", start_line=4),
    )
    parse_tfsec_json(payload, b"", tmp_path, "tfsec")
    rows = [
        json.loads(line)
        for line in (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    ]
    assert [r["rule_id"] for r in rows] == [
        "rule-crit",
        "rule-high",
        "rule-med",
        "rule-low",
    ]


def test_envelope_not_dict_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        findings = parse_tfsec_json(b"[]", b"", tmp_path, "tfsec")
    assert findings == []
    assert any(
        "tfsec_parser_envelope_not_dict" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_missing_location_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    bad = _result(location_present=False)
    payload = _payload(bad, _result(rule_id="AVD-OK"))
    with caplog.at_level(logging.WARNING):
        findings = parse_tfsec_json(payload, b"", tmp_path, "tfsec")
    assert len(findings) == 1
    assert any(
        "tfsec_parser_result_missing_field" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_missing_rule_id_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    bad = _result()
    bad.pop("rule_id")
    payload = _payload(bad, _result(rule_id="AVD-OK"))
    with caplog.at_level(logging.WARNING):
        findings = parse_tfsec_json(payload, b"", tmp_path, "tfsec")
    assert len(findings) == 1


def test_malformed_json_returns_empty(tmp_path: Path) -> None:
    assert parse_tfsec_json(b"not-json", b"", tmp_path, "tfsec") == []


def test_no_results_returns_empty(tmp_path: Path) -> None:
    assert (
        parse_tfsec_json(
            json.dumps({"results": []}).encode("utf-8"), b"", tmp_path, "tfsec"
        )
        == []
    )


def test_evidence_sidecar_includes_tool_id_and_kind(tmp_path: Path) -> None:
    payload = _payload(_result(rule_id="AVD-AWS-0001"))
    parse_tfsec_json(payload, b"", tmp_path, "tfsec-tf")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["tool_id"] == "tfsec-tf"
    assert blob["kind"] == "tfsec"
    assert blob["rule_id"] == "AVD-AWS-0001"
