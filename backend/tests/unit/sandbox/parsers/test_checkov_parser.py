"""Unit tests for :mod:`src.sandbox.parsers.checkov_parser` (Backlog/dev1_md §4.15 — ARG-021).

Pinned contracts:

* Resolves ``artifacts_dir/checkov.json`` first, falls back to ``stdout``.
* Accepts both single-runner (dict) and multi-runner (list) envelopes.
* Reads ONLY ``results.failed_checks``; passed/skipped/parsing_errors
  are intentionally ignored.
* Severity mapping (Checkov uppercase → ARGUS lowercase) is one-to-one
  for ``CRITICAL/HIGH/MEDIUM/LOW``; anything else collapses to ``info``;
  missing severity defaults to ``MEDIUM``.
* Confidence: ``CRITICAL`` / ``HIGH`` → ``LIKELY``; everything else →
  ``SUSPECTED``.
* Category: defaults to ``MISCONFIG``; ``CKV_SECRET_*`` / ``CKV_GIT_*``
  routes to ``SECRET_LEAK`` (with CWE-798 + WSTG-ATHN-06).
* Dedup: composite ``(check_id, file_path, start_line)``.
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
from src.sandbox.parsers.checkov_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_checkov_json,
)


def _failed_check(
    *,
    check_id: str = "CKV_AWS_20",
    bc_check_id: str = "BC_AWS_S3_1",
    check_name: str = "S3 bucket has an ACL of public-read or public-read-write",
    file_path: str = "/main.tf",
    file_abs_path: str = "/repo/main.tf",
    file_line_range: list[int] | None = None,
    resource: str = "aws_s3_bucket.public",
    severity: str | None = "HIGH",
    guideline: str = "https://docs.bridgecrew.io/aws/s3-public",
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "check_id": check_id,
        "bc_check_id": bc_check_id,
        "check_name": check_name,
        "check_class": f"checkov.terraform.checks.resource.aws.{check_id}",
        "file_path": file_path,
        "file_abs_path": file_abs_path,
        "file_line_range": file_line_range or [10, 20],
        "resource": resource,
        "guideline": guideline,
    }
    if severity is not None:
        record["severity"] = severity
    return record


def _runner(
    *,
    check_type: str = "terraform",
    failed: list[dict[str, Any]] | None = None,
    passed: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "check_type": check_type,
        "results": {
            "passed_checks": passed or [],
            "failed_checks": failed if failed is not None else [_failed_check()],
            "skipped_checks": [],
            "parsing_errors": [],
        },
        "summary": {
            "passed": len(passed or []),
            "failed": len(failed or [_failed_check()]),
        },
    }


def _payload_single(*failed: dict[str, Any]) -> bytes:
    return json.dumps(_runner(failed=list(failed))).encode("utf-8")


def _payload_multi(*runners: dict[str, Any]) -> bytes:
    return json.dumps(list(runners)).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_checkov_json(b"", b"", tmp_path, "checkov") == []


def test_canonical_file_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "checkov.json"
    canonical.write_bytes(_payload_single(_failed_check(check_id="CKV_AWS_20")))
    decoy = _payload_single(_failed_check(check_id="CKV_DECOY_99"))
    findings = parse_checkov_json(decoy, b"", tmp_path, "checkov")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "CKV_AWS_20" in sidecar


def test_multi_runner_envelope(tmp_path: Path) -> None:
    payload = _payload_multi(
        _runner(check_type="terraform", failed=[_failed_check(check_id="CKV_AWS_20")]),
        _runner(
            check_type="kubernetes",
            failed=[
                _failed_check(
                    check_id="CKV_K8S_1",
                    file_path="/deploy.yaml",
                    severity="MEDIUM",
                )
            ],
        ),
    )
    findings = parse_checkov_json(payload, b"", tmp_path, "checkov")
    assert len(findings) == 2


def test_severity_critical_maps_to_critical_and_likely(tmp_path: Path) -> None:
    payload = _payload_single(_failed_check(severity="CRITICAL"))
    findings = parse_checkov_json(payload, b"", tmp_path, "checkov")
    assert findings[0].cvss_v3_score == pytest.approx(9.0)
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_severity_high_maps_to_high_and_likely(tmp_path: Path) -> None:
    payload = _payload_single(_failed_check(severity="HIGH"))
    findings = parse_checkov_json(payload, b"", tmp_path, "checkov")
    assert findings[0].cvss_v3_score == pytest.approx(7.5)
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_severity_medium_maps_to_medium_and_suspected(tmp_path: Path) -> None:
    payload = _payload_single(_failed_check(severity="MEDIUM"))
    findings = parse_checkov_json(payload, b"", tmp_path, "checkov")
    assert findings[0].cvss_v3_score == pytest.approx(5.0)
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_severity_low_maps_to_low_and_suspected(tmp_path: Path) -> None:
    payload = _payload_single(_failed_check(severity="LOW"))
    findings = parse_checkov_json(payload, b"", tmp_path, "checkov")
    assert findings[0].cvss_v3_score == pytest.approx(3.0)
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_missing_severity_defaults_to_medium(tmp_path: Path) -> None:
    payload = _payload_single(_failed_check(severity=None))
    findings = parse_checkov_json(payload, b"", tmp_path, "checkov")
    assert findings[0].cvss_v3_score == pytest.approx(5.0)


def test_unknown_severity_collapses_to_info(tmp_path: Path) -> None:
    payload = _payload_single(_failed_check(severity="WHATEVER"))
    findings = parse_checkov_json(payload, b"", tmp_path, "checkov")
    assert findings[0].cvss_v3_score == pytest.approx(0.0)


def test_default_findings_get_misconfig_category(tmp_path: Path) -> None:
    payload = _payload_single(_failed_check(check_id="CKV_AWS_20"))
    findings = parse_checkov_json(payload, b"", tmp_path, "checkov")
    assert findings[0].category is FindingCategory.MISCONFIG
    assert findings[0].cwe == [16, 1032]


def test_secret_check_routes_to_secret_leak(tmp_path: Path) -> None:
    payload = _payload_single(
        _failed_check(check_id="CKV_SECRET_6", check_name="AWS access key in source")
    )
    findings = parse_checkov_json(payload, b"", tmp_path, "checkov")
    assert findings[0].category is FindingCategory.SECRET_LEAK
    assert findings[0].cwe == [798]
    assert "WSTG-ATHN-06" in findings[0].owasp_wstg


def test_dedup_collapses_identical_check(tmp_path: Path) -> None:
    duplicate = _failed_check(
        check_id="CKV_AWS_20", file_path="/main.tf", file_line_range=[10, 20]
    )
    payload = _payload_single(duplicate, dict(duplicate))
    findings = parse_checkov_json(payload, b"", tmp_path, "checkov")
    assert len(findings) == 1


def test_findings_sorted_severity_desc(tmp_path: Path) -> None:
    payload = _payload_single(
        _failed_check(check_id="CKV_LOW", severity="LOW", file_path="/a.tf"),
        _failed_check(check_id="CKV_CRIT", severity="CRITICAL", file_path="/b.tf"),
        _failed_check(check_id="CKV_MED", severity="MEDIUM", file_path="/c.tf"),
    )
    parse_checkov_json(payload, b"", tmp_path, "checkov")
    rows = [
        json.loads(line)
        for line in (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    ]
    assert [r["check_id"] for r in rows] == ["CKV_CRIT", "CKV_MED", "CKV_LOW"]


def test_envelope_unexpected_type_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        findings = parse_checkov_json(b'"a string"', b"", tmp_path, "checkov")
    assert findings == []
    assert any(
        "checkov_parser_envelope_unexpected_type"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_missing_check_id_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    bad = _failed_check()
    bad.pop("check_id")
    payload = _payload_single(bad, _failed_check(check_id="CKV_AWS_99"))
    with caplog.at_level(logging.WARNING):
        findings = parse_checkov_json(payload, b"", tmp_path, "checkov")
    assert len(findings) == 1
    assert any(
        "checkov_parser_result_missing_field" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_malformed_json_returns_empty(tmp_path: Path) -> None:
    assert parse_checkov_json(b"{garbage", b"", tmp_path, "checkov") == []


def test_runner_without_failed_checks_returns_empty(tmp_path: Path) -> None:
    payload = json.dumps(_runner(failed=[])).encode("utf-8")
    assert parse_checkov_json(payload, b"", tmp_path, "checkov") == []


def test_evidence_sidecar_includes_tool_id_and_kind(tmp_path: Path) -> None:
    payload = _payload_single(_failed_check(check_id="CKV_AWS_20"))
    parse_checkov_json(payload, b"", tmp_path, "checkov-cloud")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["tool_id"] == "checkov-cloud"
    assert blob["kind"] == "checkov"
    assert blob["check_id"] == "CKV_AWS_20"
    assert blob["check_type"] == "terraform"
