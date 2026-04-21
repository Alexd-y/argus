"""Unit tests for :mod:`src.sandbox.parsers.bandit_parser` (Backlog/dev1_md §4.16 — ARG-021).

Pinned contracts:

* Resolves ``artifacts_dir/bandit.json`` first, then falls back to ``stdout``.
* Severity mapping: ``HIGH`` / ``MEDIUM`` / ``LOW`` → identical buckets;
  unknown collapses to ``info``.
* Confidence mapping: ``HIGH`` → CONFIRMED, ``MEDIUM`` → LIKELY,
  ``LOW`` → SUSPECTED.
* CWE extraction prefers ``issue_cwe.id`` (Bandit canonical shape).
* Category routing follows ``CWE → category`` table; falls back to
  test_id-prefix heuristics (``B6xx`` → RCE, ``B5xx``/``B3xx`` → CRYPTO,
  ``B7xx`` → XSS, otherwise MISCONFIG).
* Records collapse on ``(test_id, filename, line_number)`` dedup key.
* Ordering: severity desc → test_id → filename → line.
* Sidecar JSONL stamped with ``tool_id``.
* Fail-soft on malformed envelopes / missing keys.
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
from src.sandbox.parsers.bandit_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_bandit_json,
)


def _result(
    *,
    test_id: str = "B602",
    test_name: str = "subprocess_popen_with_shell_equals_true",
    filename: str = "src/foo.py",
    line: int = 42,
    severity: str = "HIGH",
    confidence: str = "HIGH",
    cwe_id: int | None = 78,
    issue_text: str = "subprocess call with shell=True identified",
    code: str = "  41 import subprocess\n  42 subprocess.run(['ls'], shell=True)",
    line_range: list[int] | None = None,
    more_info: str = "https://bandit.readthedocs.io/...",
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "test_id": test_id,
        "test_name": test_name,
        "filename": filename,
        "line_number": line,
        "issue_severity": severity,
        "issue_confidence": confidence,
        "issue_text": issue_text,
        "code": code,
        "more_info": more_info,
        "col_offset": 9,
    }
    if cwe_id is not None:
        record["issue_cwe"] = {"id": cwe_id, "link": f"https://cwe.mitre.org/{cwe_id}"}
    if line_range is not None:
        record["line_range"] = list(line_range)
    return record


def _envelope(
    *results: dict[str, Any], errors: list[Any] | None = None
) -> dict[str, Any]:
    return {
        "errors": errors or [],
        "generated_at": "2026-04-19T12:00:00Z",
        "metrics": {"_totals": {"loc": 100, "nosec": 0}},
        "results": list(results),
    }


def _payload(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_bandit_json(b"", b"", tmp_path, "bandit") == []


def test_canonical_file_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "bandit.json"
    canonical.write_bytes(_payload(_envelope(_result(test_id="B602"))))
    decoy = _payload(_envelope(_result(test_id="B999", filename="ignored.py")))
    findings = parse_bandit_json(decoy, b"", tmp_path, "bandit")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "B602" in sidecar
    assert "B999" not in sidecar


def test_stdout_fallback_when_no_canonical_file(tmp_path: Path) -> None:
    payload = _payload(_envelope(_result(test_id="B608", cwe_id=89)))
    findings = parse_bandit_json(payload, b"", tmp_path, "bandit")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.SQLI


def test_high_severity_high_confidence_maps_to_confirmed(tmp_path: Path) -> None:
    payload = _payload(_envelope(_result(severity="HIGH", confidence="HIGH")))
    findings = parse_bandit_json(payload, b"", tmp_path, "bandit")
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED
    assert findings[0].cvss_v3_score == pytest.approx(7.0)


def test_medium_confidence_maps_to_likely(tmp_path: Path) -> None:
    payload = _payload(_envelope(_result(severity="MEDIUM", confidence="MEDIUM")))
    findings = parse_bandit_json(payload, b"", tmp_path, "bandit")
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_low_confidence_maps_to_suspected(tmp_path: Path) -> None:
    payload = _payload(_envelope(_result(severity="LOW", confidence="LOW")))
    findings = parse_bandit_json(payload, b"", tmp_path, "bandit")
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED
    assert findings[0].cvss_v3_score == pytest.approx(3.5)


def test_cwe_extracted_from_issue_cwe_id(tmp_path: Path) -> None:
    payload = _payload(_envelope(_result(cwe_id=89)))
    findings = parse_bandit_json(payload, b"", tmp_path, "bandit")
    assert findings[0].cwe == [89]
    assert findings[0].category is FindingCategory.SQLI


def test_test_id_prefix_b6_falls_back_to_rce_when_no_cwe(tmp_path: Path) -> None:
    payload = _payload(_envelope(_result(test_id="B607", cwe_id=None)))
    findings = parse_bandit_json(payload, b"", tmp_path, "bandit")
    assert findings[0].category is FindingCategory.RCE


def test_test_id_prefix_b3_falls_back_to_crypto(tmp_path: Path) -> None:
    payload = _payload(_envelope(_result(test_id="B303", cwe_id=None)))
    findings = parse_bandit_json(payload, b"", tmp_path, "bandit")
    assert findings[0].category is FindingCategory.CRYPTO


def test_unknown_test_id_prefix_collapses_to_misconfig(tmp_path: Path) -> None:
    payload = _payload(_envelope(_result(test_id="B101", cwe_id=None)))
    findings = parse_bandit_json(payload, b"", tmp_path, "bandit")
    assert findings[0].category is FindingCategory.MISCONFIG


def test_dedup_collapses_identical_test_id_filename_line(tmp_path: Path) -> None:
    payload = _payload(
        _envelope(
            _result(test_id="B602", filename="a.py", line=10),
            _result(test_id="B602", filename="a.py", line=10),
            _result(test_id="B602", filename="a.py", line=11),
        )
    )
    findings = parse_bandit_json(payload, b"", tmp_path, "bandit")
    assert len(findings) == 2


def test_results_sorted_severity_desc_then_id_then_path(tmp_path: Path) -> None:
    payload = _payload(
        _envelope(
            _result(
                test_id="B101", filename="z.py", line=1, severity="LOW", cwe_id=200
            ),
            _result(
                test_id="B602", filename="a.py", line=1, severity="HIGH", cwe_id=78
            ),
            _result(
                test_id="B608", filename="b.py", line=1, severity="MEDIUM", cwe_id=89
            ),
        )
    )
    parse_bandit_json(payload, b"", tmp_path, "bandit")
    sidecar_path = tmp_path / EVIDENCE_SIDECAR_NAME
    blobs = [json.loads(line) for line in sidecar_path.read_text("utf-8").splitlines()]
    assert [b["test_id"] for b in blobs] == ["B602", "B608", "B101"]


def test_missing_test_id_is_dropped_with_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    raw = _result()
    raw.pop("test_id")
    payload = _payload(_envelope(raw, _result(test_id="B602")))
    with caplog.at_level(logging.WARNING):
        findings = parse_bandit_json(payload, b"", tmp_path, "bandit")
    assert len(findings) == 1
    assert any(
        "bandit_parser_result_missing_field" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_malformed_json_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        findings = parse_bandit_json(b"{not-json", b"", tmp_path, "bandit")
    assert findings == []


def test_envelope_not_dict_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        findings = parse_bandit_json(b"[]", b"", tmp_path, "bandit")
    assert findings == []
    assert any(
        "bandit_parser_envelope_not_dict" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_scan_errors_logged_but_results_still_emitted(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    payload = _payload(
        _envelope(
            _result(test_id="B602"),
            errors=[{"filename": "src/oops.py", "reason": "syntax error"}],
        )
    )
    with caplog.at_level(logging.WARNING):
        findings = parse_bandit_json(payload, b"", tmp_path, "bandit")
    assert len(findings) == 1
    assert any(
        "bandit_parser_scan_errors" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_evidence_sidecar_carries_tool_id_tag(tmp_path: Path) -> None:
    payload = _payload(_envelope(_result()))
    parse_bandit_json(payload, b"", tmp_path, "bandit-custom")
    sidecar_path = tmp_path / EVIDENCE_SIDECAR_NAME
    blob = json.loads(sidecar_path.read_text("utf-8").strip())
    assert blob["tool_id"] == "bandit-custom"
    assert blob["kind"] == "bandit"
    assert blob["test_id"] == "B602"


def test_large_input_under_cap_produces_all_results(tmp_path: Path) -> None:
    items = [
        _result(test_id=f"B{600 + i:03d}", line=i + 1, filename=f"f{i}.py", cwe_id=78)
        for i in range(120)
    ]
    payload = _payload(_envelope(*items))
    findings = parse_bandit_json(payload, b"", tmp_path, "bandit")
    assert len(findings) == 120


def test_cwe_list_in_dict_form_extracted_correctly(tmp_path: Path) -> None:
    raw = _result()
    raw["issue_cwe"] = {
        "id": 327,
        "link": "https://cwe.mitre.org/data/definitions/327.html",
    }
    payload = _payload(_envelope(raw))
    findings = parse_bandit_json(payload, b"", tmp_path, "bandit")
    assert findings[0].cwe == [327]
    assert findings[0].category is FindingCategory.CRYPTO
