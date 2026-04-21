"""Unit tests for :mod:`src.sandbox.parsers.kube_bench_parser` (Backlog/dev1_md §4.15 — ARG-021).

Pinned contracts:

* Resolves ``artifacts_dir/kubebench.json`` (or ``kube_bench.json``)
  before falling back to ``stdout``.
* Top-level ``Controls[].tests[].results[]`` envelope (kube-bench 0.7.x).
* Status filter — only ``FAIL`` / ``WARN`` reach the FindingDTOs;
  ``PASS`` / ``INFO`` are dropped silently.
* Severity:

  - ``FAIL`` + ``scored: true`` → ``high``,
  - ``FAIL`` + ``scored: false`` → ``medium``,
  - ``WARN`` (always) → ``medium``.

* Confidence: every kube-bench hit → ``LIKELY``.
* Category: every finding → ``MISCONFIG`` with CWE ``[16, 250]``.
* Dedup: composite ``(test_number, node_type)``.
* Fail-soft on malformed JSON / non-dict envelope / missing fields.
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
from src.sandbox.parsers.kube_bench_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_kube_bench_json,
)


def _result(
    *,
    test_number: str = "1.1.1",
    test_desc: str = "Ensure that the API server pod spec file permissions are 644",
    status: str = "FAIL",
    scored: bool = True,
    audit: str = "stat -c %a /etc/kubernetes/manifests/kube-apiserver.yaml",
    remediation: str = "chmod 644 /etc/kubernetes/manifests/kube-apiserver.yaml",
    actual_value: str = "660",
    expected_result: str = "permissions has permission 644",
) -> dict[str, Any]:
    return {
        "test_number": test_number,
        "test_desc": test_desc,
        "audit": audit,
        "remediation": remediation,
        "test_info": [],
        "status": status,
        "scored": scored,
        "actual_value": actual_value,
        "expected_result": expected_result,
    }


def _control(
    *,
    control_id: str = "1",
    text: str = "Master Node Configuration Files",
    node_type: str = "master",
    section: str = "1.1",
    section_desc: str = "Master Node Configuration",
    results: list[dict[str, Any]] | None = None,
    version: str = "1.7",
) -> dict[str, Any]:
    return {
        "id": control_id,
        "version": version,
        "text": text,
        "node_type": node_type,
        "tests": [
            {
                "section": section,
                "desc": section_desc,
                "results": results if results is not None else [_result()],
            }
        ],
    }


def _payload(*controls: dict[str, Any]) -> bytes:
    envelope = {
        "Controls": list(controls),
        "Totals": {"total_pass": 0, "total_fail": 1, "total_warn": 0, "total_info": 0},
    }
    return json.dumps(envelope).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_kube_bench_json(b"", b"", tmp_path, "kube_bench") == []


def test_canonical_kubebench_file_is_preferred(tmp_path: Path) -> None:
    canonical = tmp_path / "kubebench.json"
    canonical.write_bytes(_payload(_control(node_type="master")))
    decoy = _payload(_control(node_type="ignored"))
    findings = parse_kube_bench_json(decoy, b"", tmp_path, "kube_bench")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "master" in sidecar


def test_underscored_filename_also_recognised(tmp_path: Path) -> None:
    canonical = tmp_path / "kube_bench.json"
    canonical.write_bytes(_payload(_control(node_type="etcd")))
    findings = parse_kube_bench_json(b"", b"", tmp_path, "kube_bench")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "etcd" in sidecar


def test_pass_results_are_dropped(tmp_path: Path) -> None:
    payload = _payload(
        _control(
            results=[
                _result(test_number="1.1.1", status="PASS"),
                _result(test_number="1.1.2", status="INFO"),
                _result(test_number="1.1.3", status="FAIL"),
            ]
        )
    )
    findings = parse_kube_bench_json(payload, b"", tmp_path, "kube_bench")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert len(findings) == 1
    assert "1.1.1" not in sidecar
    assert "1.1.3" in sidecar


def test_fail_scored_classified_as_high(tmp_path: Path) -> None:
    payload = _payload(_control(results=[_result(status="FAIL", scored=True)]))
    findings = parse_kube_bench_json(payload, b"", tmp_path, "kube_bench")
    assert findings[0].cvss_v3_score == pytest.approx(7.0)


def test_fail_unscored_classified_as_medium(tmp_path: Path) -> None:
    payload = _payload(_control(results=[_result(status="FAIL", scored=False)]))
    findings = parse_kube_bench_json(payload, b"", tmp_path, "kube_bench")
    assert findings[0].cvss_v3_score == pytest.approx(5.0)


def test_warn_classified_as_medium(tmp_path: Path) -> None:
    payload = _payload(_control(results=[_result(status="WARN", scored=True)]))
    findings = parse_kube_bench_json(payload, b"", tmp_path, "kube_bench")
    assert findings[0].cvss_v3_score == pytest.approx(5.0)


def test_findings_get_likely_confidence_and_misconfig_category(tmp_path: Path) -> None:
    payload = _payload(_control())
    findings = parse_kube_bench_json(payload, b"", tmp_path, "kube_bench")
    assert findings[0].confidence is ConfidenceLevel.LIKELY
    assert findings[0].category is FindingCategory.MISCONFIG
    assert findings[0].cwe == [16, 250]


def test_dedup_uses_test_number_and_node_type(tmp_path: Path) -> None:
    duplicates = [
        _result(test_number="1.1.1", status="FAIL"),
        _result(test_number="1.1.1", status="FAIL"),
    ]
    payload = _payload(_control(node_type="master", results=duplicates))
    findings = parse_kube_bench_json(payload, b"", tmp_path, "kube_bench")
    assert len(findings) == 1


def test_same_test_on_different_node_types_kept_separate(tmp_path: Path) -> None:
    payload = _payload(
        _control(node_type="master", results=[_result(test_number="1.1.1")]),
        _control(node_type="node", results=[_result(test_number="1.1.1")]),
    )
    findings = parse_kube_bench_json(payload, b"", tmp_path, "kube_bench")
    assert len(findings) == 2


def test_findings_sorted_severity_desc_then_node_then_test(tmp_path: Path) -> None:
    payload = _payload(
        _control(
            node_type="node",
            results=[
                _result(test_number="2.1.2", status="WARN"),
                _result(test_number="2.1.1", status="FAIL", scored=True),
            ],
        ),
        _control(
            node_type="master",
            results=[_result(test_number="1.1.1", status="FAIL", scored=True)],
        ),
    )
    findings = parse_kube_bench_json(payload, b"", tmp_path, "kube_bench")
    sidecar = tmp_path / EVIDENCE_SIDECAR_NAME
    rows = [json.loads(line) for line in sidecar.read_text("utf-8").splitlines()]
    assert [r["test_number"] for r in rows] == ["1.1.1", "2.1.1", "2.1.2"]
    assert [r["severity"] for r in rows] == ["high", "high", "medium"]
    assert len(findings) == 3


def test_envelope_not_dict_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        findings = parse_kube_bench_json(b"[]", b"", tmp_path, "kube_bench")
    assert findings == []
    assert any(
        "kube_bench_parser_envelope_not_dict" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_missing_test_number_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    bad_result = _result()
    bad_result.pop("test_number")
    payload = _payload(_control(results=[bad_result, _result(test_number="2.1.1")]))
    with caplog.at_level(logging.WARNING):
        findings = parse_kube_bench_json(payload, b"", tmp_path, "kube_bench")
    assert len(findings) == 1
    assert any(
        "kube_bench_parser_result_missing_test_number"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_malformed_json_returns_empty(tmp_path: Path) -> None:
    assert parse_kube_bench_json(b"not-json", b"", tmp_path, "kube_bench") == []


def test_no_controls_returns_empty(tmp_path: Path) -> None:
    payload = json.dumps({"Controls": []}).encode("utf-8")
    assert parse_kube_bench_json(payload, b"", tmp_path, "kube_bench") == []


def test_evidence_sidecar_includes_tool_id_and_kind(tmp_path: Path) -> None:
    payload = _payload(_control(results=[_result(test_number="2.2.1")]))
    parse_kube_bench_json(payload, b"", tmp_path, "kube_bench-mng")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["tool_id"] == "kube_bench-mng"
    assert blob["kind"] == "kube_bench"
    assert blob["test_number"] == "2.2.1"
