"""Unit tests for :mod:`src.sandbox.parsers.kics_parser` (Backlog/dev1_md §4.16 — ARG-021).

Pinned contracts:

* Resolves ``artifacts_dir/results.json`` first, then ``kics.json``,
  then ``stdout``.
* Top-level ``queries[].files[]`` envelope (KICS 1.7.x).
* Severity:

  - ``HIGH`` → ``high``,
  - ``MEDIUM`` → ``medium``,
  - ``LOW`` → ``low``,
  - ``INFO`` / ``TRACE`` / unknown → ``info``,
  - missing → ``MEDIUM`` (default).

* Confidence: ``high`` → ``LIKELY``; everything else → ``SUSPECTED``.
* Category: defaults to ``MISCONFIG``; ``query_name`` matching
  ``secret`` / ``credential`` / ``password`` / ``token`` /
  ``api[- ]key`` / ``private key`` routes to ``SECRET_LEAK``.
* CWE: from ``query.cwe`` (int / str / "CWE-NNN"); falls back to
  ``[16, 1032]`` for misconfig, ``[798]`` for secret leaks.
* Dedup: composite ``(query_id, file_name, line)``.
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
from src.sandbox.parsers import kics_parser as kics_module
from src.sandbox.parsers.kics_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_kics_json,
)


def _file_entry(
    *,
    file_name: str = "deployment.yaml",
    line: int = 42,
    issue_type: str = "MissingAttribute",
    search_key: str = "metadata.name=frontend.spec.containers.securityContext.privileged",
    expected_value: str = "false",
    actual_value: str = "true",
    resource_type: str = "Deployment",
    resource_name: str = "frontend",
) -> dict[str, Any]:
    return {
        "file_name": file_name,
        "similarity_id": "abc123",
        "line": line,
        "issue_type": issue_type,
        "search_key": search_key,
        "search_line": line,
        "search_value": "",
        "expected_value": expected_value,
        "actual_value": actual_value,
        "resource_type": resource_type,
        "resource_name": resource_name,
    }


def _query(
    *,
    query_id: str = "1c5e0e6f-cce7-44ee-bc28-001ec27c8f64",
    query_name: str = "Privileged Container",
    severity: str | None = "HIGH",
    cwe: Any = "250",
    files: list[dict[str, Any]] | None = None,
    platform: str = "Kubernetes",
    category: str = "Insecure Configurations",
    query_url: str = "https://docs.kics.io/...",
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "query_id": query_id,
        "query_name": query_name,
        "query_url": query_url,
        "platform": platform,
        "category": category,
        "description": "Run as privileged container",
        "cwe": cwe,
        "files": files if files is not None else [_file_entry()],
    }
    if severity is not None:
        record["severity"] = severity
    return record


def _payload(*queries: dict[str, Any]) -> bytes:
    envelope = {
        "kics_version": "v1.7.0",
        "files_scanned": 42,
        "lines_scanned": 9876,
        "queries_total": 1234,
        "queries": list(queries),
        "severity_counters": {"INFO": 0, "LOW": 1, "MEDIUM": 12, "HIGH": 4},
    }
    return json.dumps(envelope).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_kics_json(b"", b"", tmp_path, "kics") == []


def test_results_json_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "results.json"
    canonical.write_bytes(_payload(_query(query_id="real-query")))
    decoy = _payload(_query(query_id="decoy-query"))
    findings = parse_kics_json(decoy, b"", tmp_path, "kics")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "real-query" in sidecar


def test_kics_json_fallback(tmp_path: Path) -> None:
    canonical = tmp_path / "kics.json"
    canonical.write_bytes(_payload(_query(query_id="from-kics-json")))
    findings = parse_kics_json(b"", b"", tmp_path, "kics")
    assert len(findings) == 1


def test_severity_high_mapping(tmp_path: Path) -> None:
    payload = _payload(_query(severity="HIGH"))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].cvss_v3_score == pytest.approx(7.5)
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_severity_medium_mapping(tmp_path: Path) -> None:
    payload = _payload(_query(severity="MEDIUM"))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].cvss_v3_score == pytest.approx(5.0)
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_severity_low_mapping(tmp_path: Path) -> None:
    payload = _payload(_query(severity="LOW"))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].cvss_v3_score == pytest.approx(3.0)


def test_severity_trace_collapses_to_info(tmp_path: Path) -> None:
    payload = _payload(_query(severity="TRACE"))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].cvss_v3_score == pytest.approx(0.0)


def test_default_findings_get_misconfig_category(tmp_path: Path) -> None:
    payload = _payload(_query(query_name="Privileged Container"))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].category is FindingCategory.MISCONFIG
    assert findings[0].cwe == [250]


def test_secret_keyword_routes_to_secret_leak(tmp_path: Path) -> None:
    payload = _payload(_query(query_name="Hardcoded password in env", cwe="798"))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].category is FindingCategory.SECRET_LEAK
    assert findings[0].cwe == [798]


def test_token_keyword_routes_to_secret_leak(tmp_path: Path) -> None:
    payload = _payload(_query(query_name="GitHub token in plaintext", cwe=None))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].category is FindingCategory.SECRET_LEAK
    assert findings[0].cwe == [798]


def test_cwe_string_with_prefix_extracted(tmp_path: Path) -> None:
    payload = _payload(_query(cwe="CWE-250"))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].cwe == [250]


def test_cwe_int_extracted(tmp_path: Path) -> None:
    payload = _payload(_query(cwe=287))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].cwe == [287]


def test_cwe_missing_falls_back_to_default(tmp_path: Path) -> None:
    payload = _payload(_query(cwe=None))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].cwe == [16, 1032]


def test_dedup_collapses_identical_record(tmp_path: Path) -> None:
    payload = _payload(
        _query(
            query_id="QID-1",
            files=[
                _file_entry(file_name="dep.yaml", line=10),
                _file_entry(file_name="dep.yaml", line=10),
            ],
        )
    )
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert len(findings) == 1


def test_findings_sorted_severity_desc(tmp_path: Path) -> None:
    payload = _payload(
        _query(
            query_id="qid-low",
            severity="LOW",
            files=[_file_entry(file_name="a.yaml", line=1)],
        ),
        _query(
            query_id="qid-high",
            severity="HIGH",
            files=[_file_entry(file_name="b.yaml", line=2)],
        ),
        _query(
            query_id="qid-medium",
            severity="MEDIUM",
            files=[_file_entry(file_name="c.yaml", line=3)],
        ),
    )
    parse_kics_json(payload, b"", tmp_path, "kics")
    rows = [
        json.loads(line)
        for line in (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    ]
    assert [r["query_id"] for r in rows] == ["qid-high", "qid-medium", "qid-low"]


def test_envelope_not_dict_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        findings = parse_kics_json(b"[]", b"", tmp_path, "kics")
    assert findings == []
    assert any(
        "kics_parser_envelope_not_dict" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_missing_query_id_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    bad = _query()
    bad.pop("query_id")
    payload = _payload(bad, _query(query_id="ok-id"))
    with caplog.at_level(logging.WARNING):
        findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert len(findings) == 1
    assert any(
        "kics_parser_query_missing_id" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_malformed_json_returns_empty(tmp_path: Path) -> None:
    assert parse_kics_json(b"not-json", b"", tmp_path, "kics") == []


def test_evidence_sidecar_includes_tool_id_and_kind(tmp_path: Path) -> None:
    payload = _payload(_query(query_id="QID-XYZ"))
    parse_kics_json(payload, b"", tmp_path, "kics-iac")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["tool_id"] == "kics-iac"
    assert blob["kind"] == "kics"
    assert blob["query_id"] == "QID-XYZ"
    assert blob["platform"] == "Kubernetes"


def test_queries_field_not_a_list_returns_empty(tmp_path: Path) -> None:
    """Envelope with a non-list `queries` field is treated as empty."""
    payload = json.dumps({"queries": "not-a-list"}).encode("utf-8")
    assert parse_kics_json(payload, b"", tmp_path, "kics") == []


def test_all_queries_invalid_returns_empty_no_sidecar(tmp_path: Path) -> None:
    """When every query is malformed the result is empty and no sidecar is written."""
    payload = json.dumps({"queries": [{"no_id": True}, "string-junk", 5]}).encode(
        "utf-8"
    )
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hitting `_MAX_FINDINGS` truncates results and emits a structured warning."""
    monkeypatch.setattr(kics_module, "_MAX_FINDINGS", 2)
    files = [_file_entry(file_name=f"f{i}.yaml", line=i + 1) for i in range(5)]
    payload = _payload(_query(query_id="QID-cap", files=files))
    with caplog.at_level(logging.WARNING):
        findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert len(findings) == 2
    assert any(
        "kics_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_canonical_read_oserror_falls_back_to_stdout(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If reading `results.json` fails with OSError the parser falls back to stdout."""
    canonical = tmp_path / "results.json"
    canonical.write_bytes(b"{}")
    real_read_bytes = Path.read_bytes

    def _explode(self: Path) -> bytes:
        if self.name == "results.json":
            raise OSError("disk full")
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _explode)
    payload = _payload(_query(query_id="from-stdout"))
    with caplog.at_level(logging.WARNING):
        findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert len(findings) == 1
    assert any(
        "kics_parser_canonical_read_failed" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_sidecar_persist_oserror_logs_warning(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failure to write the sidecar emits a structured warning but findings still flow."""
    real_mkdir = Path.mkdir

    def _boom(self: Path, *args: Any, **kwargs: Any) -> None:
        if self == tmp_path:
            raise OSError("read-only")
        real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", _boom)
    payload = _payload(_query())
    with caplog.at_level(logging.WARNING):
        findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert len(findings) == 1
    assert any(
        "kics_parser_evidence_sidecar_write_failed"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_non_dict_query_in_array_skipped(tmp_path: Path) -> None:
    """Non-dict query entries are silently skipped."""
    bad_queries = ["string-query", 42, None, _query(query_id="ok-id")]
    payload = json.dumps({"queries": bad_queries}).encode("utf-8")
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert len(findings) == 1


def test_files_field_not_a_list_skips_query(tmp_path: Path) -> None:
    """Query with non-list `files` is silently skipped."""
    bad = _query(query_id="QID-bad")
    bad["files"] = "not-a-list"
    payload = _payload(bad, _query(query_id="QID-good"))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert len(findings) == 1


def test_non_dict_file_entry_skipped(tmp_path: Path) -> None:
    """Non-dict file entries are silently skipped while siblings are kept."""
    mixed_files: list[Any] = [
        "bare-string",
        99,
        None,
        _file_entry(file_name="ok.yaml", line=7),
    ]
    bad = _query(query_id="QID-mixed")
    bad["files"] = mixed_files
    findings = parse_kics_json(_payload(bad), b"", tmp_path, "kics")
    assert len(findings) == 1


def test_file_entry_without_file_name_skipped(tmp_path: Path) -> None:
    """File entry missing `file_name` is silently dropped."""
    no_name = _file_entry()
    no_name.pop("file_name")
    bad = _query(query_id="QID-no-name", files=[no_name])
    payload = _payload(bad, _query(query_id="QID-ok"))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert len(findings) == 1


def test_unknown_severity_string_collapses_to_info(tmp_path: Path) -> None:
    """Unknown severity strings collapse to `info` (CVSS 0.0)."""
    payload = _payload(_query(severity="WHATEVER"))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].cvss_v3_score == pytest.approx(0.0)
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_cwe_dict_with_id_extracted(tmp_path: Path) -> None:
    """`cwe` field as `{"id": ...}` recursively extracts the integer."""
    payload = _payload(_query(cwe={"id": "CWE-77"}))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].cwe == [77]


def test_cwe_list_dedups_and_sorts(tmp_path: Path) -> None:
    """`cwe` list collects unique CWE ids in sorted order."""
    payload = _payload(_query(cwe=["CWE-22", "352", 22, "noise"]))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].cwe == [22, 352]


def test_cwe_bool_value_falls_back_to_default(tmp_path: Path) -> None:
    """`cwe` boolean inputs are ignored and the default CWE list is used."""
    payload = _payload(_query(cwe=True))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].cwe == [16, 1032]


def test_negative_cwe_string_falls_back_to_default(tmp_path: Path) -> None:
    """A non-positive CWE token results in the default CWE list."""
    payload = _payload(_query(cwe="CWE-0"))
    findings = parse_kics_json(payload, b"", tmp_path, "kics")
    assert findings[0].cwe == [16, 1032]


def test_string_line_coerced_to_int(tmp_path: Path) -> None:
    """Numeric string `line` field is coerced to an int dedup key."""
    file_entry = _file_entry(file_name="m.yaml", line=7)
    file_entry["line"] = "11"
    payload = _payload(_query(files=[file_entry]))
    parse_kics_json(payload, b"", tmp_path, "kics")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["line"] == 11


def test_bool_line_dropped_to_default_zero(tmp_path: Path) -> None:
    """Boolean `line` is rejected by `_coerce_int` and falls back to 0."""
    file_entry = _file_entry(file_name="b.yaml")
    file_entry["line"] = True
    payload = _payload(_query(files=[file_entry]))
    parse_kics_json(payload, b"", tmp_path, "kics")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["line"] == 0


def test_negative_string_line_dropped_to_default_zero(tmp_path: Path) -> None:
    """Negative numeric strings for `line` collapse to 0."""
    file_entry = _file_entry(file_name="n.yaml")
    file_entry["line"] = "-5"
    payload = _payload(_query(files=[file_entry]))
    parse_kics_json(payload, b"", tmp_path, "kics")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["line"] == 0


def test_missing_query_url_omitted_from_evidence(tmp_path: Path) -> None:
    """When optional string fields are missing they are pruned from the sidecar."""
    bare = _query()
    for key in ("query_url", "platform", "category"):
        bare.pop(key, None)
    payload = _payload(bare)
    parse_kics_json(payload, b"", tmp_path, "kics")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "query_url" not in blob
    assert "platform" not in blob
    assert "kics_category" not in blob


def test_long_search_key_truncated_in_evidence(tmp_path: Path) -> None:
    """Oversized `search_key` is truncated in the evidence sidecar."""
    long_value = "a" * 5000
    file_entry = _file_entry(search_key=long_value)
    payload = _payload(_query(files=[file_entry]))
    parse_kics_json(payload, b"", tmp_path, "kics")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["search_key"].endswith("...[truncated]")
    assert len(blob["search_key"]) < len(long_value) + 32


def test_missing_line_field_defaults_to_zero(tmp_path: Path) -> None:
    """File entry without `line` field collapses to line=0 via `_coerce_int`."""
    file_entry = _file_entry()
    file_entry.pop("line")
    payload = _payload(_query(files=[file_entry]))
    parse_kics_json(payload, b"", tmp_path, "kics")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["line"] == 0


def test_missing_optional_text_fields_pruned_from_evidence(tmp_path: Path) -> None:
    """Missing search_key/expected/actual values are pruned via _truncate_text(None)."""
    file_entry = _file_entry()
    for key in ("search_key", "expected_value", "actual_value"):
        file_entry.pop(key, None)
    payload = _payload(_query(files=[file_entry]))
    parse_kics_json(payload, b"", tmp_path, "kics")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "search_key" not in blob
    assert "expected_value" not in blob
    assert "actual_value" not in blob
