"""Unit tests for :mod:`src.sandbox.parsers.mobsf_parser` (Backlog/dev1_md §4.18 — ARG-021).

Pinned contracts:

* Resolves ``artifacts_dir/mobsf.json`` first, falls back to ``stdout``.
* Walks documented top-level sections (``code_analysis``,
  ``permissions``, ``android_api``, ``binary_analysis``,
  ``manifest_analysis``, ``secrets``, ``certificate_analysis``,
  ``network_security``, ``findings``, ``crypto_analysis``,
  bucketed ``high`` / ``warning`` / ``info``).
* Severity:

  - ``critical`` → ``critical``,
  - ``high`` → ``high``,
  - ``warning`` → ``medium``,
  - ``info`` / ``hotspot`` → ``info``,
  - ``good`` / ``secure`` / ``pass`` → dropped.

* Confidence: ``critical`` / ``high`` → ``LIKELY``; everything else →
  ``SUSPECTED``.
* Category routing:

  - ``secrets`` section / ``hardcoded`` keyword → ``SECRET_LEAK``
    (CWE-798), with ``match_preview`` redacted.
  - ``crypto_analysis`` / ``md5`` / ``sha1`` keywords → ``CRYPTO``.
  - ``manifest`` / ``network_security`` / ``certificate`` /
    ``permission`` / ``binary`` → ``MISCONFIG``.
  - ``sql`` keyword → ``SQLI``.

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
from src.sandbox.parsers import mobsf_parser as mobsf_module
from src.sandbox.parsers.mobsf_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_mobsf_json,
)


def _payload(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_mobsf_json(b"", b"", tmp_path, "mobsf_api") == []


def test_canonical_file_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "mobsf.json"
    canonical.write_bytes(
        _payload(
            {
                "code_analysis": {
                    "rule-canonical": {
                        "severity": "high",
                        "title": "Canonical issue",
                    }
                }
            }
        )
    )
    decoy = _payload(
        {"code_analysis": {"rule-decoy": {"severity": "high", "title": "decoy"}}}
    )
    findings = parse_mobsf_json(decoy, b"", tmp_path, "mobsf_api")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "rule-canonical" in sidecar


def test_high_severity_likely(tmp_path: Path) -> None:
    payload = _payload(
        {"code_analysis": {"rule-x": {"severity": "high", "title": "X"}}}
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert findings[0].cvss_v3_score == pytest.approx(7.5)
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_warning_maps_to_medium_suspected(tmp_path: Path) -> None:
    payload = _payload(
        {"code_analysis": {"rule-y": {"severity": "warning", "title": "Y"}}}
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert findings[0].cvss_v3_score == pytest.approx(5.0)
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_info_and_hotspot_map_to_info(tmp_path: Path) -> None:
    payload = _payload(
        {
            "code_analysis": {
                "rule-i": {"severity": "info", "title": "info"},
                "rule-h": {"severity": "hotspot", "title": "hotspot"},
            }
        }
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert all(f.cvss_v3_score == pytest.approx(0.0) for f in findings)


def test_good_severity_dropped(tmp_path: Path) -> None:
    payload = _payload(
        {
            "code_analysis": {
                "rule-pass": {"severity": "good", "title": "ok"},
                "rule-fail": {"severity": "high", "title": "bad"},
            }
        }
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "rule-fail" in sidecar
    assert "rule-pass" not in sidecar


def test_secret_section_routes_to_secret_leak_with_redaction(tmp_path: Path) -> None:
    secret_value = "AKIAIOSFODNN7EXAMPLEPLAINTEXT"
    payload = _payload(
        {
            "secrets": {
                "rule-secret": {
                    "severity": "high",
                    "title": "Hardcoded AWS key",
                    "match": secret_value,
                }
            }
        }
    )
    parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    sidecar_text = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert secret_value not in sidecar_text
    assert "***REDACTED" in sidecar_text


def test_secret_section_uses_secret_leak_category(tmp_path: Path) -> None:
    payload = _payload(
        {"secrets": {"rule-secret": {"severity": "warning", "title": "found secret"}}}
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert findings[0].category is FindingCategory.SECRET_LEAK
    assert findings[0].cwe == [798]


def test_crypto_keyword_routes_to_crypto(tmp_path: Path) -> None:
    payload = _payload(
        {"code_analysis": {"rule-md5": {"severity": "warning", "title": "MD5 used"}}}
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert findings[0].category is FindingCategory.CRYPTO


def test_manifest_section_routes_to_misconfig(tmp_path: Path) -> None:
    payload = _payload(
        {
            "manifest_analysis": {
                "rule-m": {
                    "severity": "high",
                    "title": "Debuggable enabled",
                    "description": "android:debuggable=true",
                }
            }
        }
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert findings[0].category is FindingCategory.MISCONFIG


def test_sql_keyword_routes_to_sqli(tmp_path: Path) -> None:
    payload = _payload(
        {
            "code_analysis": {
                "rule-sql-injection": {
                    "severity": "high",
                    "title": "Raw SQL concatenation",
                }
            }
        }
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert findings[0].category is FindingCategory.SQLI
    assert findings[0].cwe == [89]


def test_findings_section_list_iteration(tmp_path: Path) -> None:
    payload = _payload(
        {
            "findings": [
                {"rule_id": "F1", "severity": "high", "title": "first"},
                {"rule_id": "F2", "severity": "warning", "title": "second"},
            ]
        }
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert len(findings) == 2


def test_dedup_collapses_identical_record(tmp_path: Path) -> None:
    payload = _payload(
        {
            "code_analysis": {
                "rule-dup": {
                    "severity": "high",
                    "title": "dup",
                    "file": "src/Foo.java",
                    "line": 10,
                }
            },
            "findings": [
                {
                    "rule_id": "rule-dup",
                    "severity": "high",
                    "file": "src/Foo.java",
                    "line": 10,
                    "title": "dup again",
                }
            ],
        }
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert len(findings) == 1


def test_findings_sorted_severity_desc(tmp_path: Path) -> None:
    payload = _payload(
        {
            "findings": [
                {"rule_id": "low-1", "severity": "info", "title": "i"},
                {"rule_id": "high-1", "severity": "high", "title": "h"},
                {"rule_id": "med-1", "severity": "warning", "title": "w"},
            ]
        }
    )
    parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    rows = [
        json.loads(line)
        for line in (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    ]
    severities = [r["severity"] for r in rows]
    assert severities == ["high", "medium", "info"]


def test_envelope_not_dict_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        findings = parse_mobsf_json(b"[]", b"", tmp_path, "mobsf_api")
    assert findings == []
    assert any(
        "mobsf_parser_envelope_not_dict" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_malformed_json_returns_empty(tmp_path: Path) -> None:
    assert parse_mobsf_json(b"not-json", b"", tmp_path, "mobsf_api") == []


def test_no_known_sections_returns_empty(tmp_path: Path) -> None:
    payload = _payload({"unknown_section": {"x": 1}})
    assert parse_mobsf_json(payload, b"", tmp_path, "mobsf_api") == []


def test_evidence_sidecar_includes_tool_id_and_kind(tmp_path: Path) -> None:
    payload = _payload(
        {"code_analysis": {"rule-z": {"severity": "high", "title": "Z"}}}
    )
    parse_mobsf_json(payload, b"", tmp_path, "mobsf-android")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["tool_id"] == "mobsf-android"
    assert blob["kind"] == "mobsf"
    assert blob["rule_id"] == "rule-z"
    assert blob["section"] == "code_analysis"


def test_critical_severity_maps_to_critical(tmp_path: Path) -> None:
    """`critical` severity is preserved verbatim and confidence is LIKELY."""
    payload = _payload(
        {"code_analysis": {"rule-c": {"severity": "critical", "title": "C"}}}
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert findings[0].cvss_v3_score == pytest.approx(9.0)
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_low_and_medium_severities_recognised(tmp_path: Path) -> None:
    """Explicit `low`/`medium` severities are mapped one-to-one."""
    payload = _payload(
        {
            "code_analysis": {
                "rule-low": {"severity": "low", "title": "low"},
                "rule-medium": {"severity": "medium", "title": "medium"},
            }
        }
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    scores = sorted(f.cvss_v3_score for f in findings)
    assert scores == pytest.approx([3.0, 5.0])


def test_unknown_severity_collapses_to_info(tmp_path: Path) -> None:
    """Unknown severity strings collapse to `info` (CVSS 0.0)."""
    payload = _payload(
        {"code_analysis": {"rule-x": {"severity": "weird", "title": "x"}}}
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert findings[0].cvss_v3_score == pytest.approx(0.0)


def test_severity_field_aliases(tmp_path: Path) -> None:
    """`level` and `stat` field aliases are recognised when `severity` is missing."""
    payload = _payload(
        {
            "code_analysis": {
                "alias-level": {"level": "high", "title": "level alias"},
                "alias-stat": {"stat": "warning", "title": "stat alias"},
            }
        }
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert sorted(f.cvss_v3_score for f in findings) == pytest.approx([5.0, 7.5])


def test_secure_severity_dropped_like_good(tmp_path: Path) -> None:
    """`secure` and `pass` severities are dropped together with `good`."""
    payload = _payload(
        {
            "code_analysis": {
                "rule-secure": {"severity": "secure", "title": "ok"},
                "rule-pass": {"severity": "pass", "title": "ok"},
            }
        }
    )
    assert parse_mobsf_json(payload, b"", tmp_path, "mobsf_api") == []


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hitting `_MAX_FINDINGS` truncates results and emits a structured warning."""
    monkeypatch.setattr(mobsf_module, "_MAX_FINDINGS", 2)
    findings_array = [
        {"rule_id": f"R{i}", "severity": "high", "title": f"r{i}", "line": i}
        for i in range(5)
    ]
    payload = _payload({"findings": findings_array})
    with caplog.at_level(logging.WARNING):
        findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert len(findings) == 2
    assert any(
        "mobsf_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_canonical_read_oserror_falls_back_to_stdout(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`mobsf.json` read failure falls back to stdout and logs a structured warning."""
    canonical = tmp_path / "mobsf.json"
    canonical.write_bytes(b"{}")
    real_read_bytes = Path.read_bytes

    def _explode(self: Path) -> bytes:
        if self.name == "mobsf.json":
            raise OSError("disk full")
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _explode)
    payload = _payload(
        {"code_analysis": {"rule-stdout": {"severity": "high", "title": "x"}}}
    )
    with caplog.at_level(logging.WARNING):
        findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert len(findings) == 1
    assert any(
        "mobsf_parser_canonical_read_failed" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_sidecar_persist_oserror_logs_warning(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sidecar write failures emit a structured warning but findings still flow."""
    real_mkdir = Path.mkdir

    def _boom(self: Path, *args: Any, **kwargs: Any) -> None:
        if self == tmp_path:
            raise OSError("read-only")
        real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", _boom)
    payload = _payload(
        {"code_analysis": {"rule-fs": {"severity": "high", "title": "fs"}}}
    )
    with caplog.at_level(logging.WARNING):
        findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert len(findings) == 1
    assert any(
        "mobsf_parser_evidence_sidecar_write_failed"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_files_list_with_string_entry_used_as_file(tmp_path: Path) -> None:
    """When `file` is missing the first string entry of `files` is used."""
    payload = _payload(
        {
            "code_analysis": {
                "rule-files-str": {
                    "severity": "high",
                    "title": "string files entry",
                    "files": ["src/Foo.java", "src/Bar.java"],
                }
            }
        }
    )
    parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["file"] == "src/Foo.java"


def test_files_list_with_dict_entry_used_as_file(tmp_path: Path) -> None:
    """`files[0]` as a dict with `file_path`/`name` is used when top-level file is missing."""
    payload = _payload(
        {
            "code_analysis": {
                "rule-files-dict": {
                    "severity": "high",
                    "title": "dict files entry",
                    "files": [{"file_path": "src/Dict.java", "line": 12}],
                }
            }
        }
    )
    parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["file"] == "src/Dict.java"


def test_files_list_empty_string_entry_falls_back_to_none(tmp_path: Path) -> None:
    """Empty/whitespace-only string in `files[0]` does not populate `file`."""
    payload = _payload(
        {
            "code_analysis": {
                "rule-empty-file": {
                    "severity": "high",
                    "title": "empty file entry",
                    "files": ["   "],
                }
            }
        }
    )
    parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "file" not in blob


def test_cwe_dict_with_id_extracted(tmp_path: Path) -> None:
    """`cwe` field as `{"id": ...}` recursively extracts the integer."""
    payload = _payload(
        {
            "findings": [
                {
                    "rule_id": "R-cwe-dict",
                    "severity": "warning",
                    "title": "cwe dict",
                    "cwe": {"id": "CWE-77"},
                }
            ]
        }
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert findings[0].cwe == [77]


def test_cwe_list_dedups_and_sorts(tmp_path: Path) -> None:
    """`cwe` list collects unique CWE ids in sorted order."""
    payload = _payload(
        {
            "findings": [
                {
                    "rule_id": "R-cwe-list",
                    "severity": "warning",
                    "title": "cwe list",
                    "cwe": ["CWE-22", 200, "200", "junk", True],
                }
            ]
        }
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert findings[0].cwe == [22, 200]


def test_cwe_int_alias_field(tmp_path: Path) -> None:
    """`cweid` alias is honoured and supports plain int CWE values."""
    payload = _payload(
        {
            "findings": [
                {
                    "rule_id": "R-cwe-int",
                    "severity": "warning",
                    "title": "cwe int",
                    "cweid": 327,
                }
            ]
        }
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert findings[0].cwe == [327]


def test_cwe_negative_token_falls_back_to_default(tmp_path: Path) -> None:
    """Non-positive CWE tokens are ignored and category-default CWE is used."""
    payload = _payload(
        {
            "findings": [
                {
                    "rule_id": "R-cwe-zero",
                    "severity": "warning",
                    "title": "cwe zero",
                    "cwe": "CWE-0",
                }
            ]
        }
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert findings[0].cwe == [16, 1032]


def test_owasp_mobile_string_value(tmp_path: Path) -> None:
    """A single OWASP-mobile string is wrapped into a one-element list."""
    payload = _payload(
        {
            "findings": [
                {
                    "rule_id": "R-owasp-str",
                    "severity": "high",
                    "title": "owasp str",
                    "owasp-mobile": "M2: Insecure Data Storage",
                }
            ]
        }
    )
    parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["owasp_mobile"] == ["M2: Insecure Data Storage"]


def test_owasp_mobile_list_value_filters_empty(tmp_path: Path) -> None:
    """OWASP-mobile list filters out non-string and blank entries."""
    payload = _payload(
        {
            "findings": [
                {
                    "rule_id": "R-owasp-list",
                    "severity": "high",
                    "title": "owasp list",
                    "masvs": ["MSTG-NETWORK-1", "  ", 5, "MSTG-CRYPTO-1"],
                }
            ]
        }
    )
    parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["owasp_mobile"] == ["MSTG-NETWORK-1", "MSTG-CRYPTO-1"]


def test_string_line_coerced_to_int(tmp_path: Path) -> None:
    """Numeric string `line` coerces to an int via `_coerce_int`."""
    payload = _payload(
        {
            "findings": [
                {
                    "rule_id": "R-line",
                    "severity": "high",
                    "title": "line",
                    "line": "42",
                }
            ]
        }
    )
    parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["line"] == 42


def test_bool_line_dropped(tmp_path: Path) -> None:
    """Boolean `line` is rejected by `_coerce_int` and falls back to 0."""
    payload = _payload(
        {
            "findings": [
                {
                    "rule_id": "R-bool",
                    "severity": "high",
                    "title": "bool line",
                    "line": True,
                }
            ]
        }
    )
    parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["line"] == 0


def test_negative_string_line_dropped(tmp_path: Path) -> None:
    """Negative numeric strings for `line` collapse to 0."""
    payload = _payload(
        {
            "findings": [
                {
                    "rule_id": "R-neg",
                    "severity": "high",
                    "title": "neg line",
                    "line": "-7",
                }
            ]
        }
    )
    parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["line"] == 0


def test_long_description_truncated_in_evidence(tmp_path: Path) -> None:
    """Oversized `description` values are truncated in the evidence sidecar."""
    long_value = "x" * 5000
    payload = _payload(
        {
            "findings": [
                {
                    "rule_id": "R-long",
                    "severity": "high",
                    "title": "long",
                    "description": long_value,
                }
            ]
        }
    )
    parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["description"].endswith("...[truncated]")
    assert len(blob["description"]) < len(long_value) + 32


def test_severity_bucket_recursion(tmp_path: Path) -> None:
    """Severity buckets such as `high` recurse one level via `_walk_section`."""
    payload = _payload(
        {
            "high": {
                "subsection": {
                    "rule-bucket": {"title": "bucket", "severity": "high"},
                }
            }
        }
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert len(findings) == 1


def test_non_dict_section_value_skipped(tmp_path: Path) -> None:
    """Non-dict / non-list section payloads are silently skipped."""
    payload = _payload({"code_analysis": "totally bogus"})
    assert parse_mobsf_json(payload, b"", tmp_path, "mobsf_api") == []


def test_canonical_blank_file_falls_back_to_stdout(tmp_path: Path) -> None:
    """A canonical file with only whitespace falls back to parsing stdout."""
    (tmp_path / "mobsf.json").write_bytes(b"   \n  ")
    payload = _payload(
        {"code_analysis": {"rule-fb": {"severity": "high", "title": "fb"}}}
    )
    findings = parse_mobsf_json(payload, b"", tmp_path, "mobsf_api")
    assert len(findings) == 1
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["rule_id"] == "rule-fb"
