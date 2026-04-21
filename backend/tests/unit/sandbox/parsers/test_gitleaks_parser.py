"""Unit tests for :mod:`src.sandbox.parsers.gitleaks_parser` (Backlog/dev1_md §4.16 — ARG-021).

Pinned contracts:

* Resolves ``artifacts_dir/gitleaks.json`` first, falls back to ``stdout``.
* Top-level array shape (Gitleaks 8.x).
* ``Match`` and ``Secret`` fields **must** be redacted before any
  on-disk persistence (sidecar) or DTO construction.
* Severity classification:

  - ``aws-*`` / ``private-*`` keywords → ``critical``.
  - ``github-*`` / ``slack-*`` / ``jwt`` / ``generic-api-key`` → ``high``.
  - everything else → ``medium``.

* Confidence: every Gitleaks hit → ``CONFIRMED`` (regex + entropy match).
* CWE: pinned at ``[798]`` (CWE-798: Use of Hard-coded Credentials).
* Category: every finding → ``SECRET_LEAK``.
* Dedup: prefers ``Fingerprint``; otherwise composite
  ``(RuleID, File, StartLine)``.
* Fail-soft on malformed JSON / non-list envelope.
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
from src.sandbox.parsers import gitleaks_parser as gitleaks_module
from src.sandbox.parsers.gitleaks_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_gitleaks_json,
)


def _leak(
    *,
    rule_id: str = "aws-access-token",
    description: str = "AWS Access Key ID",
    file: str = "src/config/dev.env",
    start_line: int = 12,
    end_line: int = 12,
    secret: str = "AKIAIOSFODNN7EXAMPLE",
    match: str = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    fingerprint: str | None = "abc123def456:src/config/dev.env:aws-access-token:12",
    commit: str | None = "abc123def456abc123def456abc123def456abc1",
    author: str | None = "alice",
    email: str | None = "alice@example.com",
    date: str | None = "2026-04-19T11:00:00Z",
    entropy: float | None = 4.81,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "Description": description,
        "RuleID": rule_id,
        "StartLine": start_line,
        "EndLine": end_line,
        "StartColumn": 17,
        "EndColumn": 57,
        "Match": match,
        "Secret": secret,
        "File": file,
        "SymlinkFile": "",
        "Commit": commit or "",
        "Entropy": entropy if entropy is not None else 0.0,
        "Author": author or "",
        "Email": email or "",
        "Date": date or "",
        "Message": "wip: local dev creds",
        "Tags": tags or ["aws", "key"],
        "Fingerprint": fingerprint or "",
    }
    return record


def _payload(*leaks: dict[str, Any]) -> bytes:
    return json.dumps(list(leaks)).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_gitleaks_json(b"", b"", tmp_path, "gitleaks") == []


def test_canonical_file_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "gitleaks.json"
    canonical.write_bytes(_payload(_leak(rule_id="aws-access-token")))
    decoy = _payload(_leak(rule_id="ignored-rule"))
    findings = parse_gitleaks_json(decoy, b"", tmp_path, "gitleaks")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "aws-access-token" in sidecar


def test_aws_rule_classified_as_critical(tmp_path: Path) -> None:
    payload = _payload(_leak(rule_id="aws-access-token"))
    findings = parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    assert findings[0].cvss_v3_score == pytest.approx(9.5)


def test_private_key_rule_classified_as_critical(tmp_path: Path) -> None:
    payload = _payload(_leak(rule_id="private-key"))
    findings = parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    assert findings[0].cvss_v3_score == pytest.approx(9.5)


def test_github_rule_classified_as_high(tmp_path: Path) -> None:
    payload = _payload(
        _leak(rule_id="github-pat", description="GitHub personal access token")
    )
    findings = parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    assert findings[0].cvss_v3_score == pytest.approx(8.0)


def test_generic_rule_falls_back_to_medium(tmp_path: Path) -> None:
    payload = _payload(
        _leak(rule_id="vendor-x-token", description="Vendor X auth token")
    )
    findings = parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    assert findings[0].cvss_v3_score == pytest.approx(6.0)


def test_secret_field_is_redacted_in_sidecar(tmp_path: Path) -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    match = f"AWS_KEY = {secret}"
    payload = _payload(_leak(secret=secret, match=match))
    parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    sidecar_text = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert secret not in sidecar_text, (
        "raw secret leaked through redaction — sidecar must mask"
    )
    assert "REDACTED" in sidecar_text


def test_match_field_is_redacted_in_sidecar(tmp_path: Path) -> None:
    secret = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
    match = f"GH_TOKEN: {secret}"
    payload = _payload(
        _leak(
            rule_id="github-pat",
            description="GitHub PAT",
            secret=secret,
            match=match,
        )
    )
    parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    sidecar_text = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert secret not in sidecar_text
    assert "***REDACTED" in sidecar_text


def test_short_secret_redacted_to_length_only(tmp_path: Path) -> None:
    payload = _payload(_leak(secret="short", match="short"))
    parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    sidecar_text = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "***REDACTED(5)***" in sidecar_text


def test_findings_get_confirmed_confidence_and_secret_leak_category(
    tmp_path: Path,
) -> None:
    payload = _payload(_leak())
    findings = parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED
    assert findings[0].category is FindingCategory.SECRET_LEAK
    assert findings[0].cwe == [798]


def test_dedup_prefers_fingerprint(tmp_path: Path) -> None:
    fp = "stable-fp-001"
    payload = _payload(
        _leak(rule_id="aws", file="a.env", start_line=10, fingerprint=fp),
        _leak(rule_id="aws", file="a.env", start_line=10, fingerprint=fp),
    )
    findings = parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    assert len(findings) == 1


def test_dedup_falls_back_to_rule_file_line_when_no_fingerprint(tmp_path: Path) -> None:
    payload = _payload(
        _leak(rule_id="aws", file="a.env", start_line=10, fingerprint=""),
        _leak(rule_id="aws", file="a.env", start_line=10, fingerprint=""),
        _leak(rule_id="aws", file="a.env", start_line=11, fingerprint=""),
    )
    findings = parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    assert len(findings) == 2


def test_findings_sorted_severity_desc(tmp_path: Path) -> None:
    payload = _payload(
        _leak(
            rule_id="custom-low",
            description="vendor low",
            file="a.env",
            start_line=1,
            fingerprint="fp-a",
        ),
        _leak(
            rule_id="aws-access-token",
            description="aws key",
            file="b.env",
            start_line=2,
            fingerprint="fp-b",
        ),
        _leak(
            rule_id="github-pat",
            description="github personal access token",
            file="c.env",
            start_line=3,
            fingerprint="fp-c",
        ),
    )
    findings = parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    assert len(findings) == 3
    sidecar_path = tmp_path / EVIDENCE_SIDECAR_NAME
    severities = [
        json.loads(line)["severity"]
        for line in sidecar_path.read_text("utf-8").splitlines()
    ]
    assert severities == ["critical", "high", "medium"]


def test_envelope_not_list_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        findings = parse_gitleaks_json(b"{}", b"", tmp_path, "gitleaks")
    assert findings == []
    assert any(
        "gitleaks_parser_envelope_not_list" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_missing_rule_id_dropped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    raw = _leak()
    raw.pop("RuleID")
    payload = _payload(raw, _leak(rule_id="aws"))
    with caplog.at_level(logging.WARNING):
        findings = parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    assert len(findings) == 1
    assert any(
        "gitleaks_parser_result_missing_field" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_malformed_json_returns_empty(tmp_path: Path) -> None:
    assert parse_gitleaks_json(b"{not-json", b"", tmp_path, "gitleaks") == []


def test_evidence_sidecar_includes_tool_id_and_kind(tmp_path: Path) -> None:
    payload = _payload(_leak(rule_id="github-pat", description="github token"))
    parse_gitleaks_json(payload, b"", tmp_path, "gitleaks-custom")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["tool_id"] == "gitleaks-custom"
    assert blob["kind"] == "gitleaks"
    assert blob["rule_id"] == "github-pat"


def test_large_input_under_cap_processed_fully(tmp_path: Path) -> None:
    leaks = [
        _leak(
            rule_id=f"rule-{i:04d}",
            file=f"f{i}.env",
            start_line=i + 1,
            fingerprint=f"fp-{i}",
        )
        for i in range(120)
    ]
    findings = parse_gitleaks_json(_payload(*leaks), b"", tmp_path, "gitleaks")
    assert len(findings) == 120


def test_owasp_wstg_includes_athn_06(tmp_path: Path) -> None:
    payload = _payload(_leak())
    findings = parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    assert "WSTG-ATHN-06" in findings[0].owasp_wstg


def test_normalisation_dropping_all_records_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Array of malformed records (missing RuleID/File) → no findings."""
    bad_a = _leak()
    bad_a.pop("RuleID")
    bad_b = _leak()
    bad_b.pop("File")
    payload = _payload(bad_a, bad_b)
    with caplog.at_level(logging.WARNING):
        findings = parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Hitting _MAX_FINDINGS truncates output and emits a structured warning."""
    monkeypatch.setattr(gitleaks_module, "_MAX_FINDINGS", 2)
    leaks = [
        _leak(
            rule_id=f"rule-{i}",
            file=f"f{i}.env",
            start_line=i + 1,
            fingerprint=f"fp-{i}",
        )
        for i in range(5)
    ]
    with caplog.at_level(logging.WARNING):
        findings = parse_gitleaks_json(_payload(*leaks), b"", tmp_path, "gitleaks")
    assert len(findings) == 2
    assert any(
        "gitleaks_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_empty_tags_list_excluded_from_evidence(tmp_path: Path) -> None:
    """Records with only whitespace tags must not include a `tags` key in sidecar."""
    leak = _leak()
    leak["Tags"] = ["", "   "]
    parse_gitleaks_json(_payload(leak), b"", tmp_path, "gitleaks")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "tags" not in blob


def test_long_description_triggers_evidence_truncation(tmp_path: Path) -> None:
    """Evidence blob exceeding _MAX_EVIDENCE_BYTES triggers _truncate_text path."""
    huge_desc = "X" * 4096
    leak = _leak(description=huge_desc)
    parse_gitleaks_json(_payload(leak), b"", tmp_path, "gitleaks")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["description"].endswith("...[truncated]")
    assert len(blob["description"].encode("utf-8")) < len(huge_desc)


def test_sidecar_persist_oserror_logs_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """OSError during sidecar write is caught; findings still returned."""
    blocker = tmp_path / "blocked_dir"
    blocker.write_text("file-not-dir", encoding="utf-8")
    payload = _payload(_leak())
    with caplog.at_level(logging.WARNING):
        findings = parse_gitleaks_json(payload, b"", blocker, "gitleaks")
    assert len(findings) == 1
    assert any(
        "gitleaks_parser_evidence_sidecar_write_failed"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_canonical_read_oserror_falls_back_to_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """OSError on canonical read is logged; parser falls back to stdout."""
    canonical = tmp_path / "gitleaks.json"
    canonical.write_bytes(_payload(_leak(rule_id="from-canonical")))

    def _fake_read_bytes(_self: Path) -> bytes:
        raise PermissionError("simulated permission denied")

    monkeypatch.setattr(Path, "read_bytes", _fake_read_bytes)
    stdout_payload = _payload(_leak(rule_id="from-stdout", fingerprint="fp-stdout"))
    with caplog.at_level(logging.WARNING):
        findings = parse_gitleaks_json(stdout_payload, b"", tmp_path, "gitleaks")
    assert len(findings) == 1
    sidecar_text = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "from-stdout" in sidecar_text
    assert "from-canonical" not in sidecar_text
    assert any(
        "gitleaks_parser_canonical_read_failed" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_non_dict_record_in_array_skipped(tmp_path: Path) -> None:
    """Non-dict entries in the top-level array are skipped silently."""
    payload = json.dumps(["bare-string", 42, None, _leak()]).encode("utf-8")
    findings = parse_gitleaks_json(payload, b"", tmp_path, "gitleaks")
    assert len(findings) == 1


def test_string_start_line_coerced_to_int(tmp_path: Path) -> None:
    """Numeric strings in StartLine coerce to int via _coerce_int string branch."""
    leak = _leak(fingerprint="fp-string-line")
    leak["StartLine"] = "12"
    leak["EndLine"] = "24"
    parse_gitleaks_json(_payload(leak), b"", tmp_path, "gitleaks")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["start_line"] == 12
    assert blob["end_line"] == 24


def test_invalid_string_start_line_falls_back_to_zero(tmp_path: Path) -> None:
    """Non-numeric StartLine string falls back to 0 (not parsed as int)."""
    leak = _leak(fingerprint="fp-bad-line")
    leak["StartLine"] = "not-a-number"
    parse_gitleaks_json(_payload(leak), b"", tmp_path, "gitleaks")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["start_line"] == 0


def test_bool_numeric_fields_dropped_by_coercers(tmp_path: Path) -> None:
    """Boolean values in numeric fields must NOT be coerced to int/float."""
    leak = _leak(fingerprint="fp-bool")
    leak["StartLine"] = True
    leak["Entropy"] = False
    parse_gitleaks_json(_payload(leak), b"", tmp_path, "gitleaks")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["start_line"] == 0
    assert "entropy" not in blob


def test_string_entropy_coerced_to_float(tmp_path: Path) -> None:
    """Numeric strings in Entropy are coerced via _coerce_float string branch."""
    leak = _leak(fingerprint="fp-str-entropy")
    leak["Entropy"] = "4.81"
    parse_gitleaks_json(_payload(leak), b"", tmp_path, "gitleaks")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["entropy"] == pytest.approx(4.81)


def test_invalid_string_entropy_dropped(tmp_path: Path) -> None:
    """Unparseable Entropy string returns None (ValueError swallowed)."""
    leak = _leak(fingerprint="fp-bad-entropy")
    leak["Entropy"] = "not-a-float"
    parse_gitleaks_json(_payload(leak), b"", tmp_path, "gitleaks")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "entropy" not in blob


def test_non_list_tags_yields_no_tags(tmp_path: Path) -> None:
    """Non-list Tags field is normalised to empty and excluded from sidecar."""
    leak = _leak(fingerprint="fp-bad-tags")
    leak["Tags"] = "not-a-list"
    parse_gitleaks_json(_payload(leak), b"", tmp_path, "gitleaks")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "tags" not in blob


def test_unsupported_entropy_type_dropped(tmp_path: Path) -> None:
    """List/dict Entropy values fall through _coerce_float to None."""
    leak = _leak(fingerprint="fp-list-entropy")
    leak["Entropy"] = [1.0, 2.0]
    parse_gitleaks_json(_payload(leak), b"", tmp_path, "gitleaks")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "entropy" not in blob


def test_truncate_text_handles_missing_match_when_blob_large(tmp_path: Path) -> None:
    """When match_preview is None and blob exceeds cap, _truncate_text returns None."""
    leak = _leak(fingerprint="fp-large-no-match", description="X" * 4096)
    leak["Match"] = ""
    leak["Secret"] = ""
    parse_gitleaks_json(_payload(leak), b"", tmp_path, "gitleaks")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob.get("match_preview") is None
    assert blob["description"].endswith("...[truncated]")
