"""Unit tests for :mod:`src.sandbox.parsers.trufflehog_parser` (Backlog/dev1_md §4.16 — ARG-029).

Pinned contracts:

* JSONL envelope (one JSON object per line); canonical artefact path
  ``artifacts_dir/trufflehog.json`` is preferred over stdout.
* **CRITICAL** secret redaction — ``Raw`` / ``RawV2`` / ``Redacted``
  fields MUST be passed through ``redact_secret`` BEFORE either DTO
  construction or sidecar persistence.  The test
  :func:`test_no_raw_secret_pattern_in_sidecar_bytes` mirrors the
  integration ratchet: zero matches against the high-entropy
  ``[A-Za-z0-9/_+]{40,}`` pattern in the on-disk sidecar.
* Severity classification — ``aws-*`` / ``private-*`` / ``rsa-*`` etc.
  → ``critical``; ``github`` / ``slack`` / ``jwt`` / ``twilio`` etc.
  → ``high``; everything else → ``medium``; ``Verified=true``
  escalates ``medium`` → ``high``.
* Confidence: verified → CONFIRMED, otherwise LIKELY.
* Category: every finding → :class:`FindingCategory.SECRET_LEAK`.
* CWE: pinned ``[798, 312]`` (hard-coded creds + cleartext storage).
* Dedup: ``(detector_name, file, line)``.
* Cap: hard-limited at ``_MAX_FINDINGS`` (5_000).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers import trufflehog_parser as trufflehog_module
from src.sandbox.parsers.trufflehog_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_trufflehog_jsonl,
)


_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
_HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9/_+]{40,}")


def _record(
    *,
    detector_name: str = "AWS",
    detector_type: int = 2,
    verified: bool = False,
    raw: str = "AKIAIOSFODNN7EXAMPLE",
    raw_v2: str = "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    redacted: str = "AKIAIOSFODNN7EXAMPLE",
    file_path: str = "src/config/dev.env",
    line: int = 12,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "DetectorName": detector_name,
        "DetectorType": detector_type,
        "DecoderName": "PLAIN",
        "Verified": verified,
        "VerificationError": "" if verified else "no verifier configured",
        "Raw": raw,
        "RawV2": raw_v2,
        "Redacted": redacted,
        "ExtraData": extra or {"account": "123456789012"},
        "SourceID": 12_345,
        "SourceName": "trufflehog - filesystem",
        "SourceType": 15,
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": file_path,
                    "line": line,
                }
            }
        },
    }


def _payload(*records: dict[str, Any]) -> bytes:
    return ("\n".join(json.dumps(record) for record in records) + "\n").encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_trufflehog_jsonl(b"", b"", tmp_path, "trufflehog") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "trufflehog.json"
    canonical.write_bytes(_payload(_record(detector_name="AWS")))
    decoy = _payload(_record(detector_name="ignored"))
    findings = parse_trufflehog_jsonl(decoy, b"", tmp_path, "trufflehog")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "AWS" in sidecar
    assert "ignored" not in sidecar


def test_aws_detector_classified_as_critical(tmp_path: Path) -> None:
    findings = parse_trufflehog_jsonl(
        _payload(_record(detector_name="AWS")), b"", tmp_path, "trufflehog"
    )
    assert findings[0].cvss_v3_score == pytest.approx(9.5)


def test_github_detector_classified_as_high(tmp_path: Path) -> None:
    findings = parse_trufflehog_jsonl(
        _payload(_record(detector_name="GitHub")),
        b"",
        tmp_path,
        "trufflehog",
    )
    assert findings[0].cvss_v3_score == pytest.approx(8.0)


def test_unknown_detector_falls_back_to_medium(tmp_path: Path) -> None:
    findings = parse_trufflehog_jsonl(
        _payload(_record(detector_name="VendorX")),
        b"",
        tmp_path,
        "trufflehog",
    )
    assert findings[0].cvss_v3_score == pytest.approx(6.0)


def test_verified_escalates_medium_to_high(tmp_path: Path) -> None:
    findings = parse_trufflehog_jsonl(
        _payload(_record(detector_name="VendorX", verified=True)),
        b"",
        tmp_path,
        "trufflehog",
    )
    assert findings[0].cvss_v3_score == pytest.approx(8.0)
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


def test_unverified_finding_marked_likely(tmp_path: Path) -> None:
    findings = parse_trufflehog_jsonl(
        _payload(_record(detector_name="GitHub", verified=False)),
        b"",
        tmp_path,
        "trufflehog",
    )
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_findings_use_secret_leak_category_and_pinned_cwe(tmp_path: Path) -> None:
    findings = parse_trufflehog_jsonl(_payload(_record()), b"", tmp_path, "trufflehog")
    assert findings[0].category is FindingCategory.SECRET_LEAK
    assert findings[0].cwe == [798, 312]


def test_no_raw_secret_pattern_in_sidecar_bytes(tmp_path: Path) -> None:
    """CRITICAL — sidecar must contain ZERO raw secret patterns."""
    secret = "AKIAIOSFODNN7EXAMPLE"
    long_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    parse_trufflehog_jsonl(
        _payload(_record(raw=secret, raw_v2=f"{secret}:{long_secret}")),
        b"",
        tmp_path,
        "trufflehog",
    )
    sidecar_bytes = (tmp_path / EVIDENCE_SIDECAR_NAME).read_bytes()
    assert not _AWS_KEY_RE.search(sidecar_bytes.decode("utf-8")), (
        "raw AWS access key id leaked through redaction"
    )
    assert not _HIGH_ENTROPY_RE.search(sidecar_bytes.decode("utf-8")), (
        "high-entropy raw secret blob leaked through redaction"
    )
    assert b"REDACTED" in sidecar_bytes


def test_dedup_collapses_same_detector_same_location(tmp_path: Path) -> None:
    payload = _payload(
        _record(detector_name="AWS", file_path="a.env", line=10),
        _record(detector_name="AWS", file_path="a.env", line=10),
    )
    findings = parse_trufflehog_jsonl(payload, b"", tmp_path, "trufflehog")
    assert len(findings) == 1


def test_dedup_keeps_distinct_locations(tmp_path: Path) -> None:
    payload = _payload(
        _record(detector_name="AWS", file_path="a.env", line=10),
        _record(detector_name="AWS", file_path="a.env", line=11),
        _record(detector_name="AWS", file_path="b.env", line=10),
    )
    findings = parse_trufflehog_jsonl(payload, b"", tmp_path, "trufflehog")
    assert len(findings) == 3


def test_findings_sorted_severity_desc(tmp_path: Path) -> None:
    payload = _payload(
        _record(detector_name="VendorX", file_path="m.env", line=1),
        _record(detector_name="AWS", file_path="a.env", line=2),
        _record(detector_name="GitHub", file_path="b.env", line=3),
    )
    findings = parse_trufflehog_jsonl(payload, b"", tmp_path, "trufflehog")
    assert len(findings) == 3
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    severities = [json.loads(line)["severity"] for line in sidecar]
    assert severities == ["critical", "high", "medium"]


def test_missing_detector_dropped_with_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    raw = _record()
    raw.pop("DetectorName")
    payload = _payload(raw, _record(detector_name="AWS"))
    with caplog.at_level("WARNING"):
        findings = parse_trufflehog_jsonl(payload, b"", tmp_path, "trufflehog")
    assert len(findings) == 1
    assert any(
        "trufflehog_parser_record_missing_field" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(trufflehog_module, "_MAX_FINDINGS", 2)
    payload = _payload(
        *(
            _record(detector_name=f"D{i}", file_path=f"f{i}.env", line=i + 1)
            for i in range(5)
        )
    )
    with caplog.at_level("WARNING"):
        findings = parse_trufflehog_jsonl(payload, b"", tmp_path, "trufflehog")
    assert len(findings) == 2
    assert any(
        "trufflehog_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_extra_data_keys_surfaced_values_dropped(tmp_path: Path) -> None:
    payload = _payload(
        _record(extra={"account_id": "123456789012", "region": "us-east-1"})
    )
    parse_trufflehog_jsonl(payload, b"", tmp_path, "trufflehog")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "account_id" in sidecar
    assert "region" in sidecar
    assert "us-east-1" not in sidecar
    assert "123456789012" not in sidecar


def test_owasp_wstg_includes_athn_06(tmp_path: Path) -> None:
    findings = parse_trufflehog_jsonl(_payload(_record()), b"", tmp_path, "trufflehog")
    assert "WSTG-ATHN-06" in findings[0].owasp_wstg
