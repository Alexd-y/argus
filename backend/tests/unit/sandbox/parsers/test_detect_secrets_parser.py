"""Unit tests for :mod:`src.sandbox.parsers.detect_secrets_parser` (Backlog/dev1_md §4.16 — ARG-029).

CRITICAL security gates verified here:

* ``hashed_secret`` is preserved verbatim (it is intentionally a hash,
  not a cleartext credential).
* If a hypothetical ``secret`` cleartext field appears, it is redacted
  through :func:`src.sandbox.parsers._base.redact_secret` and never
  surfaces in the sidecar.
* AWS / Private-Key / GCP plugin types escalate to ``critical`` (CVSS
  9.5).  Slack / Stripe / GitHub plugin types escalate to ``high``
  (CVSS 8.0).  Unknown plugins fall back to ``medium`` (CVSS 6.0).
* ``is_verified=true`` promotes confidence to ``CONFIRMED``.
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
from src.sandbox.parsers import detect_secrets_parser as detect_secrets_module
from src.sandbox.parsers.detect_secrets_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_detect_secrets_json,
)

_AWS_KEY_RE = re.compile(rb"AKIA[0-9A-Z]{16}")
_HIGH_ENTROPY_RE = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")
_HASH_HEX_40_RE = re.compile(r"^[0-9a-f]{40}$")


def _entry(
    *,
    plugin: str = "AWS Access Key",
    filename: str = "src/config/dev.env",
    hashed_secret: str = "daefe0b4345a654580dcad25c7c11ff4c944a8c0",
    is_verified: bool = False,
    line_number: int = 12,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "type": plugin,
        "filename": filename,
        "hashed_secret": hashed_secret,
        "is_verified": is_verified,
        "line_number": line_number,
    }
    if extra:
        record.update(extra)
    return record


def _payload(*entries: dict[str, Any]) -> bytes:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        grouped.setdefault(str(entry["filename"]), []).append(entry)
    document = {
        "version": "1.5.0",
        "plugins_used": [
            {"name": "AWSKeyDetector"},
            {"name": "PrivateKeyDetector"},
        ],
        "results": grouped,
        "generated_at": "2026-04-19T11:00:00Z",
    }
    return json.dumps(document).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_detect_secrets_json(b"", b"", tmp_path, "detect_secrets") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "detect-secrets.json"
    canonical.write_bytes(_payload(_entry(plugin="Private Key")))
    decoy = _payload(_entry(plugin="AWS Access Key"))
    findings = parse_detect_secrets_json(decoy, b"", tmp_path, "detect_secrets")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "Private Key" in sidecar
    assert "AWS Access Key" not in sidecar


def test_finding_category_and_cwe(tmp_path: Path) -> None:
    findings = parse_detect_secrets_json(
        _payload(_entry()), b"", tmp_path, "detect_secrets"
    )
    assert findings[0].category is FindingCategory.SECRET_LEAK
    assert set(findings[0].cwe) == {798, 312}


def test_aws_plugin_critical_severity(tmp_path: Path) -> None:
    findings = parse_detect_secrets_json(
        _payload(_entry(plugin="AWS Access Key")),
        b"",
        tmp_path,
        "detect_secrets",
    )
    assert findings[0].cvss_v3_score == pytest.approx(9.5)


def test_private_key_plugin_critical_severity(tmp_path: Path) -> None:
    findings = parse_detect_secrets_json(
        _payload(_entry(plugin="Private Key", filename="src/keys/dev.pem")),
        b"",
        tmp_path,
        "detect_secrets",
    )
    assert findings[0].cvss_v3_score == pytest.approx(9.5)


def test_github_plugin_high_severity(tmp_path: Path) -> None:
    findings = parse_detect_secrets_json(
        _payload(_entry(plugin="GitHub Token")),
        b"",
        tmp_path,
        "detect_secrets",
    )
    assert findings[0].cvss_v3_score == pytest.approx(8.0)


def test_unknown_plugin_medium_severity(tmp_path: Path) -> None:
    findings = parse_detect_secrets_json(
        _payload(_entry(plugin="Base64 High Entropy String")),
        b"",
        tmp_path,
        "detect_secrets",
    )
    assert findings[0].cvss_v3_score == pytest.approx(6.0)


def test_unknown_plugin_promoted_to_high_when_verified(tmp_path: Path) -> None:
    findings = parse_detect_secrets_json(
        _payload(_entry(plugin="Base64 High Entropy String", is_verified=True)),
        b"",
        tmp_path,
        "detect_secrets",
    )
    assert findings[0].cvss_v3_score == pytest.approx(8.0)


def test_verified_finding_confidence_confirmed(tmp_path: Path) -> None:
    findings = parse_detect_secrets_json(
        _payload(_entry(is_verified=True)),
        b"",
        tmp_path,
        "detect_secrets",
    )
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


def test_unverified_finding_confidence_likely(tmp_path: Path) -> None:
    findings = parse_detect_secrets_json(
        _payload(_entry(is_verified=False)),
        b"",
        tmp_path,
        "detect_secrets",
    )
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_hashed_secret_preserved_verbatim(tmp_path: Path) -> None:
    """CRITICAL — hashed_secret is a SHA-1 derivative, must NOT be redacted."""
    hashed = "daefe0b4345a654580dcad25c7c11ff4c944a8c0"
    parse_detect_secrets_json(
        _payload(_entry(hashed_secret=hashed)),
        b"",
        tmp_path,
        "detect_secrets",
    )
    sidecar_blob = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip()
    )
    assert sidecar_blob["hashed_secret"] == hashed
    assert _HASH_HEX_40_RE.match(sidecar_blob["hashed_secret"])


def test_cleartext_secret_field_redacted(tmp_path: Path) -> None:
    """CRITICAL — if cleartext ``secret`` ever appears, it MUST be redacted.

    ``hashed_secret`` (a SHA-1 fingerprint) is the *expected* persisted
    value; it is preserved verbatim because it is required for cross-scan
    correlation and is computationally hard to reverse.  Any *other*
    long opaque token in the sidecar would indicate a regression where
    a cleartext secret slipped past redaction.
    """
    cleartext = "AKIAIOSFODNN7EXAMPLE"
    hashed = "daefe0b4345a654580dcad25c7c11ff4c944a8c0"
    payload = _payload(_entry(hashed_secret=hashed, extra={"secret": cleartext}))
    parse_detect_secrets_json(payload, b"", tmp_path, "detect_secrets")
    sidecar_bytes = (tmp_path / EVIDENCE_SIDECAR_NAME).read_bytes()
    assert cleartext.encode("utf-8") not in sidecar_bytes
    assert not _AWS_KEY_RE.search(sidecar_bytes), (
        "raw AWS access key id leaked into detect_secrets sidecar"
    )
    assert b"REDACTED" in sidecar_bytes
    assert hashed.encode("utf-8") in sidecar_bytes, (
        "hashed_secret SHA-1 fingerprint must be preserved verbatim "
        "(needed for cross-scan correlation)"
    )


def test_dedup_collapses_same_plugin_filename_hash(tmp_path: Path) -> None:
    payload = _payload(_entry(line_number=10), _entry(line_number=42))
    findings = parse_detect_secrets_json(payload, b"", tmp_path, "detect_secrets")
    assert len(findings) == 1


def test_envelope_not_dict_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    canonical = tmp_path / "detect-secrets.json"
    canonical.write_bytes(b'["not", "a", "baseline"]')
    with caplog.at_level("WARNING"):
        findings = parse_detect_secrets_json(b"", b"", tmp_path, "detect_secrets")
    assert findings == []
    assert any(
        "detect_secrets_parser_envelope_not_object"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_results_missing_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    payload = json.dumps({"version": "1.5.0", "plugins_used": []}).encode("utf-8")
    with caplog.at_level("WARNING"):
        findings = parse_detect_secrets_json(payload, b"", tmp_path, "detect_secrets")
    assert findings == []
    assert any(
        "detect_secrets_parser_results_missing" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_findings_sorted_by_severity_descending(tmp_path: Path) -> None:
    payload = _payload(
        _entry(plugin="Base64 High Entropy String", filename="a.env"),
        _entry(plugin="GitHub Token", filename="b.env"),
        _entry(plugin="AWS Access Key", filename="c.env"),
    )
    findings = parse_detect_secrets_json(payload, b"", tmp_path, "detect_secrets")
    scores = [f.cvss_v3_score for f in findings]
    assert scores == sorted(scores, reverse=True)


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(detect_secrets_module, "_MAX_FINDINGS", 2)
    payload = _payload(
        *(
            _entry(hashed_secret=f"deadbeef{i:032x}", filename=f"file{i}.env")
            for i in range(5)
        )
    )
    with caplog.at_level("WARNING"):
        findings = parse_detect_secrets_json(payload, b"", tmp_path, "detect_secrets")
    assert len(findings) == 2
    assert any(
        "detect_secrets_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )
