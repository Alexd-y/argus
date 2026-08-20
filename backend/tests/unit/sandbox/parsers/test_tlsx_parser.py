"""Unit tests for :mod:`src.sandbox.parsers.tlsx_parser` (Backlog §4.3).

Pinned contracts:

* Single JSON object, JSON array, and JSONL streams are all accepted.
* Canonical ``tlsx.json`` artefact overrides stdout.
* A clean modern handshake yields exactly one INFO finding (CWE-200).
* Deprecated protocol / weak cipher / expired / self-signed / mismatched
  each add one low-severity CRYPTO finding.
* Empty / garbage input returns ``[]``.
* Sidecar JSONL is stamped with ``tool_id``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.tlsx_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_tlsx_json,
)


def _strong_record(host: str = "example.com") -> dict[str, Any]:
    return {
        "host": host,
        "ip": "93.184.216.34",
        "port": "443",
        "tls_version": "tls13",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "not_before": "2024-03-14T00:00:00Z",
        "not_after": "2027-03-14T23:59:59Z",
        "subject_cn": "www.example.org",
        "subject_an": ["example.com", "www.example.com"],
        "issuer_cn": "DigiCert TLS RSA SHA256 2020 CA1",
        "self_signed": False,
        "expired": False,
        "mismatched": False,
        "sni": "example.com",
        "jarm_hash": "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b099f3aef84",
    }


def _weak_record(host: str = "legacy.test") -> dict[str, Any]:
    return {
        "host": host,
        "port": "443",
        "tls_version": "tls10",
        "cipher": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "self_signed": True,
        "expired": True,
        "mismatched": True,
    }


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_tlsx_json(b"", b"", tmp_path, "tlsx") == []


def test_empty_json_object_returns_no_findings(tmp_path: Path) -> None:
    assert parse_tlsx_json(b"{}", b"", tmp_path, "tlsx") == []


def test_strong_handshake_single_info_finding(tmp_path: Path) -> None:
    payload = json.dumps(_strong_record()).encode("utf-8")
    findings = parse_tlsx_json(payload, b"", tmp_path, "tlsx")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.INFO
    assert 200 in finding.cwe
    assert finding.confidence is ConfidenceLevel.CONFIRMED
    assert finding.cvss_v3_score == 0.0


def test_weak_record_emits_summary_plus_crypto_findings(tmp_path: Path) -> None:
    payload = json.dumps(_weak_record()).encode("utf-8")
    findings = parse_tlsx_json(payload, b"", tmp_path, "tlsx")
    categories = [f.category for f in findings]
    # tls_summary INFO + deprecated_protocol + weak_cipher + expired +
    # self_signed + mismatched = 6 findings.
    assert len(findings) == 6
    assert categories.count(FindingCategory.INFO) == 1
    assert categories.count(FindingCategory.CRYPTO) == 5
    assert all(f.cvss_v3_score <= 5.3 for f in findings)


def test_deprecated_protocol_flagged(tmp_path: Path) -> None:
    record = _strong_record()
    record["tls_version"] = "tls10"
    payload = json.dumps(record).encode("utf-8")
    findings = parse_tlsx_json(payload, b"", tmp_path, "tlsx")
    crypto = [f for f in findings if f.category is FindingCategory.CRYPTO]
    assert len(crypto) == 1
    assert 326 in crypto[0].cwe


def test_weak_cipher_flagged(tmp_path: Path) -> None:
    record = _strong_record()
    record["cipher"] = "TLS_RSA_WITH_RC4_128_MD5"
    payload = json.dumps(record).encode("utf-8")
    findings = parse_tlsx_json(payload, b"", tmp_path, "tlsx")
    crypto = [f for f in findings if f.category is FindingCategory.CRYPTO]
    assert len(crypto) == 1


def test_json_array_envelope(tmp_path: Path) -> None:
    payload = json.dumps([_strong_record("a.test"), _strong_record("b.test")]).encode("utf-8")
    findings = parse_tlsx_json(payload, b"", tmp_path, "tlsx")
    assert len(findings) == 2


def test_jsonl_envelope(tmp_path: Path) -> None:
    payload = (
        json.dumps(_strong_record("a.test")) + "\n" + json.dumps(_strong_record("b.test"))
    ).encode("utf-8")
    findings = parse_tlsx_json(payload, b"", tmp_path, "tlsx")
    assert len(findings) == 2


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "tlsx.json"
    canonical.write_bytes(json.dumps(_strong_record("canonical.test")).encode("utf-8"))
    decoy = json.dumps(_strong_record("decoy.test")).encode("utf-8")
    parse_tlsx_json(decoy, b"", tmp_path, "tlsx")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "canonical.test" in sidecar
    assert "decoy.test" not in sidecar


def test_dedup_collapses_repeat_records(tmp_path: Path) -> None:
    payload = json.dumps([_strong_record(), _strong_record()]).encode("utf-8")
    findings = parse_tlsx_json(payload, b"", tmp_path, "tlsx")
    assert len(findings) == 1


def test_missing_host_skipped(tmp_path: Path) -> None:
    record = _strong_record()
    del record["host"]
    del record["ip"]
    payload = json.dumps([record, _strong_record("ok.test")]).encode("utf-8")
    findings = parse_tlsx_json(payload, b"", tmp_path, "tlsx")
    assert len(findings) == 1


def test_garbage_returns_no_findings(tmp_path: Path) -> None:
    assert parse_tlsx_json(b"not json at all\n<<<>>>", b"", tmp_path, "tlsx") == []


def test_sidecar_stamped_with_tool_id(tmp_path: Path) -> None:
    payload = json.dumps(_strong_record()).encode("utf-8")
    parse_tlsx_json(payload, b"", tmp_path, "tlsx")
    record = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()[0])
    assert record["tool_id"] == "tlsx"
    assert record["host"] == "example.com"
