"""Unit tests for :mod:`src.sandbox.parsers.dnsrecon_parser` (ARG-032).

Pinned contracts:

* Empty stdout ⇒ ``[]``.
* JSON array shape supported; ``records`` / ``results`` envelopes too.
* AXFR records escalate to MISCONFIG (CVSS 5.3, CWE-200/668/16).
* A / NS / MX records emit INFO findings.
* Hostname is pulled from ``name`` / ``target`` / ``exchange`` keys.
* Dedup on ``(record_type, host)`` — A + AAAA for the same host
  surface separately.
* Sidecar JSONL stamped with ``tool_id``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers.dnsrecon_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_dnsrecon,
)


def _payload(records: list[dict[str, object]]) -> bytes:
    return json.dumps(records).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_dnsrecon(b"", b"", tmp_path, "dnsrecon") == []


def test_a_records_emit_info_findings(tmp_path: Path) -> None:
    stdout = _payload(
        [
            {"type": "A", "name": "www.example.com", "address": "1.2.3.4"},
            {"type": "A", "name": "api.example.com", "address": "5.6.7.8"},
        ]
    )
    findings = parse_dnsrecon(stdout, b"", tmp_path, "dnsrecon")
    assert len(findings) == 2
    assert all(f.category is FindingCategory.INFO for f in findings)


def test_axfr_record_escalates_to_misconfig(tmp_path: Path) -> None:
    stdout = _payload([{"type": "AXFR", "name": "example.com"}])
    findings = parse_dnsrecon(stdout, b"", tmp_path, "dnsrecon")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.MISCONFIG
    assert finding.cvss_v3_score == 5.3
    assert 668 in finding.cwe


def test_mx_record_uses_exchange_field(tmp_path: Path) -> None:
    stdout = _payload(
        [{"type": "MX", "exchange": "mail.example.com", "preference": 10}]
    )
    findings = parse_dnsrecon(stdout, b"", tmp_path, "dnsrecon")
    assert len(findings) == 1


def test_records_envelope_supported(tmp_path: Path) -> None:
    stdout = json.dumps({"records": [{"type": "A", "name": "api.example.com"}]}).encode(
        "utf-8"
    )
    assert len(parse_dnsrecon(stdout, b"", tmp_path, "dnsrecon")) == 1


def test_dedup_on_type_and_host(tmp_path: Path) -> None:
    stdout = _payload(
        [
            {"type": "A", "name": "api.example.com"},
            {"type": "A", "name": "API.example.com"},
            {"type": "AAAA", "name": "api.example.com"},
        ]
    )
    assert len(parse_dnsrecon(stdout, b"", tmp_path, "dnsrecon")) == 2


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "dnsrecon.json").write_bytes(
        _payload([{"type": "A", "name": "canonical.example.com"}])
    )
    findings = parse_dnsrecon(
        _payload([{"type": "A", "name": "decoy.example.com"}]),
        b"",
        tmp_path,
        "dnsrecon",
    )
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical.example.com" in sidecar


def test_sidecar_marks_axfr(tmp_path: Path) -> None:
    parse_dnsrecon(
        _payload([{"type": "AXFR", "name": "example.com"}]),
        b"",
        tmp_path,
        "dnsrecon",
    )
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["zone_transfer"] is True
    assert record["tool_id"] == "dnsrecon"
