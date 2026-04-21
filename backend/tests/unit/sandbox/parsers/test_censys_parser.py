"""Unit tests for :mod:`src.sandbox.parsers.censys_parser` (ARG-032 batch 4c).

Pinned contracts:

* Empty stdout ⇒ ``[]``.
* One INFO finding per ``(ip, port, service_name)`` tuple.
* Software list folded into evidence for downstream CVE matching.
* Records with malformed ``ip`` / ``services`` skipped silently.
* Canonical artifact ``censys.json`` overrides stdout.
* Sidecar JSONL stamped with ``tool_id`` and 12-char ``fingerprint_hash``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.censys_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_censys,
)


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_censys(b"", b"", tmp_path, "censys") == []


def test_single_record_one_service_yields_one_finding(tmp_path: Path) -> None:
    payload = json.dumps(
        [
            {
                "ip": "10.0.0.1",
                "services": [
                    {
                        "port": 443,
                        "service_name": "HTTP",
                        "extended_service_name": "HTTPS",
                        "transport_protocol": "TCP",
                        "software": [
                            {"vendor": "nginx", "product": "nginx", "version": "1.18.0"}
                        ],
                    }
                ],
                "autonomous_system": {"asn": 64500, "name": "ExampleAS"},
                "location": {"country": "US"},
            }
        ]
    ).encode("utf-8")
    findings = parse_censys(payload, b"", tmp_path, "censys")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


def test_multiple_services_emit_separate_findings(tmp_path: Path) -> None:
    payload = json.dumps(
        [
            {
                "ip": "10.0.0.1",
                "services": [
                    {"port": 80, "service_name": "HTTP"},
                    {"port": 443, "service_name": "HTTPS"},
                    {"port": 22, "service_name": "SSH"},
                ],
            }
        ]
    ).encode("utf-8")
    findings = parse_censys(payload, b"", tmp_path, "censys")
    assert len(findings) == 3


def test_dedup_on_repeated_service(tmp_path: Path) -> None:
    payload = json.dumps(
        [
            {
                "ip": "10.0.0.1",
                "services": [
                    {"port": 443, "service_name": "HTTPS"},
                    {"port": 443, "service_name": "HTTPS"},
                ],
            }
        ]
    ).encode("utf-8")
    assert len(parse_censys(payload, b"", tmp_path, "censys")) == 1


def test_records_without_ip_skipped(tmp_path: Path) -> None:
    payload = json.dumps([{"services": [{"port": 80, "service_name": "HTTP"}]}]).encode(
        "utf-8"
    )
    assert parse_censys(payload, b"", tmp_path, "censys") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = json.dumps(
        [{"ip": "10.0.0.99", "services": [{"port": 443, "service_name": "HTTPS"}]}]
    ).encode("utf-8")
    (tmp_path / "censys.json").write_bytes(canonical)
    decoy = json.dumps(
        [{"ip": "1.1.1.1", "services": [{"port": 80, "service_name": "HTTP"}]}]
    ).encode("utf-8")
    findings = parse_censys(decoy, b"", tmp_path, "censys")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["ip"] == "10.0.0.99"


def test_sidecar_includes_software_summary(tmp_path: Path) -> None:
    payload = json.dumps(
        [
            {
                "ip": "10.0.0.1",
                "services": [
                    {
                        "port": 443,
                        "service_name": "HTTPS",
                        "software": [{"product": "nginx", "version": "1.18.0"}],
                    }
                ],
            }
        ]
    ).encode("utf-8")
    parse_censys(payload, b"", tmp_path, "censys")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["tool_id"] == "censys"
    assert record["ip"] == "10.0.0.1"
    assert record["port"] == 443
    assert record["software"] == [{"product": "nginx", "version": "1.18.0"}]
    assert isinstance(record["fingerprint_hash"], str)
    assert len(record["fingerprint_hash"]) == 12


def test_nested_hits_envelope_supported(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "hits": [
                {
                    "ip": "10.0.0.1",
                    "services": [{"port": 443, "service_name": "HTTPS"}],
                }
            ]
        }
    ).encode("utf-8")
    findings = parse_censys(payload, b"", tmp_path, "censys")
    assert len(findings) == 1
