"""Unit tests for :mod:`src.sandbox.parsers.masscan_parser` (Backlog/dev1_md §4.2 — ARG-029).

Pinned contracts:

* Top-level JSON array envelope; canonical artefact path
  ``artifacts_dir/masscan.json`` is preferred over stdout.
* Defensive trailing-comma repair for legacy masscan releases that
  emit ``[..., ]`` instead of valid JSON.
* Only ``status=="open"`` records become findings; ``filtered`` /
  ``closed`` are dropped.
* Every finding → :class:`FindingCategory.INFO`, CWE [200, 668],
  confidence :class:`ConfidenceLevel.CONFIRMED`, severity ``info``.
* Dedup: ``(ip, port, proto)``.
* Non-list envelopes log ``masscan_parser_envelope_not_list`` and
  return ``[]``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers import masscan_parser as masscan_module
from src.sandbox.parsers.masscan_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_masscan_json,
)


def _record(
    *,
    ip: str = "10.0.0.100",
    port: int = 22,
    proto: str = "tcp",
    status: str = "open",
    reason: str = "syn-ack",
    ttl: int = 128,
    timestamp: str = "1716653779",
) -> dict[str, Any]:
    return {
        "ip": ip,
        "timestamp": timestamp,
        "ports": [
            {
                "port": port,
                "proto": proto,
                "status": status,
                "reason": reason,
                "ttl": ttl,
            }
        ],
    }


def _payload(*records: dict[str, Any]) -> bytes:
    return json.dumps(list(records)).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_masscan_json(b"", b"", tmp_path, "masscan") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "masscan.json"
    canonical.write_bytes(_payload(_record(port=80)))
    decoy = _payload(_record(port=4444))
    findings = parse_masscan_json(decoy, b"", tmp_path, "masscan")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "80" in sidecar
    assert "4444" not in sidecar


def test_finding_category_and_cwe(tmp_path: Path) -> None:
    findings = parse_masscan_json(_payload(_record()), b"", tmp_path, "masscan")
    assert findings[0].category is FindingCategory.INFO
    assert set(findings[0].cwe) == {200, 668}
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED
    assert findings[0].cvss_v3_score == pytest.approx(0.0)


def test_only_open_status_emitted(tmp_path: Path) -> None:
    payload = _payload(
        _record(port=22, status="open"),
        _record(port=23, status="filtered"),
        _record(port=24, status="closed"),
    )
    findings = parse_masscan_json(payload, b"", tmp_path, "masscan")
    assert len(findings) == 1


def test_dedup_collapses_same_endpoint(tmp_path: Path) -> None:
    payload = _payload(_record(port=443), _record(port=443))
    findings = parse_masscan_json(payload, b"", tmp_path, "masscan")
    assert len(findings) == 1


def test_distinct_ports_emit_distinct_findings(tmp_path: Path) -> None:
    payload = _payload(_record(port=22), _record(port=80), _record(port=443))
    findings = parse_masscan_json(payload, b"", tmp_path, "masscan")
    assert len(findings) == 3


def test_invalid_port_dropped_with_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    payload = _payload(_record(port=99_999), _record(port=443))
    with caplog.at_level("WARNING"):
        findings = parse_masscan_json(payload, b"", tmp_path, "masscan")
    assert len(findings) == 1
    assert any(
        "masscan_parser_invalid_port" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_envelope_not_list_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    canonical = tmp_path / "masscan.json"
    canonical.write_bytes(b'{"not": "an array"}')
    with caplog.at_level("WARNING"):
        findings = parse_masscan_json(b"", b"", tmp_path, "masscan")
    assert findings == []
    assert any(
        "masscan_parser_envelope_not_list" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_trailing_comma_repaired(tmp_path: Path) -> None:
    canonical = tmp_path / "masscan.json"
    canonical.write_bytes(
        b'[{"ip":"10.0.0.1","ports":[{"port":22,"proto":"tcp","status":"open"}]},]'
    )
    findings = parse_masscan_json(b"", b"", tmp_path, "masscan")
    assert len(findings) == 1


def test_missing_ip_skipped(tmp_path: Path) -> None:
    payload = json.dumps(
        [
            {
                "timestamp": "1",
                "ports": [{"port": 22, "proto": "tcp", "status": "open"}],
            },
            _record(port=443),
        ]
    ).encode("utf-8")
    findings = parse_masscan_json(payload, b"", tmp_path, "masscan")
    assert len(findings) == 1


def test_findings_sorted_deterministically(tmp_path: Path) -> None:
    payload = _payload(
        _record(ip="10.0.0.2", port=80),
        _record(ip="10.0.0.1", port=22),
        _record(ip="10.0.0.1", port=443),
    )
    parse_masscan_json(payload, b"", tmp_path, "masscan")
    sidecar_lines = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    pairs = [
        (json.loads(line)["ip"], json.loads(line)["port"]) for line in sidecar_lines
    ]
    assert pairs == sorted(pairs)


def test_evidence_sidecar_includes_tool_id(tmp_path: Path) -> None:
    parse_masscan_json(_payload(_record()), b"", tmp_path, "masscan-vlan-7")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["tool_id"] == "masscan-vlan-7"
    assert blob["status"] == "open"


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(masscan_module, "_MAX_FINDINGS", 2)
    payload = _payload(*(_record(port=p + 1) for p in range(5)))
    with caplog.at_level("WARNING"):
        findings = parse_masscan_json(payload, b"", tmp_path, "masscan")
    assert len(findings) == 2
    assert any(
        "masscan_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )
