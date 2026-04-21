"""Unit tests for :mod:`src.sandbox.parsers.naabu_parser` (Backlog/dev1_md §4.2 — ARG-029).

Pinned contracts:

* JSONL envelope (one JSON object per line); canonical artefact path
  ``artifacts_dir/naabu.json`` is preferred over stdout.
* Every record produces an INFO finding with category
  :class:`FindingCategory.INFO`, CWE-200 / CWE-668 and confidence
  :class:`ConfidenceLevel.CONFIRMED`.
* Severity stays ``info`` — port discovery alone is not a vulnerability.
* Dedup: ``(ip, port, protocol)``.
* Records missing ``port`` or with invalid ``port`` (>65535 or <=0)
  are dropped with a structured warning.
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
from src.sandbox.parsers import naabu_parser as naabu_module
from src.sandbox.parsers.naabu_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_naabu_jsonl,
)


def _record(
    *,
    ip: str = "10.0.0.5",
    port: int | str = 443,
    host: str = "api.example.com",
    protocol: str = "tcp",
) -> dict[str, Any]:
    return {
        "ip": ip,
        "port": port,
        "host": host,
        "protocol": protocol,
        "timestamp": "2026-04-19T11:22:33Z",
    }


def _payload(*records: dict[str, Any]) -> bytes:
    return ("\n".join(json.dumps(record) for record in records) + "\n").encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_naabu_jsonl(b"", b"", tmp_path, "naabu") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "naabu.json"
    canonical.write_bytes(_payload(_record(port=8443)))
    decoy = _payload(_record(port=9999))
    findings = parse_naabu_jsonl(decoy, b"", tmp_path, "naabu")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "8443" in sidecar
    assert "9999" not in sidecar


def test_finding_category_and_cwe(tmp_path: Path) -> None:
    findings = parse_naabu_jsonl(_payload(_record()), b"", tmp_path, "naabu")
    assert findings[0].category is FindingCategory.INFO
    assert set(findings[0].cwe) == {200, 668}
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


def test_findings_have_zero_cvss(tmp_path: Path) -> None:
    findings = parse_naabu_jsonl(_payload(_record()), b"", tmp_path, "naabu")
    assert findings[0].cvss_v3_score == pytest.approx(0.0)


def test_dedup_collapses_same_endpoint(tmp_path: Path) -> None:
    payload = _payload(_record(port=443), _record(port=443))
    findings = parse_naabu_jsonl(payload, b"", tmp_path, "naabu")
    assert len(findings) == 1


def test_distinct_ports_emit_distinct_findings(tmp_path: Path) -> None:
    payload = _payload(_record(port=80), _record(port=443), _record(port=8080))
    findings = parse_naabu_jsonl(payload, b"", tmp_path, "naabu")
    assert len(findings) == 3


def test_missing_port_dropped_with_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    raw = _record()
    raw.pop("port")
    payload = _payload(raw, _record(port=443))
    with caplog.at_level("WARNING"):
        findings = parse_naabu_jsonl(payload, b"", tmp_path, "naabu")
    assert len(findings) == 1
    assert any(
        "naabu_parser_invalid_port" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_invalid_port_dropped(tmp_path: Path) -> None:
    payload = _payload(_record(port=99_999), _record(port=0), _record(port=443))
    findings = parse_naabu_jsonl(payload, b"", tmp_path, "naabu")
    assert len(findings) == 1


def test_string_port_coerced_to_int(tmp_path: Path) -> None:
    payload = _payload(_record(port="443"))
    findings = parse_naabu_jsonl(payload, b"", tmp_path, "naabu")
    assert len(findings) == 1
    sidecar = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert sidecar["port"] == 443


def test_findings_sorted_deterministically(tmp_path: Path) -> None:
    payload = _payload(
        _record(ip="10.0.0.1", port=8080),
        _record(ip="10.0.0.2", port=22),
        _record(ip="10.0.0.1", port=443),
    )
    parse_naabu_jsonl(payload, b"", tmp_path, "naabu")
    sidecar_lines = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    pairs = [
        (json.loads(line)["ip"], json.loads(line)["port"]) for line in sidecar_lines
    ]
    assert pairs == sorted(pairs)


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(naabu_module, "_MAX_FINDINGS", 2)
    payload = _payload(*(_record(port=p + 1) for p in range(5)))
    with caplog.at_level("WARNING"):
        findings = parse_naabu_jsonl(payload, b"", tmp_path, "naabu")
    assert len(findings) == 2
    assert any(
        "naabu_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_evidence_sidecar_includes_tool_id(tmp_path: Path) -> None:
    payload = _payload(_record())
    parse_naabu_jsonl(payload, b"", tmp_path, "naabu-custom")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["tool_id"] == "naabu-custom"


def test_record_without_ip_or_host_skipped(tmp_path: Path) -> None:
    """Records with neither ``ip`` nor ``host`` cannot be acted on — drop them."""
    payload = _payload({"port": 443}, _record(host="api"))
    findings = parse_naabu_jsonl(payload, b"", tmp_path, "naabu")
    assert len(findings) == 1


def test_string_field_returns_none_for_non_string(tmp_path: Path) -> None:
    """Numeric fields must not be treated as strings."""
    payload = _payload({"ip": 12345, "port": 443, "host": "ok", "protocol": "tcp"})
    parse_naabu_jsonl(payload, b"", tmp_path, "naabu")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob.get("ip") is None or blob["ip"] == ""


def test_bool_port_rejected(tmp_path: Path) -> None:
    """``isinstance(True, int)`` is True — guard so ``True`` doesn't become port=1."""
    payload = _payload({"ip": "1.1.1.1", "port": True, "host": "x"})
    findings = parse_naabu_jsonl(payload, b"", tmp_path, "naabu")
    assert findings == []


def test_tls_string_variants_coerced(tmp_path: Path) -> None:
    """``tls`` may arrive as a string in older naabu builds."""
    payload = _payload(
        {"ip": "1.1.1.1", "port": 443, "host": "a", "protocol": "tcp", "tls": "yes"},
        {"ip": "1.1.1.2", "port": 443, "host": "b", "protocol": "tcp", "tls": "no"},
        {
            "ip": "1.1.1.3",
            "port": 443,
            "host": "c",
            "protocol": "tcp",
            "tls": "maybe",
        },
    )
    parse_naabu_jsonl(payload, b"", tmp_path, "naabu")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    blobs = [json.loads(line) for line in sidecar]
    by_ip = {b["ip"]: b for b in blobs}
    assert by_ip["1.1.1.1"]["tls"] is True
    assert by_ip["1.1.1.2"]["tls"] is False
    assert "tls" not in by_ip["1.1.1.3"] or by_ip["1.1.1.3"].get("tls") is None
