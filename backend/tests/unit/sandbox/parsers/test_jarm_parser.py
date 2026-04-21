"""Unit tests for :mod:`src.sandbox.parsers.jarm_parser` (Backlog §4.4 — ARG-029).

Pinned contracts:

* Canonical artefact ``jarm.json`` overrides stdout.
* Three input shapes accepted: JSON array, single object, JSONL.
* All-zero JARM hashes are dropped (no TLS response).
* Each valid fingerprint → one INFO finding,
  category :class:`FindingCategory.INFO`, CWE 200, severity ``info``,
  confidence :class:`ConfidenceLevel.CONFIRMED`.
* The 62-character JARM hash itself is preserved verbatim (NOT a
  secret — it identifies a TLS stack).
* Dedup: ``(host, port, jarm)``.
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
from src.sandbox.parsers import jarm_parser as jarm_module
from src.sandbox.parsers.jarm_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_jarm_json,
)

_VALID_JARM = "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b099f3aef8"
_OTHER_JARM = "1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d"


def _record(
    *,
    host: str = "example.com",
    port: int | None = 443,
    fingerprint: str = _VALID_JARM,
    scheme: str = "https",
) -> dict[str, Any]:
    record: dict[str, Any] = {"host": host, "jarm": fingerprint, "scheme": scheme}
    if port is not None:
        record["port"] = port
    return record


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_jarm_json(b"", b"", tmp_path, "jarm") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "jarm.json"
    canonical.write_bytes(
        json.dumps([_record(host="canonical.example")]).encode("utf-8")
    )
    decoy = json.dumps([_record(host="decoy.example")]).encode("utf-8")
    findings = parse_jarm_json(decoy, b"", tmp_path, "jarm")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "canonical.example" in sidecar
    assert "decoy.example" not in sidecar


def test_finding_category_and_cwe(tmp_path: Path) -> None:
    payload = json.dumps([_record()]).encode("utf-8")
    findings = parse_jarm_json(payload, b"", tmp_path, "jarm")
    assert findings[0].category is FindingCategory.INFO
    assert 200 in findings[0].cwe
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED
    assert findings[0].cvss_v3_score == pytest.approx(0.0)


def test_array_envelope_supported(tmp_path: Path) -> None:
    payload = json.dumps(
        [_record(host="a"), _record(host="b", fingerprint=_OTHER_JARM)]
    ).encode("utf-8")
    findings = parse_jarm_json(payload, b"", tmp_path, "jarm")
    assert len(findings) == 2


def test_single_object_envelope_supported(tmp_path: Path) -> None:
    payload = json.dumps(_record()).encode("utf-8")
    findings = parse_jarm_json(payload, b"", tmp_path, "jarm")
    assert len(findings) == 1


def test_jsonl_envelope_supported(tmp_path: Path) -> None:
    payload = (
        json.dumps(_record(host="a")) + "\n" + json.dumps(_record(host="b"))
    ).encode("utf-8")
    findings = parse_jarm_json(payload, b"", tmp_path, "jarm")
    assert len(findings) == 2


def test_all_zero_fingerprint_dropped(tmp_path: Path) -> None:
    payload = json.dumps(
        [_record(fingerprint="0" * 62), _record(host="ok.example")]
    ).encode("utf-8")
    findings = parse_jarm_json(payload, b"", tmp_path, "jarm")
    assert len(findings) == 1


def test_invalid_fingerprint_dropped(tmp_path: Path) -> None:
    payload = json.dumps(
        [_record(fingerprint="not-a-jarm-hash"), _record(host="ok.example")]
    ).encode("utf-8")
    findings = parse_jarm_json(payload, b"", tmp_path, "jarm")
    assert len(findings) == 1


def test_default_port_443_when_missing(tmp_path: Path) -> None:
    payload = json.dumps([_record(port=None)]).encode("utf-8")
    parse_jarm_json(payload, b"", tmp_path, "jarm")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["port"] == 443


def test_jarm_hash_preserved_verbatim(tmp_path: Path) -> None:
    payload = json.dumps([_record()]).encode("utf-8")
    parse_jarm_json(payload, b"", tmp_path, "jarm")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert _VALID_JARM in sidecar


def test_dedup_collapses_same_host_port_jarm(tmp_path: Path) -> None:
    payload = json.dumps([_record(), _record()]).encode("utf-8")
    findings = parse_jarm_json(payload, b"", tmp_path, "jarm")
    assert len(findings) == 1


def test_findings_sorted_by_host(tmp_path: Path) -> None:
    payload = json.dumps(
        [
            _record(host="zeta.example"),
            _record(host="alpha.example"),
            _record(host="mu.example"),
        ]
    ).encode("utf-8")
    parse_jarm_json(payload, b"", tmp_path, "jarm")
    lines = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    hosts = [json.loads(line)["host"] for line in lines]
    assert hosts == sorted(hosts)


def test_missing_host_skipped(tmp_path: Path) -> None:
    payload = json.dumps(
        [{"jarm": _VALID_JARM, "port": 443}, _record(host="ok")]
    ).encode("utf-8")
    findings = parse_jarm_json(payload, b"", tmp_path, "jarm")
    assert len(findings) == 1


def test_target_field_aliased_to_host(tmp_path: Path) -> None:
    payload = json.dumps(
        [{"target": "alias.example", "jarm": _VALID_JARM, "port": 443}]
    ).encode("utf-8")
    findings = parse_jarm_json(payload, b"", tmp_path, "jarm")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "alias.example" in sidecar


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(jarm_module, "_MAX_FINDINGS", 2)
    payload = json.dumps([_record(host=f"host-{i}.example") for i in range(5)]).encode(
        "utf-8"
    )
    with caplog.at_level("WARNING"):
        findings = parse_jarm_json(payload, b"", tmp_path, "jarm")
    assert len(findings) == 2
    assert any(
        "jarm_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_array_with_only_invalid_returns_empty(tmp_path: Path) -> None:
    """Cover the post-iter ``if not records`` early-exit branch."""
    payload = json.dumps([{"host": "x"}]).encode("utf-8")  # missing jarm
    assert parse_jarm_json(payload, b"", tmp_path, "jarm") == []


def test_artifact_unreadable_falls_back_to_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When the canonical artefact is unreadable, parser must fall back to stdout."""
    canonical = tmp_path / "jarm.json"
    canonical.write_bytes(b"placeholder")
    original_read_bytes = Path.read_bytes

    def _explode(self: Path) -> bytes:
        if self == canonical:
            raise OSError("simulated permission denied")
        return original_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _explode)
    payload = json.dumps([_record()]).encode("utf-8")
    with caplog.at_level("WARNING", logger=jarm_module._logger.name):
        findings = parse_jarm_json(payload, b"", tmp_path, "jarm")
    assert len(findings) == 1
    assert any(
        "jarm_parser_artifact_unreadable" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_array_envelope_with_non_list_returns_empty(tmp_path: Path) -> None:
    """JSON starting with ``[`` but not parsing to a list must short-circuit."""
    canonical = tmp_path / "jarm.json"
    canonical.write_bytes(b"[\n")  # malformed array
    findings = parse_jarm_json(b"", b"", tmp_path, "jarm")
    assert findings == []


def test_object_envelope_with_non_dict_returns_empty(tmp_path: Path) -> None:
    """A bare JSONL line that fails to decode must short-circuit cleanly."""
    canonical = tmp_path / "jarm.json"
    canonical.write_bytes(b"{not json")
    findings = parse_jarm_json(b"", b"", tmp_path, "jarm")
    assert findings == []


def test_port_string_coerced_to_int(tmp_path: Path) -> None:
    payload = json.dumps([{"host": "x", "port": "8443", "jarm": _VALID_JARM}]).encode(
        "utf-8"
    )
    parse_jarm_json(payload, b"", tmp_path, "jarm")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["port"] == 8443


def test_port_out_of_range_falls_back_to_default(tmp_path: Path) -> None:
    payload = json.dumps([{"host": "x", "port": 0, "jarm": _VALID_JARM}]).encode(
        "utf-8"
    )
    parse_jarm_json(payload, b"", tmp_path, "jarm")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["port"] == 443


def test_port_bool_rejected(tmp_path: Path) -> None:
    """``isinstance(True, int)`` is True — guard explicitly so ``True`` is not 1."""
    payload = json.dumps([{"host": "x", "port": True, "jarm": _VALID_JARM}]).encode(
        "utf-8"
    )
    parse_jarm_json(payload, b"", tmp_path, "jarm")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["port"] == 443


def test_port_non_numeric_string_falls_back(tmp_path: Path) -> None:
    payload = json.dumps(
        [{"host": "x", "port": "not-a-port", "jarm": _VALID_JARM}]
    ).encode("utf-8")
    parse_jarm_json(payload, b"", tmp_path, "jarm")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["port"] == 443
