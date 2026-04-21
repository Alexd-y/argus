"""Unit tests for :mod:`src.sandbox.parsers.hashid_parser` (Backlog §4.13 — ARG-029).

CRITICAL — raw hash bytes are NEVER persisted in the sidecar.

Pinned contracts:

* Canonical artefact ``hashid.json`` overrides stdout.
* Top-level array envelope; non-list payloads emit
  ``hashid_parser_payload_not_array`` and return ``[]``.
* Each ``(hash, top-mode)`` pair → one INFO finding,
  category :class:`FindingCategory.CRYPTO`, CWE 326,
  severity ``info``, confidence
  :class:`ConfidenceLevel.LIKELY`.
* Sidecar persists ``stable_hash_12(hash)`` plus ``hash_length`` and
  the modes list — NEVER the raw cleartext hash bytes.
* When multiple modes are present and one matches a preferred hashcat
  ID (1000=NTLM, 1100, 1500, 1600, 1700, 1800, 3200, 5500, 5600, 7400,
  9900) it becomes ``preferred_mode``.
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
from src.sandbox.parsers import hashid_parser as hashid_module
from src.sandbox.parsers._base import stable_hash_12
from src.sandbox.parsers.hashid_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_hashid_json,
)

_RAW_MD5 = "5f4dcc3b5aa765d61d8327deb882cf99"
_RAW_SHA1 = "21BD12DC183F740EE76F27B78EB39C8AD972A757"
_HEX32_RE = re.compile(rb"\b[0-9a-fA-F]{32}\b")
_HEX40_RE = re.compile(rb"\b[0-9a-fA-F]{40}\b")


def _entry(
    *,
    hash_value: str = _RAW_MD5,
    modes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "hash": hash_value,
        "modes": modes
        or [
            {"name": "MD5", "hashcat": 0, "john": "raw-md5"},
            {"name": "MD4", "hashcat": None, "john": "raw-md4"},
        ],
    }


def _payload(*entries: dict[str, Any]) -> bytes:
    return json.dumps(list(entries)).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_hashid_json(b"", b"", tmp_path, "hashid") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "hashid.json"
    canonical.write_bytes(_payload(_entry(hash_value=_RAW_MD5)))
    decoy = _payload(_entry(hash_value=_RAW_SHA1))
    findings = parse_hashid_json(decoy, b"", tmp_path, "hashid")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert stable_hash_12(_RAW_MD5) in sidecar
    assert stable_hash_12(_RAW_SHA1) not in sidecar


def test_finding_category_and_cwe(tmp_path: Path) -> None:
    findings = parse_hashid_json(_payload(_entry()), b"", tmp_path, "hashid")
    assert findings[0].category is FindingCategory.CRYPTO
    assert 326 in findings[0].cwe
    assert findings[0].confidence is ConfidenceLevel.LIKELY
    assert findings[0].cvss_v3_score == pytest.approx(0.0)


def test_raw_hash_never_in_sidecar(tmp_path: Path) -> None:
    """CRITICAL — raw hash hex bytes MUST NOT appear in the sidecar."""
    parse_hashid_json(_payload(_entry()), b"", tmp_path, "hashid")
    sidecar_bytes = (tmp_path / EVIDENCE_SIDECAR_NAME).read_bytes()
    assert _RAW_MD5.encode("utf-8") not in sidecar_bytes
    assert not _HEX32_RE.search(sidecar_bytes), (
        "raw 32-char hex hash leaked into hashid sidecar"
    )


def test_raw_sha1_never_in_sidecar(tmp_path: Path) -> None:
    """CRITICAL — raw SHA-1 hex bytes MUST NOT appear in the sidecar."""
    parse_hashid_json(
        _payload(
            _entry(
                hash_value=_RAW_SHA1,
                modes=[{"name": "SHA-1", "hashcat": 100, "john": "raw-sha1"}],
            )
        ),
        b"",
        tmp_path,
        "hashid",
    )
    sidecar_bytes = (tmp_path / EVIDENCE_SIDECAR_NAME).read_bytes()
    assert _RAW_SHA1.encode("utf-8") not in sidecar_bytes
    assert _RAW_SHA1.lower().encode("utf-8") not in sidecar_bytes
    assert not _HEX40_RE.search(sidecar_bytes), (
        "raw SHA-1 hex hash leaked into hashid sidecar"
    )


def test_stable_hash_12_used_for_id(tmp_path: Path) -> None:
    parse_hashid_json(_payload(_entry()), b"", tmp_path, "hashid")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["hash_id"] == stable_hash_12(_RAW_MD5)
    assert len(blob["hash_id"]) == 12


def test_preferred_mode_promoted_for_ntlm(tmp_path: Path) -> None:
    payload = _payload(
        _entry(
            modes=[
                {"name": "MD4", "hashcat": 900, "john": "raw-md4"},
                {"name": "NTLM", "hashcat": 1000, "john": "nt"},
            ]
        )
    )
    parse_hashid_json(payload, b"", tmp_path, "hashid")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["preferred_mode"] == "NTLM"
    assert blob["preferred_hashcat_id"] == 1000


def test_preferred_mode_falls_back_to_first(tmp_path: Path) -> None:
    payload = _payload(
        _entry(
            modes=[
                {"name": "MD5", "hashcat": 0, "john": "raw-md5"},
                {"name": "MD4", "hashcat": 900, "john": "raw-md4"},
            ]
        )
    )
    parse_hashid_json(payload, b"", tmp_path, "hashid")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["preferred_mode"] == "MD5"


def test_dedup_collapses_same_hash_id_and_mode(tmp_path: Path) -> None:
    payload = _payload(_entry(), _entry())
    findings = parse_hashid_json(payload, b"", tmp_path, "hashid")
    assert len(findings) == 1


def test_no_modes_dropped_silently(tmp_path: Path) -> None:
    payload = _payload(_entry(modes=[]), _entry())
    findings = parse_hashid_json(payload, b"", tmp_path, "hashid")
    assert len(findings) == 1


def test_payload_not_array_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    canonical = tmp_path / "hashid.json"
    canonical.write_bytes(b'{"hash": "x"}')
    with caplog.at_level("WARNING"):
        findings = parse_hashid_json(b"", b"", tmp_path, "hashid")
    assert findings == []
    assert any(
        "hashid_parser_payload_not_array" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_hash_length_persisted(tmp_path: Path) -> None:
    parse_hashid_json(_payload(_entry()), b"", tmp_path, "hashid")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["hash_length"] == 32


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(hashid_module, "_MAX_FINDINGS", 2)
    payload = _payload(
        *(
            _entry(hash_value=f"{i:032x}", modes=[{"name": f"M{i}", "hashcat": i}])
            for i in range(5)
        )
    )
    with caplog.at_level("WARNING"):
        findings = parse_hashid_json(payload, b"", tmp_path, "hashid")
    assert len(findings) == 2
    assert any(
        "hashid_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )
