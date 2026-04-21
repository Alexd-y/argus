"""Unit tests for :mod:`src.sandbox.parsers.hash_analyzer_parser` (Backlog §4.13 — ARG-029).

CRITICAL — raw hash bytes are NEVER persisted in the sidecar.

Pinned contracts:

* Canonical artefact ``hash_analyzer.json`` overrides stdout.
* Both top-level array and ``{"results": [...]}`` envelopes are
  supported; single object with ``input`` is also accepted.
* Each input → INFO finding with category
  :class:`FindingCategory.CRYPTO` and CWE [326, 327].
* The match with the highest ``confidence`` (lower hashcat id on ties)
  becomes the preferred mode.
* Confidence escalates from ``LIKELY`` to ``CONFIRMED`` when the
  preferred score is ``>= 0.95``.
* Sidecar persists ``stable_hash_12`` (NEVER cleartext) plus length /
  entropy / matches.
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
from src.sandbox.parsers import hash_analyzer_parser as hash_module
from src.sandbox.parsers._base import stable_hash_12
from src.sandbox.parsers.hash_analyzer_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_hash_analyzer_json,
)

_RAW_BCRYPT = "$2b$12$KIXQR9LkqxgYQEm9HhPcAOmSYsZ4bP3HCBpYzU0t6/yUlF1u4FmKa"
_RAW_MD5 = "5f4dcc3b5aa765d61d8327deb882cf99"
_HEX32_RE = re.compile(rb"\b[0-9a-fA-F]{32}\b")
_BCRYPT_RE = re.compile(rb"\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}")


def _entry(
    *,
    hash_value: str = _RAW_MD5,
    matches: list[dict[str, Any]] | None = None,
    entropy: float | None = 4.0,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "input": hash_value,
        "matches": matches
        or [
            {"name": "MD5", "confidence": 0.92, "hashcat": 0, "john": "raw-md5"},
        ],
    }
    if entropy is not None:
        record["entropy"] = entropy
    return record


def _payload_array(*entries: dict[str, Any]) -> bytes:
    return json.dumps(list(entries)).encode("utf-8")


def _payload_results(*entries: dict[str, Any]) -> bytes:
    return json.dumps({"results": list(entries)}).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_hash_analyzer_json(b"", b"", tmp_path, "hash_analyzer") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "hash_analyzer.json"
    canonical.write_bytes(_payload_array(_entry(hash_value=_RAW_MD5)))
    decoy = _payload_array(
        _entry(
            hash_value=_RAW_BCRYPT,
            matches=[{"name": "bcrypt", "confidence": 0.99, "hashcat": 3200}],
        )
    )
    findings = parse_hash_analyzer_json(decoy, b"", tmp_path, "hash_analyzer")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert stable_hash_12(_RAW_MD5) in sidecar
    assert stable_hash_12(_RAW_BCRYPT) not in sidecar


def test_finding_category_and_cwe(tmp_path: Path) -> None:
    findings = parse_hash_analyzer_json(
        _payload_array(_entry()), b"", tmp_path, "hash_analyzer"
    )
    assert findings[0].category is FindingCategory.CRYPTO
    assert set(findings[0].cwe) == {326, 327}


def test_results_envelope_supported(tmp_path: Path) -> None:
    findings = parse_hash_analyzer_json(
        _payload_results(_entry()), b"", tmp_path, "hash_analyzer"
    )
    assert len(findings) == 1


def test_high_confidence_promotes_to_confirmed(tmp_path: Path) -> None:
    findings = parse_hash_analyzer_json(
        _payload_array(
            _entry(matches=[{"name": "bcrypt", "confidence": 0.99, "hashcat": 3200}])
        ),
        b"",
        tmp_path,
        "hash_analyzer",
    )
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


def test_low_confidence_stays_likely(tmp_path: Path) -> None:
    findings = parse_hash_analyzer_json(
        _payload_array(
            _entry(matches=[{"name": "MD5", "confidence": 0.7, "hashcat": 0}])
        ),
        b"",
        tmp_path,
        "hash_analyzer",
    )
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_preferred_mode_picks_highest_confidence(tmp_path: Path) -> None:
    parse_hash_analyzer_json(
        _payload_array(
            _entry(
                matches=[
                    {"name": "MD5", "confidence": 0.7, "hashcat": 0},
                    {"name": "MD4", "confidence": 0.95, "hashcat": 900},
                ]
            )
        ),
        b"",
        tmp_path,
        "hash_analyzer",
    )
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["preferred_mode"] == "MD4"


def test_raw_hash_never_in_sidecar(tmp_path: Path) -> None:
    """CRITICAL — raw hex hash bytes MUST NOT appear in the sidecar."""
    parse_hash_analyzer_json(_payload_array(_entry()), b"", tmp_path, "hash_analyzer")
    sidecar_bytes = (tmp_path / EVIDENCE_SIDECAR_NAME).read_bytes()
    assert _RAW_MD5.encode("utf-8") not in sidecar_bytes
    assert not _HEX32_RE.search(sidecar_bytes), (
        "raw MD5 hex hash leaked into hash_analyzer sidecar"
    )


def test_raw_bcrypt_never_in_sidecar(tmp_path: Path) -> None:
    """CRITICAL — raw bcrypt hash bytes MUST NOT appear in the sidecar."""
    parse_hash_analyzer_json(
        _payload_array(
            _entry(
                hash_value=_RAW_BCRYPT,
                matches=[{"name": "bcrypt", "confidence": 0.99, "hashcat": 3200}],
            )
        ),
        b"",
        tmp_path,
        "hash_analyzer",
    )
    sidecar_bytes = (tmp_path / EVIDENCE_SIDECAR_NAME).read_bytes()
    assert _RAW_BCRYPT.encode("utf-8") not in sidecar_bytes
    assert not _BCRYPT_RE.search(sidecar_bytes), (
        "raw bcrypt hash leaked into hash_analyzer sidecar"
    )


def test_stable_hash_12_used_for_id(tmp_path: Path) -> None:
    parse_hash_analyzer_json(_payload_array(_entry()), b"", tmp_path, "hash_analyzer")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["hash_id"] == stable_hash_12(_RAW_MD5)


def test_dedup_collapses_same_hash_id_and_mode(tmp_path: Path) -> None:
    payload = _payload_array(_entry(), _entry())
    findings = parse_hash_analyzer_json(payload, b"", tmp_path, "hash_analyzer")
    assert len(findings) == 1


def test_no_matches_dropped(tmp_path: Path) -> None:
    payload = _payload_array(_entry(matches=[]), _entry())
    findings = parse_hash_analyzer_json(payload, b"", tmp_path, "hash_analyzer")
    assert len(findings) == 1


def test_unsupported_payload_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    canonical = tmp_path / "hash_analyzer.json"
    canonical.write_bytes(b'"a string is not an envelope"')
    with caplog.at_level("WARNING"):
        findings = parse_hash_analyzer_json(b"", b"", tmp_path, "hash_analyzer")
    assert findings == []
    assert any(
        "hash_analyzer_parser_unsupported_payload"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_entropy_persisted(tmp_path: Path) -> None:
    parse_hash_analyzer_json(
        _payload_array(_entry(entropy=3.7)), b"", tmp_path, "hash_analyzer"
    )
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["entropy"] == pytest.approx(3.7)


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(hash_module, "_MAX_FINDINGS", 2)
    payload = _payload_array(*(_entry(hash_value=f"{i:032x}") for i in range(5)))
    with caplog.at_level("WARNING"):
        findings = parse_hash_analyzer_json(payload, b"", tmp_path, "hash_analyzer")
    assert len(findings) == 2
    assert any(
        "hash_analyzer_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )
