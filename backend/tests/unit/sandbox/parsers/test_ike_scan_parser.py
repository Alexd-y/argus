"""Unit tests for :mod:`src.sandbox.parsers.ike_scan_parser` (§4.17).

Pinned contracts:

* A handshake response yields one INFO finding (endpoint discovered).
* Aggressive-mode responses add one MISCONFIG finding (PSK exposure).
* SA transform is captured in the sidecar; empty / garbage → ``[]``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.ike_scan_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_ike_scan,
)

_AGGRESSIVE_OUTPUT = (
    "Starting ike-scan 1.9.4 with 1 hosts\n"
    "192.0.2.1\tAggressive Mode Handshake returned "
    "HDR=(CKY-R=1a2b3c4d) "
    "SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK "
    "LifeType=Seconds LifeDuration=28800)\n"
    "Ending ike-scan 1.9.4: 1 hosts scanned in 0.512 seconds\n"
)

_MAIN_MODE_OUTPUT = (
    "192.0.2.2\tMain Mode Handshake returned "
    "HDR=(CKY-R=9f8e) "
    "SA=(Enc=AES KeyLength=256 Hash=SHA2-256 Group=14:modp2048 Auth=PSK)\n"
)


def test_empty_returns_no_findings(tmp_path: Path) -> None:
    assert parse_ike_scan(b"", b"", tmp_path, "ike_scan") == []


def test_aggressive_mode_emits_info_plus_misconfig(tmp_path: Path) -> None:
    findings = parse_ike_scan(_AGGRESSIVE_OUTPUT.encode("utf-8"), b"", tmp_path, "ike_scan")
    assert len(findings) == 2
    categories = {f.category for f in findings}
    assert categories == {FindingCategory.INFO, FindingCategory.MISCONFIG}
    misconfig = next(f for f in findings if f.category is FindingCategory.MISCONFIG)
    assert 522 in misconfig.cwe
    assert misconfig.confidence is ConfidenceLevel.LIKELY


def test_main_mode_emits_only_info(tmp_path: Path) -> None:
    findings = parse_ike_scan(_MAIN_MODE_OUTPUT.encode("utf-8"), b"", tmp_path, "ike_scan")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO
    assert 200 in findings[0].cwe
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


def test_sa_transform_captured_in_sidecar(tmp_path: Path) -> None:
    parse_ike_scan(_AGGRESSIVE_OUTPUT.encode("utf-8"), b"", tmp_path, "ike_scan")
    lines = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    records = [json.loads(line) for line in lines if line.strip()]
    assert all(rec["tool_id"] == "ike_scan" for rec in records)
    assert any("Enc=3DES" in (rec.get("sa_transform") or "") for rec in records)


def test_dedup_same_host(tmp_path: Path) -> None:
    payload = (_MAIN_MODE_OUTPUT + _MAIN_MODE_OUTPUT).encode("utf-8")
    findings = parse_ike_scan(payload, b"", tmp_path, "ike_scan")
    assert len(findings) == 1


def test_garbage_returns_no_findings(tmp_path: Path) -> None:
    assert parse_ike_scan(b"no handshake here\n", b"", tmp_path, "ike_scan") == []
