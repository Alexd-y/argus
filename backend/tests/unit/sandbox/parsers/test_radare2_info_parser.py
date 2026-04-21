"""Unit tests for :mod:`src.sandbox.parsers.radare2_info_parser` (ARG-032).

CRITICAL security gate (C12 contract):
    Memory addresses (``0x[0-9a-fA-F]{8,}``) are scrubbed from every
    evidence value before sidecar persistence.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers.radare2_info_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_radare2_info,
)


def _payload() -> bytes:
    return json.dumps(
        {
            "info": {"bin": {"format": "elf64"}},
            "imports": [
                {"name": "system", "vaddr": "0x401234abcd"},
                {"name": "strcpy", "vaddr": "0x402123"},
                {"name": "printf", "vaddr": "0x403000"},
            ],
            "sections": [
                {"name": ".text", "perm": "r-x", "vaddr": "0x401000"},
                {"name": ".rwx_zone", "perm": "rwx", "vaddr": "0x402000"},
                {
                    "name": ".packed",
                    "perm": "r--",
                    "entropy": 7.95,
                    "vaddr": "0xdeadbeef12345678",
                },
            ],
        }
    ).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_radare2_info(b"", b"", tmp_path, "radare2_info") == []


def test_dangerous_imports_become_info_findings(tmp_path: Path) -> None:
    findings = parse_radare2_info(_payload(), b"", tmp_path, "radare2_info")
    info = [f for f in findings if f.category is FindingCategory.INFO]
    misconfig = [f for f in findings if f.category is FindingCategory.MISCONFIG]
    assert len(info) >= 2  # system + strcpy + entropy section
    assert len(misconfig) == 1  # rwx section


def test_rwx_section_emits_misconfig_finding(tmp_path: Path) -> None:
    findings = parse_radare2_info(_payload(), b"", tmp_path, "radare2_info")
    misconfig = [f for f in findings if f.category is FindingCategory.MISCONFIG]
    assert len(misconfig) == 1
    assert misconfig[0].cvss_v3_score == 5.0


def test_memory_addresses_redacted_in_sidecar(tmp_path: Path) -> None:
    parse_radare2_info(_payload(), b"", tmp_path, "radare2_info")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "0xdeadbeef12345678" not in sidecar
    assert "0x401234abcd" not in sidecar


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = json.dumps(
        {"imports": [{"name": "system", "vaddr": "0x123456"}]}
    ).encode()
    (tmp_path / "r2_info.json").write_bytes(canonical)
    decoy = json.dumps({"imports": [{"name": "popen", "vaddr": "0xabc"}]}).encode()
    findings = parse_radare2_info(decoy, b"", tmp_path, "radare2_info")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "system" in sidecar
    assert "popen" not in sidecar
    del findings


def test_high_entropy_section_emits_finding(tmp_path: Path) -> None:
    payload = json.dumps(
        {"sections": [{"name": ".packed", "perm": "r--", "entropy": 7.95}]}
    ).encode()
    findings = parse_radare2_info(payload, b"", tmp_path, "radare2_info")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO


def test_safe_imports_skipped(tmp_path: Path) -> None:
    payload = json.dumps({"imports": [{"name": "printf"}, {"name": "puts"}]}).encode()
    assert parse_radare2_info(payload, b"", tmp_path, "radare2_info") == []
