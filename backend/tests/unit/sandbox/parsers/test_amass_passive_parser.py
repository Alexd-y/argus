"""Unit tests for :mod:`src.sandbox.parsers.amass_passive_parser` (ARG-032).

Pinned contracts:

* Empty stdout ⇒ ``[]``.
* JSONL records yield one INFO finding per unique hostname.
* ``addresses`` and ``sources`` are normalised + sorted.
* Hostnames are lowercased + RFC-1035 validated (noise rejected).
* Canonical artifact ``amass.jsonl`` overrides stdout.
* Sidecar JSONL stamped with ``tool_id``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers.amass_passive_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_amass_passive,
)


def _record_line(name: str, sources: list[str] | None = None) -> bytes:
    payload = {
        "name": name,
        "domain": "example.com",
        "tag": "cert",
        "sources": sources or ["crt.sh"],
        "addresses": [{"ip": "1.2.3.4", "cidr": "1.2.3.0/24"}],
    }
    return (json.dumps(payload) + "\n").encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_amass_passive(b"", b"", tmp_path, "amass_passive") == []


def test_one_finding_per_unique_hostname(tmp_path: Path) -> None:
    stdout = _record_line("api.example.com") + _record_line("cdn.example.com")
    findings = parse_amass_passive(stdout, b"", tmp_path, "amass_passive")
    assert len(findings) == 2
    assert all(f.category is FindingCategory.INFO for f in findings)


def test_dedup_collapses_duplicate_hostnames(tmp_path: Path) -> None:
    stdout = _record_line("api.example.com") + _record_line("API.EXAMPLE.COM")
    assert len(parse_amass_passive(stdout, b"", tmp_path, "amass_passive")) == 1


def test_invalid_hostnames_rejected(tmp_path: Path) -> None:
    stdout = _record_line("not_a_host") + _record_line("api.example.com")
    findings = parse_amass_passive(stdout, b"", tmp_path, "amass_passive")
    assert len(findings) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "amass.jsonl").write_bytes(_record_line("canonical.example.com"))
    findings = parse_amass_passive(
        _record_line("decoy.example.com"), b"", tmp_path, "amass_passive"
    )
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical.example.com" in sidecar


def test_sidecar_normalises_addresses_and_sources(tmp_path: Path) -> None:
    parse_amass_passive(
        _record_line("api.example.com", ["B", "A", "B"]),
        b"",
        tmp_path,
        "amass_passive",
    )
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["sources"] == ["A", "B"]
    assert record["addresses"] == ["1.2.3.4"]
    assert record["tool_id"] == "amass_passive"


def test_records_without_name_are_skipped(tmp_path: Path) -> None:
    stdout = b'{"domain": "example.com"}\n' + _record_line("api.example.com")
    findings = parse_amass_passive(stdout, b"", tmp_path, "amass_passive")
    assert len(findings) == 1
