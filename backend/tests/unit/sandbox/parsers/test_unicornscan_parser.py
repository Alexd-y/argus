"""Unit tests for :mod:`src.sandbox.parsers.unicornscan_parser` (ARG-032).

Pinned contracts:

* Empty stdout ⇒ ``[]``.
* One INFO finding per ``(host, port, proto)`` tuple.
* Both TCP and UDP open lines parsed.
* Invalid / closed lines silently dropped.
* Dedup on ``(host, port, proto)``.
* Canonical artifact ``unicornscan.txt`` overrides stdout.
* Sidecar JSONL stamped with ``tool_id`` and 12-char ``fingerprint_hash``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.unicornscan_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_unicornscan,
)


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_unicornscan(b"", b"", tmp_path, "unicornscan") == []


def test_tcp_open_line_yields_one_finding(tmp_path: Path) -> None:
    stdout = b"TCP open                  http[   80]    from 10.0.0.1   ttl 64\n"
    findings = parse_unicornscan(stdout, b"", tmp_path, "unicornscan")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


def test_multiple_open_ports_emit_multiple_findings(tmp_path: Path) -> None:
    stdout = (
        b"TCP open                  http[   80]    from 10.0.0.1   ttl 64\n"
        b"TCP open                  https[  443]   from 10.0.0.1   ttl 64\n"
        b"UDP open                  domain[  53]   from 10.0.0.2\n"
    )
    findings = parse_unicornscan(stdout, b"", tmp_path, "unicornscan")
    assert len(findings) == 3


def test_invalid_lines_skipped(tmp_path: Path) -> None:
    stdout = (
        b"adding 10.0.0.1\n"
        b"sending probes...\n"
        b"TCP closed                 http[   80]    from 10.0.0.1   ttl 64\n"
        b"TCP open                  http[   80]    from 10.0.0.1   ttl 64\n"
    )
    findings = parse_unicornscan(stdout, b"", tmp_path, "unicornscan")
    assert len(findings) == 1


def test_dedup_on_host_port_proto(tmp_path: Path) -> None:
    stdout = (
        b"TCP open                  http[   80]    from 10.0.0.1   ttl 64\n"
        b"TCP open                  http[   80]    from 10.0.0.1   ttl 64\n"
    )
    assert len(parse_unicornscan(stdout, b"", tmp_path, "unicornscan")) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "unicornscan.txt").write_bytes(
        b"TCP open                  ssh[    22]    from 10.0.0.99  ttl 64\n"
    )
    decoy = b"TCP open                  http[   80]    from 1.1.1.1   ttl 64\n"
    findings = parse_unicornscan(decoy, b"", tmp_path, "unicornscan")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["host"] == "10.0.0.99"
    assert record["port"] == 22


def test_sidecar_records_tool_id_and_fingerprint(tmp_path: Path) -> None:
    parse_unicornscan(
        b"TCP open                  http[   80]    from 10.0.0.1   ttl 64\n",
        b"",
        tmp_path,
        "unicornscan",
    )
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["tool_id"] == "unicornscan"
    assert record["host"] == "10.0.0.1"
    assert record["port"] == 80
    assert record["proto"] == "tcp"
    assert record["service"] == "http"
    assert isinstance(record["fingerprint_hash"], str)
    assert len(record["fingerprint_hash"]) == 12


def test_invalid_port_dropped(tmp_path: Path) -> None:
    stdout = b"TCP open                  http[ 99999]    from 10.0.0.1   ttl 64\n"
    assert parse_unicornscan(stdout, b"", tmp_path, "unicornscan") == []
