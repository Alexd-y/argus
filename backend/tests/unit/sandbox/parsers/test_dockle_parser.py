"""Unit tests for :mod:`src.sandbox.parsers.dockle_parser` (Backlog/dev1_md §4.15 — ARG-021).

Pinned contracts:

* Resolves ``artifacts_dir/dockle.json`` first, falls back to ``stdout``.
* ``details[]`` envelope (Dockle 0.4.x).
* Level → severity:

  - ``FATAL`` → ``high`` (LIKELY confidence),
  - ``WARN``  → ``medium`` (SUSPECTED),
  - ``INFO``  → ``info`` (SUSPECTED),
  - ``SKIP``  → dropped,
  - ``PASS``  → dropped.

* Category: every finding → ``MISCONFIG`` with CWE ``[16, 250]``.
* Dedup: composite ``(code, alert)``. Multiple alerts inside one rule
  are emitted as separate findings.
* A rule with no alerts is still emitted once (the rule itself is the
  finding).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.dockle_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_dockle_json,
)


def _detail(
    *,
    code: str = "CIS-DI-0001",
    title: str = "Create a user for the container",
    level: str = "FATAL",
    alerts: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "code": code,
        "title": title,
        "level": level,
        "alerts": alerts if alerts is not None else ["Last user should not be root"],
    }


def _payload(*details: dict[str, Any]) -> bytes:
    envelope = {
        "summary": {
            "fatal": sum(1 for d in details if d.get("level") == "FATAL"),
            "warn": sum(1 for d in details if d.get("level") == "WARN"),
            "info": sum(1 for d in details if d.get("level") == "INFO"),
            "skip": sum(1 for d in details if d.get("level") == "SKIP"),
            "pass": sum(1 for d in details if d.get("level") == "PASS"),
        },
        "details": list(details),
    }
    return json.dumps(envelope).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_dockle_json(b"", b"", tmp_path, "dockle") == []


def test_canonical_file_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "dockle.json"
    canonical.write_bytes(_payload(_detail(code="CIS-DI-0001")))
    decoy = _payload(_detail(code="CIS-DI-9999"))
    findings = parse_dockle_json(decoy, b"", tmp_path, "dockle")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "CIS-DI-0001" in sidecar


def test_fatal_level_high_likely(tmp_path: Path) -> None:
    payload = _payload(_detail(level="FATAL"))
    findings = parse_dockle_json(payload, b"", tmp_path, "dockle")
    assert findings[0].cvss_v3_score == pytest.approx(7.0)
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_warn_level_medium_suspected(tmp_path: Path) -> None:
    payload = _payload(_detail(level="WARN"))
    findings = parse_dockle_json(payload, b"", tmp_path, "dockle")
    assert findings[0].cvss_v3_score == pytest.approx(5.0)
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_info_level_info_suspected(tmp_path: Path) -> None:
    payload = _payload(_detail(level="INFO"))
    findings = parse_dockle_json(payload, b"", tmp_path, "dockle")
    assert findings[0].cvss_v3_score == pytest.approx(0.0)
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_skip_and_pass_levels_dropped(tmp_path: Path) -> None:
    payload = _payload(
        _detail(code="CIS-PASS", level="PASS"),
        _detail(code="CIS-SKIP", level="SKIP"),
        _detail(code="CIS-WARN", level="WARN"),
    )
    findings = parse_dockle_json(payload, b"", tmp_path, "dockle")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "CIS-WARN" in sidecar
    assert "CIS-PASS" not in sidecar
    assert "CIS-SKIP" not in sidecar


def test_findings_get_misconfig_category(tmp_path: Path) -> None:
    payload = _payload(_detail())
    findings = parse_dockle_json(payload, b"", tmp_path, "dockle")
    assert findings[0].category is FindingCategory.MISCONFIG
    assert findings[0].cwe == [16, 250]


def test_multiple_alerts_emit_separate_findings(tmp_path: Path) -> None:
    payload = _payload(
        _detail(
            code="CIS-DI-0001",
            alerts=["alert one", "alert two", "alert three"],
        )
    )
    findings = parse_dockle_json(payload, b"", tmp_path, "dockle")
    assert len(findings) == 3


def test_dedup_collapses_duplicate_alerts(tmp_path: Path) -> None:
    payload = _payload(
        _detail(code="CIS-DI-0001", alerts=["dup"]),
        _detail(code="CIS-DI-0001", alerts=["dup", "dup"]),
    )
    findings = parse_dockle_json(payload, b"", tmp_path, "dockle")
    assert len(findings) == 1


def test_rule_without_alerts_still_emitted(tmp_path: Path) -> None:
    payload = _payload(_detail(code="CIS-EMPTY", alerts=[]))
    findings = parse_dockle_json(payload, b"", tmp_path, "dockle")
    assert len(findings) == 1


def test_findings_sorted_severity_desc(tmp_path: Path) -> None:
    payload = _payload(
        _detail(code="CIS-A", level="INFO", alerts=["info-alert"]),
        _detail(code="CIS-B", level="FATAL", alerts=["fatal-alert"]),
        _detail(code="CIS-C", level="WARN", alerts=["warn-alert"]),
    )
    parse_dockle_json(payload, b"", tmp_path, "dockle")
    rows = [
        json.loads(line)
        for line in (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    ]
    assert [r["code"] for r in rows] == ["CIS-B", "CIS-C", "CIS-A"]


def test_envelope_not_dict_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        findings = parse_dockle_json(b"[]", b"", tmp_path, "dockle")
    assert findings == []
    assert any(
        "dockle_parser_envelope_not_dict" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_missing_code_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    bad = _detail()
    bad.pop("code")
    payload = _payload(bad, _detail(code="CIS-OK"))
    with caplog.at_level(logging.WARNING):
        findings = parse_dockle_json(payload, b"", tmp_path, "dockle")
    assert len(findings) == 1
    assert any(
        "dockle_parser_detail_missing_code" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_malformed_json_returns_empty(tmp_path: Path) -> None:
    assert parse_dockle_json(b"not-json", b"", tmp_path, "dockle") == []


def test_no_details_returns_empty(tmp_path: Path) -> None:
    payload = json.dumps({"details": []}).encode("utf-8")
    assert parse_dockle_json(payload, b"", tmp_path, "dockle") == []


def test_evidence_sidecar_includes_tool_id_and_kind(tmp_path: Path) -> None:
    payload = _payload(_detail(code="CIS-DI-0001"))
    parse_dockle_json(payload, b"", tmp_path, "dockle-img")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["tool_id"] == "dockle-img"
    assert blob["kind"] == "dockle"
    assert blob["code"] == "CIS-DI-0001"
    assert blob["level"] == "FATAL"
