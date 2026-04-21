"""Unit tests for :mod:`src.sandbox.parsers.chrome_csp_probe_parser` (ARG-032).

Pinned contracts:

* Empty payload ⇒ ``[]``.
* CSP violations emit MISCONFIG findings (CWE-693).
* ``unsafe-inline`` / ``unsafe-eval`` / wildcard sources escalate to
  CVSS 7.5; other violations stay at CVSS 5.3.
* Missing critical CSP headers emit MISCONFIG findings.
* Dedup on ``(directive, value, where)``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers.chrome_csp_probe_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_chrome_csp_probe,
)


def _payload(violations=None, missing=None) -> bytes:
    body: dict[str, object] = {"url": "https://example.com/"}
    if violations is not None:
        body["violations"] = violations
    if missing is not None:
        body["missing"] = missing
    return json.dumps(body).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_chrome_csp_probe(b"", b"", tmp_path, "chrome_csp_probe") == []


def test_unsafe_inline_escalates_to_high(tmp_path: Path) -> None:
    payload = _payload(
        violations=[
            {"directive": "script-src", "value": "'unsafe-inline'", "where": "header"}
        ]
    )
    findings = parse_chrome_csp_probe(payload, b"", tmp_path, "chrome_csp_probe")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.MISCONFIG
    assert findings[0].cvss_v3_score == 7.5


def test_safe_directive_uses_medium(tmp_path: Path) -> None:
    payload = _payload(
        violations=[{"directive": "script-src", "value": "'self'", "where": "header"}]
    )
    findings = parse_chrome_csp_probe(payload, b"", tmp_path, "chrome_csp_probe")
    assert len(findings) == 1
    assert findings[0].cvss_v3_score == 5.3


def test_missing_critical_header_emits_high(tmp_path: Path) -> None:
    payload = _payload(missing=["Content-Security-Policy"])
    findings = parse_chrome_csp_probe(payload, b"", tmp_path, "chrome_csp_probe")
    assert len(findings) == 1
    assert findings[0].cvss_v3_score == 7.5


def test_dedup_on_directive_value_where(tmp_path: Path) -> None:
    payload = _payload(
        violations=[
            {"directive": "script-src", "value": "'self'", "where": "header"},
            {"directive": "script-src", "value": "'self'", "where": "header"},
        ]
    )
    assert len(parse_chrome_csp_probe(payload, b"", tmp_path, "chrome_csp_probe")) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = _payload(
        violations=[{"directive": "x", "value": "'self'", "where": "header"}]
    )
    (tmp_path / "csp.json").write_bytes(canonical)
    decoy = _payload(violations=[{"directive": "y", "value": "'self'", "where": "dom"}])
    parse_chrome_csp_probe(decoy, b"", tmp_path, "chrome_csp_probe")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert '"directive": "x"' in sidecar
    assert '"directive": "y"' not in sidecar


def test_sidecar_records_severity(tmp_path: Path) -> None:
    payload = _payload(
        violations=[{"directive": "script-src", "value": "*", "where": "header"}]
    )
    parse_chrome_csp_probe(payload, b"", tmp_path, "chrome_csp_probe")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["severity"] == "high"
