"""Unit tests for :mod:`src.sandbox.parsers.openapi_scanner_parser` (Backlog/dev1_md §4.14 — ARG-029).

Pinned contracts:

* Canonical artefact ``openapi.json`` overrides stdout.
* ``findings[]`` envelope is preferred over ``endpoints[]``; once
  vulnerabilities are emitted, endpoint discovery is suppressed to
  avoid double-counting.
* Severity → CVSS map: critical 9.5 / high 7.5 / medium 5.0 / low 3.0.
* Vulnerabilities → :class:`ConfidenceLevel.LIKELY`; endpoints →
  :class:`ConfidenceLevel.CONFIRMED` with severity ``info``.
* Category routing follows ``_CATEGORY_HINT`` (idor → IDOR / CWE-639,
  jwt → JWT / CWE-345, ssrf → SSRF / CWE-918, etc.).
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
from src.sandbox.parsers import openapi_scanner_parser as openapi_module
from src.sandbox.parsers.openapi_scanner_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_openapi_scanner_json,
)


def _vuln(
    *,
    finding_id: str = "OAS-BOLA-001",
    severity: str = "high",
    category: str = "idor",
    endpoint: str = "POST /v1/users/{userId}/transfer",
    title: str = "Possible BOLA on transfer endpoint",
    description: str = "Path parameter not validated",
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "category": category,
        "endpoint": endpoint,
        "title": title,
        "description": description,
    }


def _endpoint(
    *,
    method: str = "GET",
    path: str = "/v1/users",
    operation_id: str = "listUsers",
    auth: str = "bearer",
) -> dict[str, Any]:
    return {
        "method": method,
        "path": path,
        "operationId": operation_id,
        "auth": auth,
        "responses": ["200", "401"],
    }


def _payload(
    *,
    findings: list[dict[str, Any]] | None = None,
    endpoints: list[dict[str, Any]] | None = None,
) -> bytes:
    document: dict[str, Any] = {
        "schema_version": "openapi-3.0.1",
        "target": "https://api.example.com",
        "auth_schemes": ["bearer", "apiKey"],
    }
    if findings is not None:
        document["findings"] = findings
    if endpoints is not None:
        document["endpoints"] = endpoints
    return json.dumps(document).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_openapi_scanner_json(b"", b"", tmp_path, "openapi_scanner") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "openapi.json"
    canonical.write_bytes(_payload(findings=[_vuln(finding_id="canonical_id")]))
    decoy = _payload(findings=[_vuln(finding_id="decoy_id")])
    findings = parse_openapi_scanner_json(decoy, b"", tmp_path, "openapi_scanner")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "canonical_id" in sidecar
    assert "decoy_id" not in sidecar


def test_vulnerability_findings_have_likely_confidence(tmp_path: Path) -> None:
    findings = parse_openapi_scanner_json(
        _payload(findings=[_vuln()]), b"", tmp_path, "openapi_scanner"
    )
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_idor_category_maps_to_idor_with_cwe_639(tmp_path: Path) -> None:
    findings = parse_openapi_scanner_json(
        _payload(findings=[_vuln(category="idor")]),
        b"",
        tmp_path,
        "openapi_scanner",
    )
    assert findings[0].category is FindingCategory.IDOR
    assert 639 in findings[0].cwe


def test_jwt_category_maps_to_jwt_with_cwe_345(tmp_path: Path) -> None:
    findings = parse_openapi_scanner_json(
        _payload(findings=[_vuln(category="jwt", finding_id="jwt-1")]),
        b"",
        tmp_path,
        "openapi_scanner",
    )
    assert findings[0].category is FindingCategory.JWT
    assert 345 in findings[0].cwe


def test_ssrf_category_maps_to_ssrf_with_cwe_918(tmp_path: Path) -> None:
    findings = parse_openapi_scanner_json(
        _payload(findings=[_vuln(category="ssrf", finding_id="ssrf-1")]),
        b"",
        tmp_path,
        "openapi_scanner",
    )
    assert findings[0].category is FindingCategory.SSRF
    assert 918 in findings[0].cwe


def test_unknown_category_defaults_to_misconfig(tmp_path: Path) -> None:
    findings = parse_openapi_scanner_json(
        _payload(findings=[_vuln(category="weirdo")]),
        b"",
        tmp_path,
        "openapi_scanner",
    )
    assert findings[0].category is FindingCategory.MISCONFIG


def test_severity_to_cvss_mapping(tmp_path: Path) -> None:
    payload = _payload(
        findings=[
            _vuln(severity="critical", finding_id="c1"),
            _vuln(severity="high", finding_id="c2"),
            _vuln(severity="medium", finding_id="c3"),
            _vuln(severity="low", finding_id="c4"),
        ]
    )
    findings = parse_openapi_scanner_json(payload, b"", tmp_path, "openapi_scanner")
    scores = sorted(f.cvss_v3_score for f in findings)
    assert scores == pytest.approx([3.0, 5.0, 7.5, 9.5])


def test_findings_take_priority_over_endpoints(tmp_path: Path) -> None:
    payload = _payload(
        findings=[_vuln()],
        endpoints=[_endpoint(), _endpoint(path="/v1/posts")],
    )
    findings = parse_openapi_scanner_json(payload, b"", tmp_path, "openapi_scanner")
    assert len(findings) == 1
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_endpoint_fallback_emits_info_findings(tmp_path: Path) -> None:
    payload = _payload(
        endpoints=[
            _endpoint(method="GET", path="/v1/users"),
            _endpoint(method="POST", path="/v1/users"),
        ]
    )
    findings = parse_openapi_scanner_json(payload, b"", tmp_path, "openapi_scanner")
    assert len(findings) == 2
    assert all(f.category is FindingCategory.INFO for f in findings)
    assert all(f.confidence is ConfidenceLevel.CONFIRMED for f in findings)
    assert all(f.cvss_v3_score == pytest.approx(0.0) for f in findings)


def test_finding_missing_id_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    bogus = _vuln()
    bogus.pop("id")
    payload = _payload(findings=[bogus, _vuln(finding_id="ok")])
    with caplog.at_level("WARNING"):
        findings = parse_openapi_scanner_json(payload, b"", tmp_path, "openapi_scanner")
    assert len(findings) == 1
    assert any(
        "openapi_scanner_parser_finding_missing_id"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_envelope_not_object_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    canonical = tmp_path / "openapi.json"
    canonical.write_bytes(b'["unexpected"]')
    with caplog.at_level("WARNING"):
        findings = parse_openapi_scanner_json(b"", b"", tmp_path, "openapi_scanner")
    assert findings == []
    assert any(
        "openapi_scanner_parser_envelope_not_object"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_dedup_collapses_same_finding_id(tmp_path: Path) -> None:
    payload = _payload(findings=[_vuln(), _vuln()])
    findings = parse_openapi_scanner_json(payload, b"", tmp_path, "openapi_scanner")
    assert len(findings) == 1


def test_findings_sorted_by_severity_descending(tmp_path: Path) -> None:
    payload = _payload(
        findings=[
            _vuln(severity="low", finding_id="c1"),
            _vuln(severity="critical", finding_id="c2"),
            _vuln(severity="high", finding_id="c3"),
        ]
    )
    findings = parse_openapi_scanner_json(payload, b"", tmp_path, "openapi_scanner")
    scores = [f.cvss_v3_score for f in findings]
    assert scores == sorted(scores, reverse=True)


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(openapi_module, "_MAX_FINDINGS", 2)
    payload = _payload(findings=[_vuln(finding_id=f"id-{i}") for i in range(5)])
    with caplog.at_level("WARNING"):
        findings = parse_openapi_scanner_json(payload, b"", tmp_path, "openapi_scanner")
    assert len(findings) == 2
    assert any(
        "openapi_scanner_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )
