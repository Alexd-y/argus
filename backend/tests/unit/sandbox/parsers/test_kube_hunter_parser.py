"""Unit tests for :mod:`src.sandbox.parsers.kube_hunter_parser` (Backlog/dev1_md §4.15 — ARG-018 / F-M03).

Pinned contracts:

* Resolves ``artifacts_dir/kubehunter.json`` (or ``kube_hunter.json``)
  before falling back to ``stdout``.
* Only the top-level ``vulnerabilities[]`` array yields findings;
  ``nodes`` / ``services`` are attack-surface context.
* Category — kube-hunter's ``category`` string drives the FindingCategory
  mapping; unknown categories fall back to ``MISCONFIG``.
* Severity → CVSS — ``high`` → 8.5, ``medium`` → 5.5, ``low`` → 3.5.
* Confidence — every kube-hunter hit → ``LIKELY``.
* Dedup — composite ``(vid, location)``.
* Fail-soft on malformed JSON / non-dict envelope / missing title.
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
from src.sandbox.parsers.kube_hunter_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_kube_hunter_json,
)


def _vuln(
    *,
    vid: str = "KHV005",
    location: str = "10.0.0.5:10250",
    category: str = "Information Disclosure",
    severity: str = "medium",
    vulnerability: str = "Access to pod's secrets",
    description: str = "Accessing the pods secrets within a compromised pod.",
    evidence: str = "count: 3",
    hunter: str = "Kubelet Secure Ports Hunter",
    avd_reference: str = "avd.aquasec.com/misconfig/khv005",
) -> dict[str, Any]:
    return {
        "location": location,
        "vid": vid,
        "category": category,
        "severity": severity,
        "vulnerability": vulnerability,
        "description": description,
        "evidence": evidence,
        "avd_reference": avd_reference,
        "hunter": hunter,
    }


def _payload(
    *vulns: dict[str, Any],
    services: list[dict[str, Any]] | None = None,
    nodes: list[dict[str, Any]] | None = None,
) -> bytes:
    envelope: dict[str, Any] = {
        "nodes": nodes if nodes is not None else [],
        "services": services if services is not None else [],
        "vulnerabilities": list(vulns),
    }
    return json.dumps(envelope).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_kube_hunter_json(b"", b"", tmp_path, "kube_hunter") == []


def test_canonical_kubehunter_file_is_preferred(tmp_path: Path) -> None:
    (tmp_path / "kubehunter.json").write_bytes(_payload(_vuln(vid="KHV001")))
    decoy = _payload(_vuln(vid="IGNORED"))
    findings = parse_kube_hunter_json(decoy, b"", tmp_path, "kube_hunter")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "KHV001" in sidecar
    assert "IGNORED" not in sidecar


def test_underscored_filename_also_recognised(tmp_path: Path) -> None:
    (tmp_path / "kube_hunter.json").write_bytes(_payload(_vuln(vid="KHV042")))
    findings = parse_kube_hunter_json(b"", b"", tmp_path, "kube_hunter")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "KHV042" in sidecar


def test_only_vulnerabilities_yield_findings(tmp_path: Path) -> None:
    payload = _payload(
        _vuln(),
        services=[{"service": "Kubelet API", "location": "10.0.0.5:10250"}],
        nodes=[{"type": "Node/Master", "location": "10.0.0.5"}],
    )
    findings = parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    assert len(findings) == 1


def test_category_mapping_rce(tmp_path: Path) -> None:
    payload = _payload(_vuln(category="Remote Code Execution", severity="high"))
    findings = parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    assert findings[0].category is FindingCategory.RCE


def test_category_mapping_info(tmp_path: Path) -> None:
    payload = _payload(_vuln(category="Information Disclosure"))
    findings = parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    assert findings[0].category is FindingCategory.INFO


def test_category_mapping_auth(tmp_path: Path) -> None:
    payload = _payload(_vuln(category="Access Risk"))
    findings = parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    assert findings[0].category is FindingCategory.AUTH


def test_unknown_category_falls_back_to_misconfig(tmp_path: Path) -> None:
    payload = _payload(_vuln(category="Something Novel"))
    findings = parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    assert findings[0].category is FindingCategory.MISCONFIG


def test_high_severity_maps_to_high_cvss(tmp_path: Path) -> None:
    payload = _payload(_vuln(severity="high"))
    findings = parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    assert findings[0].cvss_v3_score == 8.5


def test_medium_severity_maps_to_medium_cvss(tmp_path: Path) -> None:
    payload = _payload(_vuln(severity="medium"))
    findings = parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    assert findings[0].cvss_v3_score == 5.5


def test_low_severity_maps_to_low_cvss(tmp_path: Path) -> None:
    payload = _payload(_vuln(severity="low"))
    findings = parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    assert findings[0].cvss_v3_score == 3.5


def test_unknown_severity_defaults_to_medium(tmp_path: Path) -> None:
    payload = _payload(_vuln(severity="apocalyptic"))
    findings = parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    assert findings[0].cvss_v3_score == 5.5


def test_findings_get_likely_confidence(tmp_path: Path) -> None:
    payload = _payload(_vuln())
    findings = parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_dedup_uses_vid_and_location(tmp_path: Path) -> None:
    payload = _payload(
        _vuln(vid="KHV005", location="10.0.0.5:10250"),
        _vuln(vid="KHV005", location="10.0.0.5:10250"),
    )
    findings = parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    assert len(findings) == 1


def test_same_vid_different_location_kept_separate(tmp_path: Path) -> None:
    payload = _payload(
        _vuln(vid="KHV005", location="10.0.0.5:10250"),
        _vuln(vid="KHV005", location="10.0.0.6:10250"),
    )
    findings = parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    assert len(findings) == 2


def test_service_name_folded_into_evidence(tmp_path: Path) -> None:
    payload = _payload(
        _vuln(location="10.0.0.5:10250"),
        services=[{"service": "Kubelet API", "location": "10.0.0.5:10250"}],
    )
    parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["service"] == "Kubelet API"


def test_missing_title_emits_warning_and_is_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    bad = _vuln(vid="KHV999")
    bad.pop("vulnerability")
    payload = _payload(bad, _vuln(vid="KHV005"))
    with caplog.at_level(logging.WARNING):
        findings = parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    assert len(findings) == 1
    assert any(
        "kube_hunter_parser_vuln_missing_title" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_envelope_not_dict_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        findings = parse_kube_hunter_json(b"[]", b"", tmp_path, "kube_hunter")
    assert findings == []
    assert any(
        "kube_hunter_parser_envelope_not_dict" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_malformed_json_returns_empty(tmp_path: Path) -> None:
    assert parse_kube_hunter_json(b"not-json", b"", tmp_path, "kube_hunter") == []


def test_no_vulnerabilities_key_returns_empty(tmp_path: Path) -> None:
    payload = json.dumps({"nodes": [], "services": []}).encode("utf-8")
    assert parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter") == []


def test_evidence_sidecar_includes_tool_id_kind_and_category_raw(tmp_path: Path) -> None:
    payload = _payload(_vuln(vid="KHV050", category="Remote Code Execution"))
    parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter-mng")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["tool_id"] == "kube_hunter-mng"
    assert blob["kind"] == "kube_hunter"
    assert blob["vid"] == "KHV050"
    assert blob["category"] == FindingCategory.RCE.value
    assert blob["category_raw"] == "Remote Code Execution"


def test_findings_sorted_severity_desc(tmp_path: Path) -> None:
    payload = _payload(
        _vuln(vid="KHV-LOW", severity="low", location="a"),
        _vuln(vid="KHV-HIGH", severity="high", location="b"),
        _vuln(vid="KHV-MED", severity="medium", location="c"),
    )
    parse_kube_hunter_json(payload, b"", tmp_path, "kube_hunter")
    rows = [
        json.loads(line)
        for line in (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    ]
    assert [r["severity"] for r in rows] == ["high", "medium", "low"]
