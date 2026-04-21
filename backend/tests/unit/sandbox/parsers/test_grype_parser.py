"""Unit tests for :mod:`src.sandbox.parsers.grype_parser` (Backlog/dev1_md §4.15 — ARG-021).

Pinned contracts:

* Resolves ``artifacts_dir/grype.json`` first, falls back to ``stdout``.
* ``matches[]`` envelope (Grype 0.74+).
* Severity mapping (case-insensitive):

  - ``Critical`` → ``critical``,
  - ``High`` → ``high``,
  - ``Medium`` → ``medium``,
  - ``Low`` → ``low``,
  - ``Negligible`` / ``Unknown`` → ``info``.

* Confidence: every Grype hit → ``CONFIRMED``.
* Category: every finding → ``SUPPLY_CHAIN``.
* CWE: from ``relatedVulnerabilities[].cwes[]`` (e.g. ``"CWE-22"``);
  falls back to ``[1395]`` (CWE-1395 — Vulnerable Third-Party Component).
* CVSS: highest v3.x ``baseScore`` from ``vulnerability.cvss[]`` wins;
  vector preserved when it starts with ``CVSS:3.`` or ``CVSS:4.``;
  otherwise sentinel score from severity bucket.
* Dedup: composite ``(cve_id, package_name, package_version)``.
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
from src.sandbox.parsers import grype_parser as grype_module
from src.sandbox.parsers.grype_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_grype_json,
)


def _match(
    *,
    cve_id: str = "CVE-2024-12345",
    severity: str = "High",
    package_name: str = "openssl",
    package_version: str = "1.2.3-1.el9",
    package_type: str = "rpm",
    cwes: list[str] | None = None,
    cvss_entries: list[dict[str, Any]] | None = None,
    fix_versions: list[str] | None = None,
    fix_state: str = "fixed",
    description: str = "Out-of-bounds write in OpenSSL",
    purl: str = "pkg:rpm/redhat/openssl@1.2.3-1.el9",
) -> dict[str, Any]:
    cvss_block: list[dict[str, Any]]
    if cvss_entries is None:
        cvss_block = [
            {
                "version": "3.1",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "metrics": {
                    "baseScore": 9.8,
                    "exploitabilityScore": 3.9,
                    "impactScore": 5.9,
                },
            }
        ]
    else:
        cvss_block = cvss_entries
    related = []
    if cwes:
        related.append({"id": "GHSA-test", "cwes": cwes})
    return {
        "vulnerability": {
            "id": cve_id,
            "dataSource": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "namespace": "nvd:cpe",
            "severity": severity,
            "urls": [f"https://example.com/{cve_id}"],
            "description": description,
            "cvss": cvss_block,
            "fix": {"versions": fix_versions or ["1.2.4"], "state": fix_state},
        },
        "relatedVulnerabilities": related,
        "matchDetails": [
            {
                "type": "exact-direct-match",
                "matcher": "rpm-matcher",
                "searchedBy": {"distro": {"type": "rhel", "version": "9.2"}},
                "found": {"versionConstraint": "< 1.2.4 (rpm)"},
            }
        ],
        "artifact": {
            "name": package_name,
            "version": package_version,
            "type": package_type,
            "purl": purl,
            "locations": [{"path": "/var/lib/rpm/Packages"}],
        },
    }


def _payload(*matches: dict[str, Any]) -> bytes:
    envelope = {
        "matches": list(matches),
        "source": {"target": "alpine:3.18", "type": "image"},
        "distro": {"name": "alpine", "version": "3.18"},
        "descriptor": {"name": "grype", "version": "0.74.0"},
    }
    return json.dumps(envelope).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_grype_json(b"", b"", tmp_path, "grype") == []


def test_canonical_file_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "grype.json"
    canonical.write_bytes(_payload(_match(cve_id="CVE-2024-12345")))
    decoy = _payload(_match(cve_id="CVE-2099-9999"))
    findings = parse_grype_json(decoy, b"", tmp_path, "grype")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "CVE-2024-12345" in sidecar


def test_severity_critical(tmp_path: Path) -> None:
    payload = _payload(
        _match(
            severity="Critical",
            cvss_entries=[
                {
                    "version": "3.1",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "metrics": {"baseScore": 9.8},
                }
            ],
        )
    )
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cvss_v3_score == pytest.approx(9.8)


def test_severity_high(tmp_path: Path) -> None:
    payload = _payload(
        _match(
            severity="High",
            cvss_entries=[
                {
                    "version": "3.1",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "metrics": {"baseScore": 7.5},
                }
            ],
        )
    )
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cvss_v3_score == pytest.approx(7.5)


def test_severity_negligible_collapses_to_info(tmp_path: Path) -> None:
    payload = _payload(_match(severity="Negligible", cvss_entries=[]))
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cvss_v3_score == pytest.approx(0.0)


def test_severity_unknown_collapses_to_info(tmp_path: Path) -> None:
    payload = _payload(_match(severity="Unknown", cvss_entries=[]))
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cvss_v3_score == pytest.approx(0.0)


def test_findings_get_supply_chain_category_and_confirmed(tmp_path: Path) -> None:
    payload = _payload(_match())
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].category is FindingCategory.SUPPLY_CHAIN
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


def test_cwe_extracted_from_related_vulnerabilities(tmp_path: Path) -> None:
    payload = _payload(_match(cwes=["CWE-22", "CWE-79"]))
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cwe == [22, 79]


def test_cwe_falls_back_to_default_when_missing(tmp_path: Path) -> None:
    payload = _payload(_match(cwes=None))
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cwe == [1395]


def test_highest_cvss_score_wins(tmp_path: Path) -> None:
    payload = _payload(
        _match(
            cvss_entries=[
                {
                    "version": "3.0",
                    "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                    "metrics": {"baseScore": 5.5},
                },
                {
                    "version": "3.1",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "metrics": {"baseScore": 9.8},
                },
                {
                    "version": "2.0",
                    "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                    "metrics": {"baseScore": 6.0},
                },
            ]
        )
    )
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cvss_v3_score == pytest.approx(9.8)
    assert findings[0].cvss_v3_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_v2_only_falls_back_to_severity_anchor(tmp_path: Path) -> None:
    payload = _payload(
        _match(
            severity="High",
            cvss_entries=[
                {
                    "version": "2.0",
                    "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                    "metrics": {"baseScore": 7.5},
                }
            ],
        )
    )
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cvss_v3_score == pytest.approx(7.5)


def test_dedup_collapses_identical_match(tmp_path: Path) -> None:
    payload = _payload(_match(), _match())
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert len(findings) == 1


def test_same_cve_different_package_kept_separate(tmp_path: Path) -> None:
    payload = _payload(
        _match(cve_id="CVE-2024-1", package_name="glibc"),
        _match(cve_id="CVE-2024-1", package_name="zlib"),
    )
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert len(findings) == 2


def test_findings_sorted_severity_desc(tmp_path: Path) -> None:
    payload = _payload(
        _match(
            cve_id="CVE-2024-1001",
            severity="Low",
            cvss_entries=[
                {
                    "version": "3.1",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                    "metrics": {"baseScore": 3.0},
                }
            ],
            package_name="pkg-low",
        ),
        _match(
            cve_id="CVE-2024-9999",
            severity="Critical",
            cvss_entries=[
                {
                    "version": "3.1",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "metrics": {"baseScore": 9.8},
                }
            ],
            package_name="pkg-crit",
        ),
        _match(
            cve_id="CVE-2024-5555",
            severity="Medium",
            cvss_entries=[
                {
                    "version": "3.1",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    "metrics": {"baseScore": 5.0},
                }
            ],
            package_name="pkg-med",
        ),
    )
    parse_grype_json(payload, b"", tmp_path, "grype")
    rows = [
        json.loads(line)
        for line in (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    ]
    assert [r["cve_id"] for r in rows] == [
        "CVE-2024-9999",
        "CVE-2024-5555",
        "CVE-2024-1001",
    ]


def test_envelope_not_dict_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        findings = parse_grype_json(b"[]", b"", tmp_path, "grype")
    assert findings == []
    assert any(
        "grype_parser_envelope_not_dict" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_match_missing_artifact_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    bad = _match()
    bad.pop("artifact")
    payload = _payload(bad, _match(cve_id="CVE-OK"))
    with caplog.at_level(logging.WARNING):
        findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert len(findings) == 1
    assert any(
        "grype_parser_match_missing_field" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_malformed_json_returns_empty(tmp_path: Path) -> None:
    assert parse_grype_json(b"not-json", b"", tmp_path, "grype") == []


def test_evidence_sidecar_includes_tool_id_and_kind(tmp_path: Path) -> None:
    payload = _payload(_match(cve_id="CVE-2024-99999"))
    parse_grype_json(payload, b"", tmp_path, "grype-img")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["tool_id"] == "grype-img"
    assert blob["kind"] == "grype"
    assert blob["cve_id"] == "CVE-2024-99999"
    assert blob["package_name"] == "openssl"


def test_matches_field_not_a_list_returns_empty(tmp_path: Path) -> None:
    """Envelope with non-list `matches` is rejected silently."""
    envelope = json.dumps({"matches": "not-a-list"}).encode("utf-8")
    assert parse_grype_json(envelope, b"", tmp_path, "grype") == []


def test_all_matches_invalid_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """When every match fails normalisation, parser returns []."""
    no_artifact = _match(cve_id="CVE-NA")
    no_artifact.pop("artifact")
    no_vuln = _match(cve_id="CVE-NV")
    no_vuln.pop("vulnerability")
    no_id = _match(cve_id="")
    no_name = _match(cve_id="CVE-NN", package_name="")
    payload = _payload(no_artifact, no_vuln, no_id, no_name, "bare-string")  # type: ignore[arg-type]
    with caplog.at_level(logging.WARNING):
        findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings == []
    events = {record.__dict__.get("event") for record in caplog.records}
    assert "grype_parser_match_missing_field" in events
    assert "grype_parser_match_missing_cve" in events
    assert "grype_parser_artifact_missing_name" in events


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Hitting _MAX_FINDINGS truncates output and emits a structured warning."""
    monkeypatch.setattr(grype_module, "_MAX_FINDINGS", 2)
    matches = [
        _match(
            cve_id=f"CVE-2024-{i:04d}",
            package_name=f"pkg-{i}",
            package_version=f"1.0.{i}",
        )
        for i in range(5)
    ]
    with caplog.at_level(logging.WARNING):
        findings = parse_grype_json(_payload(*matches), b"", tmp_path, "grype")
    assert len(findings) == 2
    assert any(
        "grype_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_canonical_read_oserror_falls_back_to_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """OSError on canonical read is logged; parser falls back to stdout."""
    canonical = tmp_path / "grype.json"
    canonical.write_bytes(_payload(_match(cve_id="CVE-CANONICAL-9999")))

    def _fake_read_bytes(_self: Path) -> bytes:
        raise PermissionError("simulated permission denied")

    monkeypatch.setattr(Path, "read_bytes", _fake_read_bytes)
    stdout_payload = _payload(_match(cve_id="CVE-STDOUT-1111"))
    with caplog.at_level(logging.WARNING):
        findings = parse_grype_json(stdout_payload, b"", tmp_path, "grype")
    assert len(findings) == 1
    sidecar_text = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "CVE-STDOUT-1111" in sidecar_text
    assert any(
        "grype_parser_canonical_read_failed" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_sidecar_persist_oserror_logs_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """OSError on sidecar write is caught and logged; findings still returned."""
    blocker = tmp_path / "block_file"
    blocker.write_text("file-not-dir", encoding="utf-8")
    payload = _payload(_match())
    with caplog.at_level(logging.WARNING):
        findings = parse_grype_json(payload, b"", blocker, "grype")
    assert len(findings) == 1
    assert any(
        "grype_parser_evidence_sidecar_write_failed"
        in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_severity_unknown_string_collapses_to_info(tmp_path: Path) -> None:
    """Severity values outside the known set fall back to `info`."""
    payload = _payload(_match(severity="weird-token", cvss_entries=[]))
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cvss_v3_score == pytest.approx(0.0)


def test_non_string_severity_treated_as_unknown(tmp_path: Path) -> None:
    """Non-string severity falls through _string_field and defaults to Unknown."""
    bad = _match(cvss_entries=[])
    bad["vulnerability"]["severity"] = 123
    payload = _payload(bad)
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cvss_v3_score == pytest.approx(0.0)


def test_ghsa_id_preserved_as_cve_token(tmp_path: Path) -> None:
    """GHSA-* identifiers are kept verbatim by _normalise_cve_id."""
    payload = _payload(_match(cve_id="GHSA-xxxx-yyyy-zzzz"))
    parse_grype_json(payload, b"", tmp_path, "grype")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["cve_id"] == "GHSA-xxxx-yyyy-zzzz"


def test_extract_cvss_non_list_returns_sentinel(tmp_path: Path) -> None:
    """Non-list `cvss` field collapses to severity-anchored sentinel."""
    bad = _match(severity="High")
    bad["vulnerability"]["cvss"] = "not-a-list"
    payload = _payload(bad)
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cvss_v3_score == pytest.approx(7.5)


def test_extract_cvss_skips_non_dict_entries_and_missing_score(
    tmp_path: Path,
) -> None:
    """Non-dict entries / entries without metrics are skipped in CVSS scoring."""
    payload = _payload(
        _match(
            severity="High",
            cvss_entries=[
                "bare-string",  # type: ignore[list-item]
                {  # missing metrics
                    "version": "3.1",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
                {  # invalid vector
                    "version": "2.0",
                    "vector": "AV:N/AC:L",
                    "metrics": {"baseScore": 5.0},
                },
            ],
        )
    )
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cvss_v3_score == pytest.approx(7.5)


def test_related_vulnerabilities_non_list_returns_empty(tmp_path: Path) -> None:
    """Non-list `relatedVulnerabilities` collapses to empty (no CWE harvest)."""
    bad = _match(cwes=None)
    bad["relatedVulnerabilities"] = "not-a-list"
    payload = _payload(bad)
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cwe == [1395]


def test_extract_cwe_handles_singular_cwe_field(tmp_path: Path) -> None:
    """`vulnerability.cwe` (singular) is honoured alongside `cwes` list."""
    bad = _match(cwes=None)
    bad["vulnerability"]["cwe"] = "CWE-352"
    payload = _payload(bad)
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cwe == [352]


def test_extract_cwe_supports_int_dict_and_bool(tmp_path: Path) -> None:
    """_extract_cwe handles ints, dicts (recurse via id), and ignores bools."""
    bad = _match(cwes=None)
    bad["vulnerability"]["cwes"] = [22, True, {"id": "CWE-79"}]
    payload = _payload(bad)
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cwe == [22, 79]


def test_extract_fix_non_dict_returns_empty(tmp_path: Path) -> None:
    """Non-dict `fix` block leaves fix_versions / fix_state empty."""
    bad = _match()
    bad["vulnerability"]["fix"] = "fixed"
    payload = _payload(bad)
    parse_grype_json(payload, b"", tmp_path, "grype")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "fix_versions" not in blob
    assert "fix_state" not in blob


def test_extract_match_details_handles_empty_list(tmp_path: Path) -> None:
    """Empty matchDetails list collapses match_type / matcher to None."""
    bad = _match()
    bad["matchDetails"] = []
    payload = _payload(bad)
    parse_grype_json(payload, b"", tmp_path, "grype")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "match_type" not in blob
    assert "matcher" not in blob


def test_extract_match_details_first_non_dict_returns_none(tmp_path: Path) -> None:
    """matchDetails whose first element is not a dict falls back to None pair."""
    bad = _match()
    bad["matchDetails"] = ["bare-string", {"type": "x", "matcher": "y"}]
    payload = _payload(bad)
    parse_grype_json(payload, b"", tmp_path, "grype")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "match_type" not in blob


def test_extract_locations_handles_str_items_and_non_list(tmp_path: Path) -> None:
    """Locations may be a list of strings; non-list collapses to []."""
    bad = _match()
    bad["artifact"]["locations"] = ["/etc/secrets", "/usr/lib/x"]
    payload = _payload(bad)
    parse_grype_json(payload, b"", tmp_path, "grype")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["locations"] == ["/etc/secrets", "/usr/lib/x"]


def test_extract_locations_non_list_yields_empty(tmp_path: Path) -> None:
    """Non-list `locations` field is dropped from sidecar."""
    bad = _match()
    bad["artifact"]["locations"] = "not-a-list"
    payload = _payload(bad)
    parse_grype_json(payload, b"", tmp_path, "grype")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "locations" not in blob


def test_coerce_float_handles_bool_and_string_branches(tmp_path: Path) -> None:
    """baseScore as bool returns None; numeric string is parsed."""
    payload = _payload(
        _match(
            severity="High",
            cvss_entries=[
                {  # bool baseScore — should be skipped
                    "version": "3.1",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "metrics": {"baseScore": True},
                },
                {  # string baseScore — parsed as 8.5
                    "version": "3.1",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "metrics": {"baseScore": "8.5"},
                },
            ],
        )
    )
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cvss_v3_score == pytest.approx(8.5)


def test_coerce_float_invalid_string_returns_none(tmp_path: Path) -> None:
    """Unparseable string baseScore returns None and falls back to severity anchor."""
    payload = _payload(
        _match(
            severity="High",
            cvss_entries=[
                {
                    "version": "3.1",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "metrics": {"baseScore": "not-a-number"},
                }
            ],
        )
    )
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cvss_v3_score == pytest.approx(7.5)


def test_long_description_truncated_in_evidence(tmp_path: Path) -> None:
    """Description longer than _MAX_EVIDENCE_BYTES is truncated in sidecar."""
    huge = "Y" * (4 * 1024 + 256)
    payload = _payload(_match(description=huge))
    parse_grype_json(payload, b"", tmp_path, "grype")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert blob["description"].endswith("...[truncated]")
    assert len(blob["description"].encode("utf-8")) < len(huge)


def test_non_dict_match_in_array_skipped(tmp_path: Path) -> None:
    """Non-dict entries inside `matches` are skipped silently."""
    envelope = json.dumps(
        {"matches": ["bare", 42, None, json.loads(_payload(_match()))["matches"][0]]}
    ).encode("utf-8")
    findings = parse_grype_json(envelope, b"", tmp_path, "grype")
    assert len(findings) == 1


def test_metrics_without_basescore_falls_back_to_anchor(tmp_path: Path) -> None:
    """Empty metrics dict makes _coerce_float receive None → severity anchor wins."""
    payload = _payload(
        _match(
            severity="Medium",
            cvss_entries=[
                {
                    "version": "3.1",
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "metrics": {},
                }
            ],
        )
    )
    findings = parse_grype_json(payload, b"", tmp_path, "grype")
    assert findings[0].cvss_v3_score == pytest.approx(5.0)


def test_missing_description_is_omitted_from_evidence(tmp_path: Path) -> None:
    """Missing vuln.description path: _truncate_text(None) returns None and is dropped."""
    bad = _match()
    bad["vulnerability"].pop("description")
    parse_grype_json(_payload(bad), b"", tmp_path, "grype")
    blob = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip())
    assert "description" not in blob
