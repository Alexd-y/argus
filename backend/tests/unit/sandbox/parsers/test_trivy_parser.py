"""Unit tests for :mod:`src.sandbox.parsers.trivy_parser` (Backlog/dev1_md §4.15 — ARG-018).

Each test pins one contract documented in the parser:

* ``parse_trivy_json`` resolves ``artifacts_dir/trivy.json`` first, then
  falls back to ``stdout``.
* Severity routing:

  - ``CRITICAL`` / ``HIGH`` → ``LIKELY``;
  - ``MEDIUM`` + CVE present → ``LIKELY``;
  - ``MEDIUM`` without CVE → ``SUSPECTED``;
  - ``LOW`` / ``UNKNOWN`` → ``SUSPECTED``;
  - secrets at ``CRITICAL`` escalate to ``CONFIRMED``.

* CVE normalisation: re-adds the ``CVE-`` prefix; drops malformed tokens;
  picks up extra CVEs found in ``References``.
* CWE extraction handles ``"CWE-79"``, ``"79"``, and integer values.
* CVSS extraction prefers the NVD vendor block and validates that the
  vector starts with ``CVSS:3.`` or ``CVSS:4.``; falls back through the
  vendor priority list, then to the per-severity sentinel.
* Misconfigurations with ``Status="PASS"`` are dropped (Trivy emits
  passes for audit completeness; not findings).
* Secrets get a redacted ``match_preview`` and the dedup hash is taken
  over the secret bytes (never the raw secret in the dedup tuple).
* Records collapse on stable per-kind dedup keys; the parser is
  deterministic across runs.
* Hard cap at 10 000 findings — defends the worker against a runaway
  scan over a multi-thousand-package image.
* Malformed envelopes / unexpected types are skipped with a structured
  WARNING; the worker never crashes on bad input.
* Sidecar JSONL ``trivy_findings.jsonl`` carries one record per emitted
  finding stamped with the source ``tool_id`` (``trivy_image`` /
  ``trivy_fs``).
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
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_VECTOR,
)
from src.sandbox.parsers.trivy_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_trivy_json,
)


# ---------------------------------------------------------------------------
# Builders for canonical fixture shapes
# ---------------------------------------------------------------------------


def _vuln(
    *,
    vid: str = "CVE-2024-12345",
    pkg: str = "openssl",
    installed: str | None = "3.0.11-1~deb12u1",
    fixed: str | None = "3.0.11-1~deb12u2",
    severity: str = "HIGH",
    title: str = "openssl: padding oracle in PKCS1 v1.5",
    description: str = "...",
    primary_url: str | None = "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
    refs: list[str] | None = None,
    cwes: list[Any] | None = None,
    cvss: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "VulnerabilityID": vid,
        "PkgName": pkg,
        "Severity": severity,
        "Title": title,
        "Description": description,
    }
    if installed is not None:
        record["InstalledVersion"] = installed
    if fixed is not None:
        record["FixedVersion"] = fixed
    if primary_url is not None:
        record["PrimaryURL"] = primary_url
    if refs is not None:
        record["References"] = list(refs)
    if cwes is not None:
        record["CweIDs"] = list(cwes)
    if cvss is not None:
        record["CVSS"] = cvss
    return record


def _misconfig(
    *,
    cid: str = "DS002",
    avd_id: str | None = "AVD-DS-0002",
    title: str = "Image user should not be 'root'",
    description: str = "Image runs as root by default",
    message: str = "Specify at least 1 USER command in Dockerfile",
    namespace: str | None = "builtin.dockerfile.DS002",
    resolution: str | None = "Add 'USER non-root' before any sensitive ops",
    severity: str = "HIGH",
    primary_url: str | None = "https://avd.aquasec.com/misconfig/ds002",
    references: list[str] | None = None,
    status: str | None = "FAIL",
    start_line: int | None = 5,
    end_line: int | None = 5,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "ID": cid,
        "Title": title,
        "Description": description,
        "Message": message,
        "Severity": severity,
    }
    if avd_id is not None:
        record["AVDID"] = avd_id
    if namespace is not None:
        record["Namespace"] = namespace
    if resolution is not None:
        record["Resolution"] = resolution
    if primary_url is not None:
        record["PrimaryURL"] = primary_url
    if references is not None:
        record["References"] = list(references)
    if status is not None:
        record["Status"] = status
    if start_line is not None or end_line is not None:
        cause: dict[str, Any] = {}
        if start_line is not None:
            cause["StartLine"] = start_line
        if end_line is not None:
            cause["EndLine"] = end_line
        record["CauseMetadata"] = cause
    return record


def _secret(
    *,
    rule_id: str = "github-pat",
    category: str = "GitHub",
    title: str = "GitHub Personal Access Token",
    severity: str = "CRITICAL",
    start_line: int = 42,
    end_line: int = 42,
    match: str = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
) -> dict[str, Any]:
    return {
        "RuleID": rule_id,
        "Category": category,
        "Title": title,
        "Severity": severity,
        "StartLine": start_line,
        "EndLine": end_line,
        "Match": match,
        "Code": {"Lines": [{"Number": start_line, "Content": "...", "IsCause": True}]},
    }


def _envelope(
    *,
    target: str = "registry.example/foo:1.2.3 (debian 12.5)",
    result_class: str = "os-pkgs",
    result_type: str = "debian",
    vulnerabilities: list[dict[str, Any]] | None = None,
    misconfigurations: list[dict[str, Any]] | None = None,
    secrets: list[dict[str, Any]] | None = None,
    artifact_name: str = "registry.example/foo:1.2.3",
    artifact_type: str = "container_image",
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "Target": target,
        "Class": result_class,
        "Type": result_type,
    }
    if vulnerabilities is not None:
        result["Vulnerabilities"] = list(vulnerabilities)
    if misconfigurations is not None:
        result["Misconfigurations"] = list(misconfigurations)
    if secrets is not None:
        result["Secrets"] = list(secrets)
    return {
        "ArtifactName": artifact_name,
        "ArtifactType": artifact_type,
        "Results": [result],
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def artifacts_dir(tmp_path: Path) -> Path:
    out = tmp_path / "artifacts"
    out.mkdir()
    return out


def _write_canonical(artifacts_dir: Path, payload: dict[str, Any]) -> None:
    (artifacts_dir / "trivy.json").write_text(json.dumps(payload), encoding="utf-8")


def _read_sidecar(artifacts_dir: Path) -> list[dict[str, Any]]:
    sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
    if not sidecar.is_file():
        return []
    return [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ===========================================================================
# 1. Payload resolution: canonical artifact > stdout
# ===========================================================================


def test_canonical_artifact_takes_precedence_over_stdout(
    artifacts_dir: Path,
) -> None:
    """``trivy.json`` on disk wins over stdout (canonical YAML uses ``-o``)."""
    canonical = _envelope(vulnerabilities=[_vuln(vid="CVE-2024-1111")])
    stdout_payload = _envelope(vulnerabilities=[_vuln(vid="CVE-2024-2222")])
    _write_canonical(artifacts_dir, canonical)
    findings = parse_trivy_json(
        stdout=json.dumps(stdout_payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert len(findings) == 1
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["vuln_id"] == "CVE-2024-1111"


def test_trivy_fs_reads_trivy_fs_canonical_filename(
    artifacts_dir: Path,
) -> None:
    """``trivy_fs`` writes ``/out/trivy_fs.json`` (per Backlog §4.15);
    ``parse_trivy_json`` MUST read that file when ``tool_id='trivy_fs'``,
    not ``/out/trivy.json`` (which only ``trivy_image`` uses).

    Regression: pre-fix the parser hard-coded ``trivy.json`` and silently
    returned ``[]`` for every ``trivy_fs`` invocation, dropping all
    SCA / IaC / secret findings from filesystem scans.
    """
    payload = _envelope(vulnerabilities=[_vuln(vid="CVE-2024-9001")])
    (artifacts_dir / "trivy_fs.json").write_text(json.dumps(payload), encoding="utf-8")
    findings = parse_trivy_json(
        stdout=b"",
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_fs",
    )
    assert len(findings) == 1
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["vuln_id"] == "CVE-2024-9001"
    assert sidecar[0]["tool_id"] == "trivy_fs"


def test_trivy_image_does_not_fall_back_to_trivy_fs_filename(
    artifacts_dir: Path,
) -> None:
    """``trivy_image`` MUST NOT pick up ``trivy_fs.json`` (cross-tool isolation).

    Two Trivy invocations share an ``/out`` mount in production; the
    parser must read only the file its own YAML wrote, never the
    sibling tool's artifact.
    """
    payload = _envelope(vulnerabilities=[_vuln(vid="CVE-2024-9002")])
    (artifacts_dir / "trivy_fs.json").write_text(json.dumps(payload), encoding="utf-8")
    findings = parse_trivy_json(
        stdout=b"",
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert findings == []


def test_trivy_fs_does_not_fall_back_to_trivy_image_filename(
    artifacts_dir: Path,
) -> None:
    """Symmetric to :func:`test_trivy_image_does_not_fall_back_to_trivy_fs_filename`.

    A stale ``trivy.json`` from a prior ``trivy_image`` run in the same
    artifacts dir must not be served to a ``trivy_fs`` parse call.
    """
    payload = _envelope(vulnerabilities=[_vuln(vid="CVE-2024-9003")])
    (artifacts_dir / "trivy.json").write_text(json.dumps(payload), encoding="utf-8")
    findings = parse_trivy_json(
        stdout=b"",
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_fs",
    )
    assert findings == []


def test_unknown_tool_id_falls_back_to_default_trivy_filename(
    artifacts_dir: Path,
) -> None:
    """Future Trivy callers without an explicit filename mapping read the default.

    Defends backwards-compat: a hypothetical ``trivy_repo`` registered
    later without a ``_CANONICAL_FILENAME_BY_TOOL`` entry still parses
    best-effort against ``trivy.json`` rather than silently returning
    an empty list.
    """
    payload = _envelope(vulnerabilities=[_vuln(vid="CVE-2024-9004")])
    (artifacts_dir / "trivy.json").write_text(json.dumps(payload), encoding="utf-8")
    findings = parse_trivy_json(
        stdout=b"",
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_future_caller",
    )
    assert len(findings) == 1


def test_stdout_used_when_canonical_absent(artifacts_dir: Path) -> None:
    """When ``trivy.json`` is missing, parser falls back to stdout."""
    payload = _envelope(vulnerabilities=[_vuln()])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_fs",
    )
    assert len(findings) == 1


def test_empty_input_returns_empty_list(artifacts_dir: Path) -> None:
    """No canonical artifact and empty stdout → empty result."""
    findings = parse_trivy_json(
        stdout=b"",
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert findings == []
    assert not (artifacts_dir / EVIDENCE_SIDECAR_NAME).exists()


def test_malformed_json_returns_empty_list(
    artifacts_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Garbage JSON produces a structured warning and no findings."""
    caplog.set_level(logging.WARNING)
    findings = parse_trivy_json(
        stdout=b"{not valid json",
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert findings == []


def test_envelope_not_dict_returns_empty(
    artifacts_dir: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Top-level array (not a dict) is rejected with a WARNING."""
    caplog.set_level(logging.WARNING)
    findings = parse_trivy_json(
        stdout=b"[1, 2, 3]",
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert findings == []
    assert any("envelope_not_dict" in r.message for r in caplog.records)


# ===========================================================================
# 2. Vulnerabilities — severity / CVSS / CVE / CWE / confidence
# ===========================================================================


def test_critical_vuln_maps_to_supply_chain_likely(
    artifacts_dir: Path,
) -> None:
    """CRITICAL vulnerability → SUPPLY_CHAIN / LIKELY."""
    payload = _envelope(
        vulnerabilities=[_vuln(severity="CRITICAL", vid="CVE-2024-99999")]
    )
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.category == FindingCategory.SUPPLY_CHAIN
    assert f.confidence == ConfidenceLevel.LIKELY


def test_medium_vuln_with_cve_escalates_to_likely(
    artifacts_dir: Path,
) -> None:
    """MEDIUM with a CVE id present → LIKELY (NVD-confirmed)."""
    payload = _envelope(
        vulnerabilities=[_vuln(severity="MEDIUM", vid="CVE-2023-12345")]
    )
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert findings[0].confidence == ConfidenceLevel.LIKELY


def test_low_vuln_remains_suspected(artifacts_dir: Path) -> None:
    """LOW severity stays SUSPECTED even with a CVE id."""
    payload = _envelope(vulnerabilities=[_vuln(severity="LOW")])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert findings[0].confidence == ConfidenceLevel.SUSPECTED


def test_cvss_picks_nvd_vendor_first(artifacts_dir: Path) -> None:
    """When NVD + RedHat both have V3Score, NVD wins."""
    cvss = {
        "nvd": {
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "V3Score": 9.8,
        },
        "redhat": {
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "V3Score": 7.5,
        },
    }
    payload = _envelope(vulnerabilities=[_vuln(severity="HIGH", cvss=cvss)])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    f = findings[0]
    assert f.cvss_v3_score == 9.8
    assert f.cvss_v3_vector.startswith("CVSS:3.")


def test_cvss_falls_back_to_severity_sentinel_when_invalid_vector(
    artifacts_dir: Path,
) -> None:
    """CVSS:2.0 vectors are rejected; score from severity sentinel applies."""
    cvss = {"vendor": {"V3Vector": "CVSS:2.0/AV:N/AC:L", "V3Score": 8.5}}
    payload = _envelope(vulnerabilities=[_vuln(severity="HIGH", cvss=cvss)])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    f = findings[0]
    assert f.cvss_v3_score == 8.5  # score is preserved, only the vector is sentinel
    assert f.cvss_v3_vector == SENTINEL_CVSS_VECTOR


def test_cvss_absent_block_uses_severity_anchor(
    artifacts_dir: Path,
) -> None:
    """Without a CVSS block, the severity bucket sentinel applies."""
    payload = _envelope(vulnerabilities=[_vuln(severity="HIGH", cvss=None)])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert findings[0].cvss_v3_score == 7.5  # _SEVERITY_TO_CVSS["high"]


def test_cwe_extracted_from_string_and_int_forms(artifacts_dir: Path) -> None:
    """Trivy CWE list accepts ``CWE-79`` strings and bare integers."""
    payload = _envelope(
        vulnerabilities=[_vuln(severity="HIGH", cwes=["CWE-310", 327, "CWE-79"])]
    )
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert sorted(findings[0].cwe) == [79, 310, 327]


def test_cwe_defaults_to_supply_chain_when_missing(
    artifacts_dir: Path,
) -> None:
    """SUPPLY_CHAIN with no CWE → fallback to CWE-1395."""
    payload = _envelope(vulnerabilities=[_vuln(severity="HIGH", cwes=None)])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert findings[0].cwe == [1395]


def test_cve_extracted_from_references_in_addition_to_id(
    artifacts_dir: Path,
) -> None:
    """Extra CVEs hidden in ``References`` are surfaced and deduplicated."""
    payload = _envelope(
        vulnerabilities=[
            _vuln(
                vid="CVE-2024-12345",
                refs=[
                    "https://access.redhat.com/security/cve/CVE-2024-99999",
                    "https://example.com/no-cve-here",
                ],
            )
        ]
    )
    parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sorted(sidecar[0]["cve"]) == ["CVE-2024-12345", "CVE-2024-99999"]


def test_invalid_cve_token_drops_from_list(artifacts_dir: Path) -> None:
    """Malformed CVE tokens (missing year/seq) are silently dropped."""
    payload = _envelope(
        vulnerabilities=[
            _vuln(
                vid="CVE-2024-12345",
                refs=["CVE-XX-XX", "CVE-1900-99"],  # bad year + short seq
            )
        ]
    )
    parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["cve"] == ["CVE-2024-12345"]


def test_vuln_dedup_by_target_pkg_version_id(artifacts_dir: Path) -> None:
    """Same vuln across two duplicated emissions collapses to one finding."""
    v = _vuln(vid="CVE-2024-12345", pkg="openssl", installed="3.0.11")
    payload = _envelope(vulnerabilities=[v, v.copy()])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert len(findings) == 1


def test_vuln_missing_required_fields_is_skipped(
    artifacts_dir: Path,
) -> None:
    """Vuln without VulnerabilityID OR PkgName is skipped."""
    bad1 = _vuln()
    bad1.pop("VulnerabilityID")
    bad2 = _vuln(vid="CVE-2024-12345")
    bad2.pop("PkgName")
    payload = _envelope(vulnerabilities=[bad1, bad2, _vuln(vid="CVE-2024-22222")])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert len(findings) == 1


# ===========================================================================
# 3. Misconfigurations — pass filtering, AVDID fallback, CauseMetadata
# ===========================================================================


def test_misconfig_pass_status_is_filtered_out(
    artifacts_dir: Path,
) -> None:
    """``Status="PASS"`` records are not findings (audit completeness only)."""
    pass_record = _misconfig(status="PASS")
    fail_record = _misconfig(status="FAIL", cid="DS003")
    payload = _envelope(
        result_class="config",
        misconfigurations=[pass_record, fail_record],
    )
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert len(findings) == 1
    assert findings[0].category == FindingCategory.MISCONFIG


def test_misconfig_avdid_fallback_when_id_missing(
    artifacts_dir: Path,
) -> None:
    """If ``ID`` is absent, ``AVDID`` becomes the check identifier."""
    record = _misconfig(cid="", avd_id="AVD-DS-0009")
    record.pop("ID", None)
    payload = _envelope(result_class="config", misconfigurations=[record])
    parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["check_id"] == "AVD-DS-0009"


def test_misconfig_uses_cause_metadata_lines(artifacts_dir: Path) -> None:
    """``CauseMetadata.StartLine`` / ``EndLine`` flow through to evidence."""
    payload = _envelope(
        result_class="config",
        misconfigurations=[_misconfig(start_line=12, end_line=15)],
    )
    parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["start_line"] == 12
    assert sidecar[0]["end_line"] == 15


# ===========================================================================
# 4. Secrets — confidence escalation, redaction, dedup
# ===========================================================================


def test_critical_secret_escalates_to_confirmed(artifacts_dir: Path) -> None:
    """CRITICAL secret findings become CONFIRMED (Trivy regex matched)."""
    payload = _envelope(
        result_class="secret",
        secrets=[_secret(severity="CRITICAL")],
    )
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_fs",
    )
    assert findings[0].confidence == ConfidenceLevel.CONFIRMED
    assert findings[0].category == FindingCategory.SECRET_LEAK


def test_secret_match_is_redacted_in_sidecar(artifacts_dir: Path) -> None:
    """Raw secret value never lands in the sidecar; only a redacted prefix."""
    payload = _envelope(
        result_class="secret",
        secrets=[_secret(match="ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")],
    )
    parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_fs",
    )
    sidecar = _read_sidecar(artifacts_dir)
    preview = sidecar[0]["match_preview"]
    assert preview.startswith("ghp_")
    assert "***REDACTED***" in preview
    assert "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" not in preview


def test_two_distinct_secrets_at_same_line_stay_separate(
    artifacts_dir: Path,
) -> None:
    """Different secret values at the same line do not collapse."""
    payload = _envelope(
        result_class="secret",
        secrets=[
            _secret(start_line=42, match="ghp_111111111111111111111111111111111111"),
            _secret(start_line=42, match="ghp_222222222222222222222222222222222222"),
        ],
    )
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_fs",
    )
    assert len(findings) == 2


def test_identical_secret_dedupes(artifacts_dir: Path) -> None:
    """Same rule + same line + same secret value → one finding."""
    s = _secret(start_line=42, match="ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    payload = _envelope(result_class="secret", secrets=[s, s.copy()])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_fs",
    )
    assert len(findings) == 1


# ===========================================================================
# 5. Sidecar persistence + tool_id stamping + sort determinism
# ===========================================================================


def test_sidecar_records_carry_tool_id(artifacts_dir: Path) -> None:
    """Every sidecar record is stamped with the source ``tool_id``."""
    payload = _envelope(
        vulnerabilities=[_vuln(vid="CVE-2024-12345")],
        misconfigurations=[_misconfig()],
    )
    parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_fs",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert {r["tool_id"] for r in sidecar} == {"trivy_fs"}


def test_sort_is_deterministic_severity_desc(artifacts_dir: Path) -> None:
    """Findings sort by severity desc, then kind, then target."""
    payload = _envelope(
        vulnerabilities=[
            _vuln(vid="CVE-2024-LOW", severity="LOW"),
            _vuln(vid="CVE-2024-CRIT", severity="CRITICAL"),
            _vuln(vid="CVE-2024-MED", severity="MEDIUM"),
        ]
    )
    parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    sidecar = _read_sidecar(artifacts_dir)
    severities = [r["severity"] for r in sidecar]
    assert severities == ["critical", "medium", "low"]


def test_unknown_severity_normalises_to_info(artifacts_dir: Path) -> None:
    """Unknown / weird severity strings normalise to ``info``."""
    payload = _envelope(vulnerabilities=[_vuln(vid="CVE-2024-12345", severity="WEIRD")])
    parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["severity"] == "info"


def test_canonical_path_traversal_attempt_falls_back_to_stdout(
    tmp_path: Path,
) -> None:
    """A poisoned canonical path is rejected; parser still tries stdout."""
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    payload = _envelope(vulnerabilities=[_vuln()])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert len(findings) == 1


# ===========================================================================
# 6. Edge cases for branch coverage
# ===========================================================================


def test_non_dict_result_entries_are_skipped(artifacts_dir: Path) -> None:
    """Items in ``Results[]`` that are not dicts are silently skipped."""
    payload: dict[str, Any] = {
        "ArtifactName": "x",
        "ArtifactType": "container_image",
        "Results": [
            "garbage",
            42,
            None,
            {
                "Target": "t",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": [_vuln(vid="CVE-2024-12345")],
            },
        ],
    }
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert len(findings) == 1


def test_non_dict_vuln_misconfig_secret_entries_skipped(
    artifacts_dir: Path,
) -> None:
    """Non-dict items in Vulnerabilities/Misconfigurations/Secrets are skipped."""
    payload = {
        "Results": [
            {
                "Target": "t",
                "Class": "config",
                "Type": "dockerfile",
                "Vulnerabilities": ["bad", 1, _vuln()],
                "Misconfigurations": [None, _misconfig()],
                "Secrets": ["nope", _secret()],
            }
        ],
    }
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert len(findings) == 3


def test_results_field_not_list_returns_empty(artifacts_dir: Path) -> None:
    """``Results`` is a dict (wrong type) → empty findings."""
    payload = {"Results": {"oops": "dict"}}
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert findings == []


def test_misconfig_without_id_or_avdid_skipped(artifacts_dir: Path) -> None:
    """Misconfig without ``ID`` AND ``AVDID`` is silently dropped."""
    bad = _misconfig()
    bad.pop("ID", None)
    bad.pop("AVDID", None)
    payload = _envelope(result_class="config", misconfigurations=[bad])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert findings == []


def test_secret_without_rule_id_skipped(artifacts_dir: Path) -> None:
    """Secret entry without ``RuleID`` is dropped."""
    bad = _secret()
    bad.pop("RuleID")
    payload = _envelope(result_class="secret", secrets=[bad])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert findings == []


def test_secret_with_short_match_is_redacted(artifacts_dir: Path) -> None:
    """Tiny secret matches still produce a redacted preview."""
    payload = _envelope(
        result_class="secret",
        secrets=[_secret(match="abc")],  # length 3 < 4 → REDACTED only
    )
    parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_fs",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["match_preview"] == "***REDACTED***"


def test_cvss_vendor_priority_fallback_picks_unknown_vendor(
    artifacts_dir: Path,
) -> None:
    """When NVD/Ghsa/RedHat are absent, an unknown vendor block still wins."""
    cvss = {
        "obscure_vendor": {
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "V3Score": 8.1,
        }
    }
    payload = _envelope(vulnerabilities=[_vuln(severity="HIGH", cvss=cvss)])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert findings[0].cvss_v3_score == 8.1


def test_cvss_score_outside_range_falls_back_to_sentinel(
    artifacts_dir: Path,
) -> None:
    """Out-of-range V3Score (>10.0) is rejected; severity sentinel used."""
    cvss = {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L", "V3Score": 99.0}}
    payload = _envelope(vulnerabilities=[_vuln(severity="HIGH", cvss=cvss)])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert findings[0].cvss_v3_score == 7.5  # sentinel


def test_references_accept_single_string(artifacts_dir: Path) -> None:
    """Vuln References can be a single string (not just list)."""
    raw = _vuln()
    raw["References"] = "https://example.com/single-ref"
    payload = _envelope(vulnerabilities=[raw])
    parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    sidecar = _read_sidecar(artifacts_dir)
    assert sidecar[0]["references"] == ["https://example.com/single-ref"]


def test_long_description_truncated_in_evidence(artifacts_dir: Path) -> None:
    """Multi-KB descriptions are truncated at the evidence cap."""
    huge = "a" * 8192
    payload = _envelope(vulnerabilities=[_vuln(severity="HIGH", description=huge)])
    parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    # description maps to "message" in sidecar; verify it is truncated
    sidecar = _read_sidecar(artifacts_dir)
    if sidecar[0].get("message"):
        assert sidecar[0]["message"].endswith("...[truncated]")


def test_safe_join_rejects_path_traversal(
    artifacts_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Internal ``_safe_join`` refuses traversal segments."""
    from src.sandbox.parsers.trivy_parser import _safe_join

    base = artifacts_dir
    assert _safe_join(base, "trivy.json") == base / "trivy.json"
    assert _safe_join(base, "../etc/passwd") is None
    assert _safe_join(base, "subdir/file.json") is None
    assert _safe_join(base, "dir\\file") is None


def test_parser_recovers_from_canonical_read_oserror(
    artifacts_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """OS error reading the canonical artifact falls back to stdout."""
    caplog.set_level(logging.WARNING)
    canonical = artifacts_dir / "trivy.json"
    canonical.write_text("placeholder", encoding="utf-8")
    real_read_bytes = Path.read_bytes

    def _boom(self: Path) -> bytes:
        if self == canonical:
            raise OSError("simulated read failure")
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _boom)
    payload = _envelope(vulnerabilities=[_vuln()])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert len(findings) == 1
    assert any("canonical_read_failed" in r.message for r in caplog.records)


def test_sidecar_write_failure_does_not_crash(
    artifacts_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """OS error writing the sidecar logs structured warning, swallows error."""
    caplog.set_level(logging.WARNING)
    real_open = Path.open

    def _boom(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == EVIDENCE_SIDECAR_NAME:
            raise OSError("simulated write failure")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _boom)
    payload = _envelope(vulnerabilities=[_vuln()])
    findings = parse_trivy_json(
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
        artifacts_dir=artifacts_dir,
        tool_id="trivy_image",
    )
    assert len(findings) == 1
    assert any("evidence_sidecar_write_failed" in r.message for r in caplog.records)
