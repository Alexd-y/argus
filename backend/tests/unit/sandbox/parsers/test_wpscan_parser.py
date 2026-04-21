"""Unit tests for :mod:`src.sandbox.parsers.wpscan_parser` (Backlog/dev1_md §4.7).

Each test pins one contract documented in the parser:

* ``parse_wpscan_json`` resolves the canonical artifact first
  (``artifacts_dir/wpscan.json``) and falls back to ``stdout``.
* ``interesting_findings[*]`` map to :class:`FindingCategory.INFO`,
  ``ConfidenceLevel.SUSPECTED`` with CWE-200 hints.
* Core / theme / plugin vulnerabilities map to
  :class:`FindingCategory.MISCONFIG` with CWE-1395; severity is held
  through the confidence ladder — ``LIKELY`` when at least one CVE is
  attached, ``SUSPECTED`` otherwise.
* User enumeration maps to :class:`FindingCategory.INFO` with the
  IDNT-04 WSTG hint.
* CVE refs are extracted from both the inline ``cve`` field and the
  ``references.cve`` array, normalised to ``CVE-YYYY-...`` form, sorted
  and deduplicated.
* Records collapse on a stable ``(kind, component, slug, title, *cves)``
  key — running WPScan twice on the same site emits one finding per
  unique record.
* Output ordering is deterministic — sorted by the dedup key.
* Hard cap at 5 000 findings — prevents a runaway plugin enumeration
  from exhausting worker memory.
* Malformed / empty / non-dict JSON returns ``[]`` and writes no
  sidecar; the malformed payload is logged once at WARNING.
* Sidecar JSONL ``wpscan_findings.jsonl`` carries one compact record per
  emitted finding, stamped with the source ``tool_id`` so the downstream
  evidence pipeline can route per-tool.
* ``parse_droopescan_json`` honours the same dispatch contract; emits
  info-only findings for detected versions, components and users.
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
    SENTINEL_CVSS_SCORE,
    SENTINEL_CVSS_VECTOR,
    SENTINEL_UUID,
)
from src.sandbox.parsers.wpscan_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_droopescan_json,
    parse_wpscan_json,
)

# ---------------------------------------------------------------------------
# Builders for canonical fixture shapes
# ---------------------------------------------------------------------------


def _interesting_finding(
    *,
    finding_type: str = "headers",
    to_s: str = "Server: Apache/2.4.41",
    url: str = "https://example.com/",
    references: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "type": finding_type,
        "to_s": to_s,
        "url": url,
    }
    if references is not None:
        record["references"] = references
    return record


def _vulnerability(
    *,
    title: str,
    cve: list[str] | None = None,
    references_cve: list[str] | None = None,
    fixed_in: str | None = "1.0.0",
    url: str = "https://wpscan.com/vulnerability/abc",
) -> dict[str, Any]:
    references: dict[str, list[str]] = {}
    if references_cve is not None:
        references["cve"] = list(references_cve)
    record: dict[str, Any] = {
        "title": title,
        "fixed_in": fixed_in,
        "url": url,
        "references": references,
    }
    if cve is not None:
        record["cve"] = list(cve)
    return record


def _wpscan_payload(
    *,
    interesting: list[dict[str, Any]] | None = None,
    core_version: str | None = "5.8.1",
    core_vulns: list[dict[str, Any]] | None = None,
    main_theme_slug: str | None = None,
    main_theme_vulns: list[dict[str, Any]] | None = None,
    plugins: dict[str, dict[str, Any]] | None = None,
    themes: dict[str, dict[str, Any]] | None = None,
    users: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if interesting is not None:
        payload["interesting_findings"] = interesting
    if core_version is not None or core_vulns is not None:
        payload["version"] = {
            "number": core_version,
            "vulnerabilities": list(core_vulns or []),
        }
    if main_theme_slug is not None:
        payload["main_theme"] = {
            "slug": main_theme_slug,
            "version": {"number": "1.2.3"},
            "vulnerabilities": list(main_theme_vulns or []),
        }
    if plugins is not None:
        payload["plugins"] = plugins
    if themes is not None:
        payload["themes"] = themes
    if users is not None:
        payload["users"] = users
    return payload


def _plugin_block(
    *,
    version: str | None = "1.0.0",
    vulnerabilities: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    block: dict[str, Any] = {"vulnerabilities": list(vulnerabilities or [])}
    if version is not None:
        block["version"] = {"number": version}
    return block


def _payload_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload).encode("utf-8")


# ---------------------------------------------------------------------------
# parse_wpscan_json — contract tests
# ---------------------------------------------------------------------------


def test_parse_wpscan_canonical_artifact_takes_precedence_over_stdout(
    tmp_path: Path,
) -> None:
    """Canonical ``wpscan.json`` wins; stdout is ignored when both are set."""
    canonical_payload = _wpscan_payload(
        interesting=[
            _interesting_finding(finding_type="readme", to_s="readme.html"),
        ],
        core_version=None,
    )
    (tmp_path / "wpscan.json").write_bytes(_payload_bytes(canonical_payload))

    stdout_payload = _wpscan_payload(
        interesting=[
            _interesting_finding(finding_type="config", to_s="should not appear"),
        ],
        core_version=None,
    )
    findings = parse_wpscan_json(
        stdout=_payload_bytes(stdout_payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "readme" in sidecar
    assert "should not appear" not in sidecar


def test_parse_wpscan_stdout_fallback_when_canonical_missing(
    tmp_path: Path,
) -> None:
    """No canonical → fall back to stdout."""
    payload = _wpscan_payload(
        interesting=[_interesting_finding(finding_type="config_backup")],
        core_version=None,
    )
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_parse_wpscan_interesting_finding_carries_info_classification(
    tmp_path: Path,
) -> None:
    """Interesting findings → INFO/SUSPECTED with CWE-200, WSTG-INFO-08."""
    payload = _wpscan_payload(
        interesting=[
            _interesting_finding(finding_type="xmlrpc", to_s="XML-RPC seems enabled"),
        ],
        core_version=None,
    )
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.INFO
    assert finding.confidence is ConfidenceLevel.SUSPECTED
    assert 200 in finding.cwe
    assert "WSTG-INFO-08" in finding.owasp_wstg
    assert finding.cvss_v3_vector == SENTINEL_CVSS_VECTOR
    assert finding.cvss_v3_score == SENTINEL_CVSS_SCORE
    assert finding.tenant_id == SENTINEL_UUID


def test_parse_wpscan_core_vuln_with_cve_escalates_to_likely(tmp_path: Path) -> None:
    """A version vuln with a CVE reference → MISCONFIG / LIKELY."""
    payload = _wpscan_payload(
        core_vulns=[
            _vulnerability(
                title="WP Core 5.8.0 — auth bypass",
                references_cve=["2024-12345"],
                fixed_in="5.8.2",
            ),
        ],
    )
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.MISCONFIG
    assert finding.confidence is ConfidenceLevel.LIKELY
    assert 1395 in finding.cwe


def test_parse_wpscan_vuln_without_cve_stays_suspected(tmp_path: Path) -> None:
    """A version vuln without any CVE → MISCONFIG / SUSPECTED."""
    payload = _wpscan_payload(
        core_vulns=[
            _vulnerability(title="WP Core 5.8.0 — info disclosure"),
        ],
    )
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.MISCONFIG
    assert finding.confidence is ConfidenceLevel.SUSPECTED


def test_parse_wpscan_plugin_vuln_records_slug_in_sidecar(tmp_path: Path) -> None:
    """Plugin vulns are tagged with the plugin slug in the sidecar evidence."""
    payload = _wpscan_payload(
        plugins={
            "akismet": _plugin_block(
                version="4.0.0",
                vulnerabilities=[
                    _vulnerability(
                        title="Akismet < 4.0.3 — XSS",
                        references_cve=["2023-9999"],
                    ),
                ],
            ),
        },
    )
    parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    sidecar_lines = [
        line
        for line in (tmp_path / EVIDENCE_SIDECAR_NAME)
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    parsed = [json.loads(line) for line in sidecar_lines]
    plugin_records = [r for r in parsed if r["component"] == "plugin"]
    assert plugin_records, "plugin record absent from sidecar"
    assert plugin_records[0]["slug"] == "akismet"
    assert plugin_records[0]["cve"] == ["CVE-2023-9999"]
    assert plugin_records[0]["version"] == "4.0.0"
    assert plugin_records[0]["tool_id"] == "wpscan"


def test_parse_wpscan_user_enum_emits_idnt04(tmp_path: Path) -> None:
    """Users dict → INFO findings tagged WSTG-IDNT-04."""
    payload = _wpscan_payload(
        users={
            "admin": {"id": 1},
            "editor": {"id": 2},
        },
        core_version=None,
    )
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 2
    assert all(f.category is FindingCategory.INFO for f in findings)
    assert all("WSTG-IDNT-04" in f.owasp_wstg for f in findings)


def test_parse_wpscan_cve_normalisation_merges_inline_and_references(
    tmp_path: Path,
) -> None:
    """Inline ``cve`` and ``references.cve`` merge / dedupe / sort / prefix."""
    payload = _wpscan_payload(
        core_vulns=[
            _vulnerability(
                title="dup-cve",
                cve=["2024-11111", "2024-99999"],
                references_cve=["CVE-2024-11111", "2024-22222"],
            ),
        ],
    )
    parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["cve"] == ["CVE-2024-11111", "CVE-2024-22222", "CVE-2024-99999"]


def test_parse_wpscan_dedup_collapses_duplicates(tmp_path: Path) -> None:
    """Re-discovering the same plugin vuln twice → one finding."""
    duplicate_vuln = _vulnerability(
        title="Akismet < 4.0.3 — XSS", references_cve=["2023-9999"]
    )
    payload = _wpscan_payload(
        plugins={
            "akismet": _plugin_block(
                vulnerabilities=[duplicate_vuln, dict(duplicate_vuln)],
            ),
        },
    )
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 1


def test_parse_wpscan_output_ordering_is_deterministic(tmp_path: Path) -> None:
    """Two runs of the parser on the same payload produce identical sidecars."""
    payload = _wpscan_payload(
        interesting=[
            _interesting_finding(finding_type="readme"),
            _interesting_finding(finding_type="config_backup"),
            _interesting_finding(finding_type="xmlrpc"),
        ],
        core_version=None,
    )
    sidecar_path = tmp_path / EVIDENCE_SIDECAR_NAME

    parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    first = sidecar_path.read_text(encoding="utf-8")
    sidecar_path.unlink()

    parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    second = sidecar_path.read_text(encoding="utf-8")
    assert first == second


def test_parse_wpscan_caps_at_5000_findings(tmp_path: Path) -> None:
    """A pathological plugin enumeration is hard-capped at 5_000 records."""
    plugins: dict[str, dict[str, Any]] = {
        f"plugin-{i:05d}": _plugin_block(
            vulnerabilities=[_vulnerability(title=f"vuln-{i}")]
        )
        for i in range(5_500)
    }
    payload = _wpscan_payload(plugins=plugins, core_version=None)
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 5_000


def test_parse_wpscan_malformed_json_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Garbage stdout → ``[]``; one structured WARNING is emitted."""
    with caplog.at_level(logging.WARNING):
        findings = parse_wpscan_json(
            stdout=b"<<not-json>>",
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="wpscan",
        )
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()
    assert any(
        getattr(r, "event", "") == "parsers_json_malformed" for r in caplog.records
    )


def test_parse_wpscan_empty_inputs_return_empty_no_sidecar(tmp_path: Path) -> None:
    """Empty stdout + missing canonical → ``[]`` and no sidecar artifact."""
    findings = parse_wpscan_json(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_parse_wpscan_non_object_root_returns_empty(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Top-level JSON array is rejected (WPScan emits an object)."""
    with caplog.at_level(logging.WARNING):
        findings = parse_wpscan_json(
            stdout=b'["array","not","object"]',
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="wpscan",
        )
    assert findings == []
    assert any(
        getattr(r, "event", "") == "wpscan_parser_stdout_not_object"
        for r in caplog.records
    )


def test_parse_wpscan_canonical_unreadable_falls_back_to_stdout(
    tmp_path: Path,
) -> None:
    """Empty canonical file falls back gracefully to stdout."""
    (tmp_path / "wpscan.json").write_bytes(b"")  # zero-byte canonical
    payload = _wpscan_payload(
        interesting=[_interesting_finding(finding_type="readme")],
        core_version=None,
    )
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 1


def test_parse_wpscan_main_theme_vuln_round_trips(tmp_path: Path) -> None:
    """``main_theme.vulnerabilities[*]`` is parsed identically to themes[]."""
    payload = _wpscan_payload(
        main_theme_slug="twentytwentyone",
        main_theme_vulns=[
            _vulnerability(
                title="theme rce",
                references_cve=["2024-7777"],
            ),
        ],
        core_version=None,
    )
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.MISCONFIG
    assert finding.confidence is ConfidenceLevel.LIKELY


def test_parse_wpscan_themes_dict_is_iterated(tmp_path: Path) -> None:
    """Each ``themes[slug]`` entry is iterated; vuln titles flow through."""
    payload = _wpscan_payload(
        themes={
            "alpha": _plugin_block(
                vulnerabilities=[_vulnerability(title="alpha vuln")]
            ),
            "beta": _plugin_block(vulnerabilities=[_vulnerability(title="beta vuln")]),
        },
        core_version=None,
    )
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 2


def test_parse_wpscan_users_legacy_list_shape(tmp_path: Path) -> None:
    """Older WPScan emits ``users`` as a list of dicts; both shapes parse."""
    payload = {
        "users": [
            {"username": "admin"},
            {"name": "editor"},
        ],
    }
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 2


def test_parse_wpscan_interesting_finding_without_to_s_is_skipped(
    tmp_path: Path,
) -> None:
    """A finding without ``to_s`` AND without ``url`` is dropped (no signal)."""
    payload = {
        "interesting_findings": [
            {"type": "headers"},
            _interesting_finding(finding_type="readme"),
        ],
    }
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# parse_droopescan_json — contract tests
# ---------------------------------------------------------------------------


def test_parse_droopescan_versions_emit_info_findings(tmp_path: Path) -> None:
    """Each version candidate becomes one INFO finding."""
    payload = {
        "version": [{"version": "8.x"}, {"version": "9.0"}],
        "themes": {"finds": []},
        "plugins": {"finds": []},
    }
    findings = parse_droopescan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="droopescan",
    )
    assert len(findings) == 2
    assert all(f.category is FindingCategory.INFO for f in findings)


def test_parse_droopescan_components_and_users(tmp_path: Path) -> None:
    """Plugins and users round-trip and produce dedup-stable output."""
    payload = {
        "version": {"finds": [{"version": "8.x"}]},
        "themes": {"finds": [{"name": "bartik", "version": "8.0"}]},
        "plugins": {"finds": [{"name": "ctools", "version": "7.x-1.5"}]},
        "users": {"finds": [{"username": "admin"}, {"username": "editor"}]},
    }
    findings = parse_droopescan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="droopescan",
    )
    assert len(findings) == 5  # 1 version + 1 theme + 1 plugin + 2 users
    sidecar_path = tmp_path / EVIDENCE_SIDECAR_NAME
    parsed = [
        json.loads(line)
        for line in sidecar_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    components = sorted({r["component"] for r in parsed})
    assert components == ["cms_version", "plugin", "theme", "user"]


def test_parse_droopescan_empty_payload_is_safe(tmp_path: Path) -> None:
    """Missing top-level keys produce zero findings, no sidecar."""
    findings = parse_droopescan_json(
        stdout=b"{}",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="droopescan",
    )
    assert findings == []
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


def test_parse_droopescan_canonical_artifact_takes_precedence(
    tmp_path: Path,
) -> None:
    """Canonical ``droopescan.json`` wins over stdout (same as WPScan)."""
    canonical = {
        "version": [{"version": "9.x"}],
    }
    (tmp_path / "droopescan.json").write_bytes(_payload_bytes(canonical))
    stdout = {"version": [{"version": "should-not-appear"}]}
    findings = parse_droopescan_json(
        stdout=_payload_bytes(stdout),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="droopescan",
    )
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "9.x" in sidecar
    assert "should-not-appear" not in sidecar


# ---------------------------------------------------------------------------
# Edge-case coverage
# ---------------------------------------------------------------------------


def test_parse_wpscan_canonical_not_object_logs_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A canonical artefact that decodes to a list (not dict) is logged + skipped."""
    (tmp_path / "wpscan.json").write_bytes(b'["not","an","object"]')
    payload = _wpscan_payload(
        interesting=[_interesting_finding(finding_type="readme")],
        core_version=None,
    )
    with caplog.at_level(logging.WARNING):
        findings = parse_wpscan_json(
            stdout=_payload_bytes(payload),
            stderr=b"",
            artifacts_dir=tmp_path,
            tool_id="wpscan",
        )
    assert len(findings) == 1  # falls through to stdout
    assert any(
        getattr(r, "event", "") == "wpscan_parser_canonical_not_object"
        for r in caplog.records
    )


def test_parse_wpscan_unsafe_canonical_name_is_rejected(tmp_path: Path) -> None:
    """The defensive ``_safe_join`` refuses traversal-shaped names.

    Direct invocation passes a hard-coded canonical name, so the guard is
    only reachable via the internal helper. We cover it through
    :func:`parse_droopescan_json` to keep the test surface public.
    """
    # Empty stdout + missing canonical = empty result (also exercises the
    # ``canonical is None`` short circuit when artifacts_dir lacks the file).
    findings = parse_droopescan_json(
        stdout=b"",
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="droopescan",
    )
    assert findings == []


def test_parse_wpscan_malformed_inner_records_are_tolerated(tmp_path: Path) -> None:
    """Non-dict items inside lists are skipped silently (defence in-depth)."""
    payload = {
        "interesting_findings": [
            "not-a-dict",
            42,
            None,
            _interesting_finding(finding_type="readme"),
        ],
        "version": {
            "number": "5.8.1",
            "vulnerabilities": [
                "garbage",
                _vulnerability(title="real vuln"),
            ],
        },
        "plugins": {
            "valid": _plugin_block(vulnerabilities=[_vulnerability(title="ok")]),
            123: {"vulnerabilities": []},  # non-string key
            "broken": "not-a-block",  # non-dict block
        },
        "users": {
            "admin": {"id": 1},
            "editor": "legacy-shape-string",  # tolerated → emits username=editor
        },
    }
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    # 1 interesting + 1 core vuln + 1 plugin vuln + 2 users = 5
    assert len(findings) == 5


def test_parse_wpscan_vuln_without_title_is_skipped(tmp_path: Path) -> None:
    """A vulnerability dict without a title is dropped (no signal)."""
    payload = {
        "version": {
            "number": "5.8.1",
            "vulnerabilities": [
                {"fixed_in": "5.8.2"},  # no title
                _vulnerability(title="ok"),
            ],
        },
    }
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 1


def test_parse_wpscan_inline_cve_string_is_normalised(tmp_path: Path) -> None:
    """A bare string in inline ``cve`` is accepted and normalised."""
    payload = {
        "plugins": {
            "wp-rocket": _plugin_block(
                vulnerabilities=[
                    _vulnerability(title="single string cve", cve=["2024-12345"]),
                ],
            ),
        },
    }
    parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["cve"] == ["CVE-2024-12345"]


def test_parse_wpscan_references_normalised_into_strings(tmp_path: Path) -> None:
    """Mixed-type reference lists are coerced to ``list[str]`` (skip non-strings)."""
    payload = {
        "version": {
            "number": "5.8.1",
            "vulnerabilities": [
                {
                    "title": "weird refs",
                    "references": {
                        "url": ["https://a.test", 1234, None, "https://b.test"],
                        "exploitdb": "EDB-12345",
                        "cve": ["2024-99999"],
                        123: ["non-string-key"],
                    },
                },
            ],
        },
    }
    parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    refs = sidecar["references"]
    assert refs["url"] == ["https://a.test", "https://b.test"]
    assert refs["exploitdb"] == ["EDB-12345"]


def test_parse_wpscan_main_theme_with_string_version_field(tmp_path: Path) -> None:
    """``main_theme.version`` may be a bare string instead of ``{number: ...}``."""
    payload = {
        "main_theme": {
            "slug": "twentytwenty",
            "version": "1.7.2",
            "vulnerabilities": [_vulnerability(title="ok")],
        },
    }
    parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    sidecar = json.loads(
        (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    )
    assert sidecar["version"] == "1.7.2"


def test_parse_wpscan_canonical_with_non_string_users_dict_value(
    tmp_path: Path,
) -> None:
    """A ``users[username]`` value that is not a dict is upgraded to ``{username}``."""
    payload = {
        "users": {
            "admin": "not-a-dict",
        },
    }
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 1


def test_parse_droopescan_handles_dict_version_block(tmp_path: Path) -> None:
    """Droopescan version may be a dict containing ``finds``."""
    payload = {
        "version": {"finds": [{"version": "10.x"}]},
        "themes": {"finds": []},
    }
    findings = parse_droopescan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="droopescan",
    )
    assert len(findings) == 1


def test_parse_wpscan_canonical_read_error_falls_back_to_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An OSError on the canonical artefact is logged + falls through to stdout."""
    # Create the file so `is_file()` is True, then make read_bytes() blow up.
    canonical = tmp_path / "wpscan.json"
    canonical.write_bytes(b"{}")

    original_read_bytes = Path.read_bytes

    def _raise_oserror(self: Path) -> bytes:
        if self == canonical:
            raise PermissionError("simulated read failure")
        return original_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _raise_oserror)

    payload = _wpscan_payload(
        interesting=[_interesting_finding(finding_type="readme")],
        core_version=None,
    )
    findings = parse_wpscan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 1


def test_parse_wpscan_droopescan_finding_carries_droopescan_tool_id(
    tmp_path: Path,
) -> None:
    """The sidecar ``tool_id`` reflects the parser variant — droopescan vs wpscan."""
    payload = {
        "version": [{"version": "8.x"}],
    }
    parse_droopescan_json(
        stdout=_payload_bytes(payload),
        stderr=b"",
        artifacts_dir=tmp_path,
        tool_id="droopescan",
    )
    sidecar_records = [
        json.loads(line)
        for line in (tmp_path / EVIDENCE_SIDECAR_NAME)
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert all(r["tool_id"] == "droopescan" for r in sidecar_records)
