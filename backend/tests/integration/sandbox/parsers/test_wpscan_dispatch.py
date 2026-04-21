"""Integration test: wpscan / droopescan parser dispatch (Backlog/dev1_md §4.7).

Sister suite to ``test_katana_dispatch.py`` and ``test_ffuf_dispatch.py``;
this one pins the ARG-014 contract that the two JSON-emitting §4.7 CMS
scanners route through the per-tool registry to their dedicated parser
in :mod:`src.sandbox.parsers.wpscan_parser`:

* ``wpscan``     — ``--format json --output /out/wpscan.json`` envelope
  with ``interesting_findings`` / ``version`` / ``main_theme`` /
  ``themes`` / ``plugins`` / ``users``.
* ``droopescan`` — ``-o json`` envelope with ``version`` / ``themes`` /
  ``plugins`` / ``modules`` / ``users``. Lightweight info-only adapter.

Pinned invariants:

1.  Each tool_id is registered against ``ParseStrategy.JSON_OBJECT`` and
    routes to its dedicated parser (not the global JSON_OBJECT default
    used by the §4.5 ffuf-family).
2.  The shared evidence sidecar ``wpscan_findings.jsonl`` is emitted by
    every tool and stamps each record with its source ``tool_id``.
3.  The three §4.7 text-only tools (``joomscan``, ``cmsmap``,
    ``magescan``) have NO parser registration by design — pinned so a
    future silent move into ``_DEFAULT_TOOL_PARSERS`` lights up the diff
    in CI. The three §4.7 nuclei wrappers (``nextjs_check``,
    ``spring_boot_actuator``, ``jenkins_enum``) DO register against
    ``ParseStrategy.NUCLEI_JSONL`` since ARG-015 (covered by
    ``test_nuclei_dispatch.py``); they intentionally produce no
    findings when misrouted through JSON_OBJECT because the wpscan-
    shaped JSON does not contain nuclei records.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import pytest

from src.pipeline.contracts.finding_dto import (
    FindingCategory,
    FindingDTO,
)
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import (
    dispatch_parse,
    get_registered_tool_parsers,
    reset_registry,
)
from src.sandbox.parsers.wpscan_parser import EVIDENCE_SIDECAR_NAME


# ---------------------------------------------------------------------------
# Hermetic registry fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_registry() -> Iterator[None]:
    yield
    reset_registry()


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


# §4.7 tools that route through ``parse_*_json`` in
# :mod:`src.sandbox.parsers.wpscan_parser`. Hard-coded so a silent shrink
# breaks CI immediately.
CMS_JSON_TOOL_IDS: Final[tuple[str, ...]] = ("wpscan", "droopescan")


# §4.7 tools that emit *text* output (``parse_strategy=text_lines``) and
# therefore have NO JSON_OBJECT registration. Pinned explicitly.
TEXT_LINES_CMS_TOOL_IDS: Final[tuple[str, ...]] = (
    "joomscan",
    "cmsmap",
    "magescan",
)


# §4.7 tools that wrap nuclei templates (``parse_strategy=nuclei_jsonl``)
# and therefore have NO JSON_OBJECT registration. Their parser ships in
# ARG-015.
NUCLEI_CMS_TOOL_IDS: Final[tuple[str, ...]] = (
    "nextjs_check",
    "spring_boot_actuator",
    "jenkins_enum",
)


def _wpscan_payload() -> bytes:
    """Build a minimal but representative WPScan JSON payload."""
    return json.dumps(
        {
            "interesting_findings": [
                {
                    "type": "headers",
                    "to_s": "Server: Apache/2.4.41",
                    "url": "https://target.example/",
                },
            ],
            "version": {
                "number": "5.8.1",
                "vulnerabilities": [
                    {
                        "title": "WP Core 5.8.0 < 5.8.2 — auth bypass",
                        "fixed_in": "5.8.2",
                        "references": {"cve": ["2024-12345"]},
                    },
                ],
            },
            "plugins": {
                "akismet": {
                    "version": {"number": "4.0.0"},
                    "vulnerabilities": [
                        {
                            "title": "Akismet < 4.0.3 — XSS",
                            "fixed_in": "4.0.3",
                            "references": {"cve": ["2023-9999"]},
                        },
                    ],
                },
            },
            "users": {
                "admin": {"id": 1},
            },
        },
        sort_keys=True,
    ).encode("utf-8")


def _droopescan_payload() -> bytes:
    """Build a minimal but representative droopescan JSON payload."""
    return json.dumps(
        {
            "version": [{"version": "9.x"}],
            "plugins": {"finds": [{"name": "ctools", "version": "9.x-1.5"}]},
            "themes": {"finds": [{"name": "bartik", "version": "9.x"}]},
            "users": {"finds": [{"username": "admin"}]},
        },
        sort_keys=True,
    ).encode("utf-8")


def _build_stdout(tool_id: str) -> bytes:
    if tool_id == "wpscan":
        return _wpscan_payload()
    if tool_id == "droopescan":
        return _droopescan_payload()
    raise AssertionError(f"unknown tool_id={tool_id!r}")  # pragma: no cover


# ---------------------------------------------------------------------------
# Per-tool registration surface
# ---------------------------------------------------------------------------


def test_default_per_tool_registry_includes_all_cms_json_tools() -> None:
    """Every §4.7 JSON-emitting tool must be registered."""
    registered = get_registered_tool_parsers()
    for tool_id in CMS_JSON_TOOL_IDS:
        assert tool_id in registered, (
            f"{tool_id} missing from per-tool parser registry — broken "
            f"wiring in src.sandbox.parsers.__init__"
        )
    # Cross-batch coexistence: §4.4 + §4.5 + §4.6 wirings must survive ARG-014.
    for legacy in ("httpx", "ffuf_dir", "katana"):
        assert legacy in registered, f"{legacy} slot must survive ARG-014 registration"


# ---------------------------------------------------------------------------
# Routing — happy path for every JSON-emitting CMS scanner
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CMS_JSON_TOOL_IDS)
def test_dispatch_routes_each_cms_tool_to_wpscan_parser(
    tool_id: str, tmp_path: Path
) -> None:
    """Both §4.7 JSON tool_ids dispatch via JSON_OBJECT and produce findings."""
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _build_stdout(tool_id),
        b"",
        tmp_path / tool_id,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: dispatch produced no findings"
    assert all(isinstance(f, FindingDTO) for f in findings)


@pytest.mark.parametrize("tool_id", CMS_JSON_TOOL_IDS)
def test_dispatch_writes_shared_sidecar_with_correct_tool_id(
    tool_id: str, tmp_path: Path
) -> None:
    """Each CMS dispatch emits a per-finding sidecar tagged with the tool_id."""
    artifacts_dir = tmp_path / tool_id
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _build_stdout(tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings

    sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file(), (
        f"{tool_id}: wpscan parser family must write evidence sidecar at {sidecar}"
    )
    parsed = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(parsed) == len(findings)
    assert all(rec["tool_id"] == tool_id for rec in parsed), (
        f"{tool_id}: every sidecar record must tag its source tool_id"
    )


def test_wpscan_dispatch_attaches_misconfig_for_known_vulns(tmp_path: Path) -> None:
    """WPScan vulnerability records → at least one MISCONFIG-classified finding."""
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _wpscan_payload(),
        b"",
        tmp_path,
        tool_id="wpscan",
    )
    misconfig = [f for f in findings if f.category is FindingCategory.MISCONFIG]
    assert misconfig, "expected at least one MISCONFIG finding for WPScan vulns"
    assert all(1395 in f.cwe for f in misconfig)


def test_droopescan_dispatch_attaches_info_only_findings(tmp_path: Path) -> None:
    """Droopescan only emits INFO findings (no inline vuln metadata)."""
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _droopescan_payload(),
        b"",
        tmp_path,
        tool_id="droopescan",
    )
    assert findings
    assert all(f.category is FindingCategory.INFO for f in findings)


# ---------------------------------------------------------------------------
# Negative path — text_lines / nuclei_jsonl tools must not cross-wire
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", TEXT_LINES_CMS_TOOL_IDS)
def test_text_lines_cms_tools_have_no_json_object_parser(
    tool_id: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """text_lines §4.7 tools must NOT be reachable via JSON_OBJECT dispatch.

    A misrouted JSON_OBJECT dispatch fail-softs to the
    ``parsers.dispatch.unmapped_tool`` warning AND emits one ARG-020
    heartbeat finding so the orchestrator can distinguish "tool ran but
    parser deferred" from a silent skip.
    """
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = dispatch_parse(
            ParseStrategy.JSON_OBJECT,
            _wpscan_payload(),
            b"",
            tmp_path,
            tool_id=tool_id,
        )

    assert len(findings) == 1, (
        f"{tool_id}: expected exactly one heartbeat via JSON_OBJECT misroute, "
        f"got {len(findings)}"
    )
    heartbeat = findings[0]
    assert heartbeat.category is FindingCategory.INFO
    assert "ARGUS-HEARTBEAT" in heartbeat.owasp_wstg
    assert f"HEARTBEAT-{tool_id}" in heartbeat.owasp_wstg
    assert any(
        getattr(record, "event", "") == "parsers_dispatch_unmapped_tool"
        and getattr(record, "tool_id", None) == tool_id
        for record in caplog.records
    ), f"{tool_id}: missing parsers.dispatch.unmapped_tool warning"


@pytest.mark.parametrize("tool_id", NUCLEI_CMS_TOOL_IDS)
def test_nuclei_cms_tools_inert_when_misrouted_via_json_object(
    tool_id: str, tmp_path: Path
) -> None:
    """nuclei_jsonl §4.7 tools must produce no findings via JSON_OBJECT.

    Since ARG-015 the three nuclei wrappers ARE registered (against
    :class:`~src.sandbox.adapter_base.ParseStrategy.NUCLEI_JSONL`), so
    a misroute through JSON_OBJECT no longer triggers ``unmapped_tool``.
    Instead the shared :func:`parse_nuclei_jsonl` runs against the
    wpscan-shaped JSON object, finds no nuclei records, and returns ``[]``
    — keeping the misroute inert (defence-in-depth on top of the
    strategy-level registration check in ``test_nuclei_dispatch.py``).
    """
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _wpscan_payload(),
        b"",
        tmp_path,
        tool_id=tool_id,
    )

    assert findings == [], (
        f"{tool_id}: nuclei parser must yield no findings on wpscan-shaped JSON"
    )


@pytest.mark.parametrize("tool_id", NUCLEI_CMS_TOOL_IDS)
def test_nuclei_cms_wrappers_produce_findings_after_arg015(
    tool_id: str, tmp_path: Path
) -> None:
    """ARG-015 graduation: the 3 §4.7 nuclei wrappers now produce findings.

    Pre-ARG-015 these tool_ids were declared in YAML (cycle 2) but had no
    parser, so dispatch via NUCLEI_JSONL fail-softed with ``unmapped_tool``.
    ARG-015 wires them through :func:`parse_nuclei_jsonl`. This test pins
    the positive contract — every wrapper, run against a representative
    nuclei JSONL payload, must yield at least one FindingDTO and stamp
    its source ``tool_id`` onto every sidecar record so the three callers
    stay demultiplexable downstream.
    """
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    payload = (
        json.dumps(
            {
                "template-id": "tech-detect",
                "info": {
                    "name": "Tech detection",
                    "severity": "info",
                    "tags": ["tech"],
                },
                "host": "https://target.example",
                "matched-at": "https://target.example/",
                "matcher-status": True,
            },
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")

    findings = dispatch_parse(
        ParseStrategy.NUCLEI_JSONL,
        payload,
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )

    assert findings, (
        f"{tool_id}: ARG-015 should have wired this wrapper to parse_nuclei_jsonl"
    )
    sidecar = artifacts_dir / "nuclei_findings.jsonl"
    assert sidecar.is_file()
    parsed = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert all(rec["tool_id"] == tool_id for rec in parsed), (
        f"{tool_id}: sidecar records must carry the source tool_id"
    )


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_dispatch_is_deterministic_across_repeated_runs(tmp_path: Path) -> None:
    """Two dispatch calls on the same payload produce identical sidecars."""
    artifacts_a = tmp_path / "a"
    artifacts_b = tmp_path / "b"
    payload = _wpscan_payload()
    dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        payload,
        b"",
        artifacts_a,
        tool_id="wpscan",
    )
    dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        payload,
        b"",
        artifacts_b,
        tool_id="wpscan",
    )
    sidecar_a = (artifacts_a / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    sidecar_b = (artifacts_b / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert sidecar_a == sidecar_b
