"""Integration test: nmap XML_NMAP dispatch (Backlog/dev1_md §4.2 — ARG-019).

Sister suite to :mod:`tests.integration.sandbox.parsers.test_trivy_semgrep_dispatch`;
this one pins the ARG-019 contract that:

* All five §4.2 nmap callers (``nmap_tcp_full`` / ``nmap_tcp_top`` /
  ``nmap_udp`` / ``nmap_version`` / ``nmap_vuln``) route through
  :class:`~src.sandbox.adapter_base.ParseStrategy.XML_NMAP` to the
  shared :func:`src.sandbox.parsers.nmap_parser.parse_nmap_xml`.
* Each variant resolves its own per-tool canonical filename
  (``nmap_full.xml`` / ``nmap_tcp.xml`` / ``nmap_udp.xml`` /
  ``nmap_v.xml`` / ``nmap_vuln.xml``) so multiple variants depositing
  XML into the same artefacts directory never silently consume each
  other's output.
* The legacy ``nmap.xml`` filename remains available as a fallback for
  operator overrides + unit-test fixtures, but the per-tool name takes
  priority when both are present.
* The canonical ``nmap_findings.jsonl`` sidecar is produced for every
  variant and stamped with the source ``tool_id`` so downstream
  deduplication / correlation can demultiplex by tool without
  re-querying nmap.
* Cross-routing safety: a vulners-bearing payload routed under an
  unknown ``tool_id`` falls back to the legacy filename and stays
  inert when no recognisable XML is present (no shape-confusion
  attacks against the dispatch layer).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import (
    dispatch_parse,
    get_registered_tool_parsers,
    reset_registry,
)
from src.sandbox.parsers.nmap_parser import EVIDENCE_SIDECAR_NAME


# ---------------------------------------------------------------------------
# Hermetic registry fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_registry() -> Iterator[None]:
    yield
    reset_registry()


# ---------------------------------------------------------------------------
# Pinned per-tool canonical filenames (mirrors the YAML-declared ``-oX``
# output names).  Adding/removing a Nmap variant is intentionally a
# deliberate test edit — silent drift between the parser table and the
# YAML catalogue is exactly what this file exists to catch.
# ---------------------------------------------------------------------------


NMAP_TOOL_FILENAMES: Final[dict[str, str]] = {
    "nmap_tcp_full": "nmap_full.xml",
    "nmap_tcp_top": "nmap_tcp.xml",
    "nmap_udp": "nmap_udp.xml",
    "nmap_version": "nmap_v.xml",
    "nmap_vuln": "nmap_vuln.xml",
}

NMAP_TOOL_IDS: Final[tuple[str, ...]] = tuple(sorted(NMAP_TOOL_FILENAMES))


# ---------------------------------------------------------------------------
# Fixture builders — minimal Nmap XML envelope (one open port, optional
# vulners script).  Mirrors the unit-test fixtures in
# ``test_nmap_parser.py`` but kept self-contained so the dispatch suite
# stays runnable in isolation.
# ---------------------------------------------------------------------------


_HEADER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<!DOCTYPE nmaprun>\n"
    '<nmaprun scanner="nmap" args="nmap -sS -p- 10.0.0.1" '
    'start="1700000000" version="7.94" xmloutputversion="1.05">\n'
)
_FOOTER = '<runstats><finished time="1700000060"/></runstats>\n</nmaprun>\n'


def _open_port_xml(*, host: str = "10.0.0.1", port: int = 80) -> str:
    return (
        _HEADER
        + (
            '<host starttime="1700000010" endtime="1700000050">'
            '<status state="up" reason="syn-ack"/>'
            f'<address addr="{host}" addrtype="ipv4"/>'
            f'<ports><port protocol="tcp" portid="{port}">'
            '<state state="open"/>'
            '<service name="http" product="nginx" version="1.25.3"/>'
            "</port></ports>"
            "</host>"
        )
        + _FOOTER
    )


def _vulners_xml(*, host: str = "10.0.0.1", port: int = 80) -> str:
    """Single host + port + a vulners script row that maps to a CRITICAL CVE."""
    vulners_text = (
        "cpe:/a:apache:http_server:2.4.49:&#xa;"
        "&#x9;CVE-2021-41773&#x9;9.8&#x9;"
        "https://vulners.com/cve/CVE-2021-41773"
    )
    return (
        _HEADER
        + (
            '<host starttime="1700000010" endtime="1700000050">'
            '<status state="up" reason="syn-ack"/>'
            f'<address addr="{host}" addrtype="ipv4"/>'
            f'<ports><port protocol="tcp" portid="{port}">'
            '<state state="open"/>'
            '<service name="http" product="Apache"/>'
            f'<script id="vulners" output="{vulners_text}"/>'
            "</port></ports>"
            "</host>"
        )
        + _FOOTER
    )


def _read_sidecar(artifacts_dir: Path) -> list[dict[str, object]]:
    sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file(), f"sidecar {sidecar} missing"
    with sidecar.open("r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


# ---------------------------------------------------------------------------
# Registry — every §4.2 nmap caller must be registered against the
# shared parser at module-import time.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", NMAP_TOOL_IDS)
def test_every_nmap_variant_has_a_registered_parser(tool_id: str) -> None:
    """All five §4.2 nmap callers must route to a parser at startup."""
    registered = get_registered_tool_parsers()
    assert tool_id in registered, (
        f"{tool_id} must be wired into _DEFAULT_TOOL_PARSERS so the "
        f"dispatch layer routes XML_NMAP through parse_nmap_xml"
    )


# ---------------------------------------------------------------------------
# Routing — happy path per variant, per-tool canonical filename
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", NMAP_TOOL_IDS)
def test_dispatch_routes_each_nmap_variant_to_parser_via_per_tool_filename(
    tool_id: str, tmp_path: Path
) -> None:
    """Each Nmap variant resolves its YAML-declared canonical filename."""
    filename = NMAP_TOOL_FILENAMES[tool_id]
    (tmp_path / filename).write_text(_open_port_xml(), encoding="utf-8")

    findings = dispatch_parse(
        ParseStrategy.XML_NMAP,
        b"",
        b"",
        tmp_path,
        tool_id=tool_id,
    )

    assert findings, (
        f"{tool_id}: dispatch produced no findings from the canonical "
        f"artifact file at {filename}"
    )
    sidecar = _read_sidecar(tmp_path)
    assert all(rec["tool_id"] == tool_id for rec in sidecar), (
        f"{tool_id}: every sidecar record must tag its source tool_id"
    )


@pytest.mark.parametrize("tool_id", NMAP_TOOL_IDS)
def test_dispatch_falls_back_to_stdout_when_artifact_missing(
    tool_id: str, tmp_path: Path
) -> None:
    """No canonical artifact + non-empty stdout XML still parses."""
    payload = _open_port_xml().encode("utf-8")
    findings = dispatch_parse(
        ParseStrategy.XML_NMAP,
        payload,
        b"",
        tmp_path,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: stdout fallback must still produce findings"


# ---------------------------------------------------------------------------
# Cross-variant isolation — distinct filenames must never silently
# bleed into another variant's parse pass when a single artefacts mount
# holds the output of multiple Nmap runs.
# ---------------------------------------------------------------------------


def test_dispatch_isolates_variants_under_shared_artifacts_dir(
    tmp_path: Path,
) -> None:
    """``nmap_udp`` must not pick up ``nmap_full.xml`` left behind by ``nmap_tcp_full``.

    Walks every (writer, reader) ordered pair of distinct Nmap variants
    sharing one artefacts directory and asserts the reader either parses
    its own filename (when the writer wrote both) or falls through to
    ``[]`` (when only the writer's filename is present).  Defends against
    accidental cross-variant artefact pickup the same way the §4.15
    Trivy isolation test defends ``trivy_image`` from ``trivy_fs.json``.
    """
    failures: list[str] = []
    for writer in NMAP_TOOL_IDS:
        artifacts_dir = tmp_path / f"writer-{writer}"
        artifacts_dir.mkdir()
        (artifacts_dir / NMAP_TOOL_FILENAMES[writer]).write_text(
            _open_port_xml(host="10.0.0.42"), encoding="utf-8"
        )

        for reader in NMAP_TOOL_IDS:
            if reader == writer:
                continue
            findings = dispatch_parse(
                ParseStrategy.XML_NMAP,
                b"",
                b"",
                artifacts_dir,
                tool_id=reader,
            )
            if findings:
                failures.append(
                    f"reader={reader} silently consumed writer={writer}'s "
                    f"artefact ({NMAP_TOOL_FILENAMES[writer]})"
                )

    assert not failures, "cross-variant artefact bleed:\n" + "\n".join(failures)


def test_dispatch_legacy_filename_serves_as_fallback_for_known_variants(
    tmp_path: Path,
) -> None:
    """``nmap.xml`` (legacy) is consumed when the per-tool filename is missing."""
    (tmp_path / "nmap.xml").write_text(
        _open_port_xml(host="10.0.0.99"), encoding="utf-8"
    )

    findings = dispatch_parse(
        ParseStrategy.XML_NMAP,
        b"",
        b"",
        tmp_path,
        tool_id="nmap_version",
    )

    assert findings, (
        "nmap_version must fall back to the legacy ``nmap.xml`` filename "
        "when the per-tool ``nmap_v.xml`` is missing"
    )
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["host"] == "10.0.0.99"


def test_dispatch_per_tool_filename_takes_priority_over_legacy(
    tmp_path: Path,
) -> None:
    """The per-tool filename always wins over the legacy fallback."""
    (tmp_path / "nmap_full.xml").write_text(
        _open_port_xml(host="10.0.0.1"), encoding="utf-8"
    )
    (tmp_path / "nmap.xml").write_text(
        _open_port_xml(host="10.0.0.99"), encoding="utf-8"
    )

    findings = dispatch_parse(
        ParseStrategy.XML_NMAP,
        b"",
        b"",
        tmp_path,
        tool_id="nmap_tcp_full",
    )

    assert findings
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["host"] == "10.0.0.1", (
        "per-tool ``nmap_full.xml`` must beat legacy ``nmap.xml`` for nmap_tcp_full"
    )


# ---------------------------------------------------------------------------
# Vulners → SUPPLY_CHAIN classification routes through dispatch layer
# ---------------------------------------------------------------------------


def test_dispatch_routes_vulners_critical_to_supply_chain_likely(
    tmp_path: Path,
) -> None:
    """Critical CVE in vulners script output → SUPPLY_CHAIN, LIKELY confidence."""
    (tmp_path / NMAP_TOOL_FILENAMES["nmap_vuln"]).write_text(
        _vulners_xml(), encoding="utf-8"
    )
    findings = dispatch_parse(
        ParseStrategy.XML_NMAP,
        b"",
        b"",
        tmp_path,
        tool_id="nmap_vuln",
    )
    sca = [f for f in findings if f.category is FindingCategory.SUPPLY_CHAIN]
    assert sca, "expected at least one SUPPLY_CHAIN finding for the critical CVE"
    assert sca[0].confidence is ConfidenceLevel.LIKELY
    assert sca[0].cvss_v3_score == pytest.approx(9.8)


# ---------------------------------------------------------------------------
# Sidecar isolation — multiple Nmap variants in the same dir share
# the canonical ``nmap_findings.jsonl`` filename but stamp every
# record with the source ``tool_id`` so downstream consumers can
# demultiplex without re-running nmap.
# ---------------------------------------------------------------------------


def test_sequential_variants_share_sidecar_but_keep_tool_id(
    tmp_path: Path,
) -> None:
    """Two Nmap variants run sequentially in one dir overwrite the sidecar
    but each invocation always tags the records it produced.  Writers
    that need to keep history must rotate the sidecar themselves — this
    test pins that the dispatch layer does NOT silently merge records.
    """
    (tmp_path / NMAP_TOOL_FILENAMES["nmap_tcp_full"]).write_text(
        _open_port_xml(host="10.0.0.1", port=80), encoding="utf-8"
    )
    first = dispatch_parse(
        ParseStrategy.XML_NMAP,
        b"",
        b"",
        tmp_path,
        tool_id="nmap_tcp_full",
    )
    assert first
    sidecar_first = _read_sidecar(tmp_path)
    assert all(rec["tool_id"] == "nmap_tcp_full" for rec in sidecar_first)

    (tmp_path / NMAP_TOOL_FILENAMES["nmap_version"]).write_text(
        _open_port_xml(host="10.0.0.2", port=443), encoding="utf-8"
    )
    second = dispatch_parse(
        ParseStrategy.XML_NMAP,
        b"",
        b"",
        tmp_path,
        tool_id="nmap_version",
    )
    assert second
    sidecar_second = _read_sidecar(tmp_path)
    assert all(rec["tool_id"] == "nmap_version" for rec in sidecar_second)
    assert {rec["host"] for rec in sidecar_second} == {"10.0.0.2"}, (
        "second invocation overwrites the sidecar with its own records"
    )


# ---------------------------------------------------------------------------
# Cross-routing safety — empty / unparseable input + unknown tool_id
# ---------------------------------------------------------------------------


def test_dispatch_unknown_tool_id_emits_heartbeat_only(
    tmp_path: Path,
) -> None:
    """An unknown ``tool_id`` only emits the ARG-020 heartbeat, never a finding.

    Defends against accidental cross-tool artefact pickup when an
    unrelated tool_id is dispatched under XML_NMAP.  The parser must
    never autodiscover arbitrary ``*.xml`` files in the artefacts dir;
    the unmapped tool fail-soft path emits exactly one heartbeat
    finding and the per-tool ``parse_nmap_xml`` parser is never invoked.
    """
    (tmp_path / "nmap_full.xml").write_text(_open_port_xml(), encoding="utf-8")

    findings = dispatch_parse(
        ParseStrategy.XML_NMAP,
        b"",
        b"",
        tmp_path,
        tool_id="some_other_tool",
    )

    assert len(findings) == 1, (
        "an unknown tool_id must emit exactly one ARG-020 heartbeat finding "
        "and never consume per-tool nmap artefact files"
    )
    heartbeat = findings[0]
    assert heartbeat.category is FindingCategory.INFO
    assert "ARGUS-HEARTBEAT" in heartbeat.owasp_wstg
    assert "HEARTBEAT-some_other_tool" in heartbeat.owasp_wstg
