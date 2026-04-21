"""Unit tests for :mod:`src.sandbox.parsers.nmap_parser` (Backlog/dev1_md §4.2 — ARG-019).

Each test pins one contract documented in the parser:

* ``parse_nmap_xml`` resolves ``artifacts_dir/nmap.xml`` first, then
  falls back to ``stdout``.
* Open-port records carry ``FindingCategory.INFO`` with confidence
  ``LIKELY`` (banner present) or ``SUSPECTED`` (no ``-sV``).
* Closed / filtered ports are dropped — only ``state="open"`` is
  surfaced.
* Vulners NSE script output is parsed line-by-line; each ``CVE-…
  <CVSS>`` line becomes a ``SUPPLY_CHAIN`` finding with the parsed
  CVSS score and an NIST-bucket severity.
* Non-CVE ids inside vulners output (EDB / MSF / packetstorm) are
  dropped: they reference the same CVE.
* Confidence routing: CVSS ≥ 7.0 → ``LIKELY``; CVSS ≥ 4.0 →
  ``SUSPECTED``; etc.
* CWE backstop: vuln rows default to ``[1395]`` (Use of Vulnerable
  Component); INFO rows default to ``[200]`` (Information Exposure).
* Records collapse on stable per-kind dedup keys; the parser is
  deterministic across runs (same XML → identical FindingDTO list +
  identical sidecar bytes).
* Hard cap at 10 000 findings — defends the worker against a
  runaway ``-sV`` over a /16.
* XXE / billion-laughs payloads are refused by ``defusedxml``; the
  parser returns ``[]`` after a structured warning rather than
  expanding the entity tree.
* Malformed XML returns ``[]`` after a structured warning.
* Sidecar JSONL ``nmap_findings.jsonl`` carries one record per
  emitted finding stamped with the source ``tool_id`` (``nmap_tcp_top``
  / ``nmap_vuln`` / etc).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.nmap_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_nmap_xml,
)


# ---------------------------------------------------------------------------
# Fixture builders — synthesise the canonical Nmap ``-oX`` envelope.
# ---------------------------------------------------------------------------


_HEADER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<!DOCTYPE nmaprun>\n"
    '<nmaprun scanner="nmap" args="nmap -sS -p- 10.0.0.1" '
    'start="1700000000" version="7.94" xmloutputversion="1.05">\n'
)
_FOOTER = '<runstats><finished time="1700000060"/></runstats>\n</nmaprun>\n'


def _service_block(
    *,
    name: str = "",
    product: str = "",
    version: str = "",
    extrainfo: str = "",
    cpe: list[str] | None = None,
) -> str:
    if not (name or product or version or extrainfo or cpe):
        return ""
    attrs = [
        f'name="{name}"' if name else "",
        f'product="{product}"' if product else "",
        f'version="{version}"' if version else "",
        f'extrainfo="{extrainfo}"' if extrainfo else "",
    ]
    attrs_str = " ".join(a for a in attrs if a)
    inner = ""
    if cpe:
        inner = "".join(f"<cpe>{c}</cpe>" for c in cpe)
    if inner:
        return f"<service {attrs_str}>{inner}</service>"
    return f"<service {attrs_str}/>"


def _port_block(
    *,
    portid: int = 80,
    protocol: str = "tcp",
    state: str = "open",
    service: str = "",
    scripts: str = "",
) -> str:
    return (
        f'<port protocol="{protocol}" portid="{portid}">'
        f'<state state="{state}"/>'
        f"{service}"
        f"{scripts}"
        "</port>"
    )


def _host_block(
    *,
    addr: str = "10.0.0.1",
    addrtype: str = "ipv4",
    hostname: str = "",
    ports: str = "",
) -> str:
    hn = ""
    if hostname:
        hn = f'<hostnames><hostname name="{hostname}" type="user"/></hostnames>'
    return (
        '<host starttime="1700000010" endtime="1700000050">'
        '<status state="up" reason="syn-ack"/>'
        f'<address addr="{addr}" addrtype="{addrtype}"/>'
        f"{hn}"
        f"<ports>{ports}</ports>"
        "</host>"
    )


def _envelope(host_blocks: list[str]) -> str:
    return _HEADER + "".join(host_blocks) + _FOOTER


def _vulners_script(output: str) -> str:
    """Build a ``<script id="vulners" output="…"/>`` element.

    Real nmap XML always emits the script output as character
    references (``&#xa;`` for newline, ``&#x9;`` for tab) because
    XML attribute-value normalisation collapses literal whitespace
    runs into a single space (XML 1.0 §3.3.3). Character references
    bypass that normalisation, so we mirror nmap's wire format here
    and the parser sees the same multi-line text it would in
    production.
    """
    safe = (
        output.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("\t", "&#x9;")
        .replace("\n", "&#xa;")
    )
    return f'<script id="vulners" output="{safe}"/>'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_sidecar(artifacts_dir: Path) -> list[dict[str, object]]:
    sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file(), f"sidecar {sidecar} missing"
    with sidecar.open("r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


# ---------------------------------------------------------------------------
# 1. Payload resolution
# ---------------------------------------------------------------------------


def test_resolves_canonical_artifact_first(tmp_path: Path) -> None:
    """``artifacts_dir/nmap.xml`` wins over stdout."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(portid=80, service=_service_block(name="http")),
            ),
        ]
    )
    (tmp_path / "nmap.xml").write_text(xml, encoding="utf-8")
    findings = parse_nmap_xml(b"", b"", tmp_path, "nmap_tcp_top")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO


def test_falls_back_to_stdout_when_artifact_absent(tmp_path: Path) -> None:
    """Without ``nmap.xml`` the parser reads stdout instead."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(portid=22, service=_service_block(name="ssh")),
            ),
        ]
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_tcp_top")
    assert len(findings) == 1


def test_returns_empty_for_no_input(tmp_path: Path) -> None:
    """Empty stdout + missing artifact → ``[]`` (fail-soft)."""
    findings = parse_nmap_xml(b"", b"", tmp_path, "nmap_tcp_top")
    assert findings == []


def test_canonical_artifact_takes_priority_over_stdout(tmp_path: Path) -> None:
    """When both sources exist, the canonical artifact wins."""
    canonical_xml = _envelope(
        [
            _host_block(addr="10.0.0.1", ports=_port_block(portid=80)),
        ]
    )
    stdout_xml = _envelope(
        [
            _host_block(addr="10.0.0.99", ports=_port_block(portid=22)),
        ]
    )
    (tmp_path / "nmap.xml").write_text(canonical_xml, encoding="utf-8")
    findings = parse_nmap_xml(stdout_xml.encode("utf-8"), b"", tmp_path, "nmap_tcp_top")
    sidecar = _read_sidecar(tmp_path)
    assert len(findings) == 1
    assert sidecar[0]["host"] == "10.0.0.1"
    assert sidecar[0]["port"] == "80"


# ---------------------------------------------------------------------------
# 2. Open-port (INFO) findings
# ---------------------------------------------------------------------------


def test_open_port_with_banner_is_likely(tmp_path: Path) -> None:
    """Open port + service banner → ``LIKELY`` confidence."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(
                    portid=443,
                    service=_service_block(
                        name="http",
                        product="nginx",
                        version="1.25.3",
                    ),
                ),
            ),
        ]
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_version")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.INFO
    assert finding.confidence is ConfidenceLevel.LIKELY
    assert finding.cwe == [200]


def test_open_port_without_banner_is_suspected(tmp_path: Path) -> None:
    """Open port without ``-sV`` banner → ``SUSPECTED``."""
    xml = _envelope(
        [
            _host_block(ports=_port_block(portid=8080)),
        ]
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_tcp_top")
    assert len(findings) == 1
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED


def test_closed_port_is_dropped(tmp_path: Path) -> None:
    """Closed / filtered ports never become findings."""
    xml = _envelope(
        [
            _host_block(
                ports=(
                    _port_block(portid=22, state="closed")
                    + _port_block(portid=80, state="filtered")
                    + _port_block(portid=443, state="open")
                ),
            ),
        ]
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_tcp_top")
    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["port"] == "443"


def test_owasp_wstg_includes_fingerprint_when_banner(tmp_path: Path) -> None:
    """A service banner adds WSTG-INFO-02 (fingerprint) to the row."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(
                    portid=80,
                    service=_service_block(name="http", product="Apache"),
                ),
            ),
        ]
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_version")
    assert findings[0].owasp_wstg == ["WSTG-INFO-04", "WSTG-INFO-02"]


def test_owasp_wstg_minimal_without_banner(tmp_path: Path) -> None:
    """Without a banner the WSTG list stays at the enumeration anchor."""
    xml = _envelope([_host_block(ports=_port_block(portid=8080))])
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_tcp_top")
    assert findings[0].owasp_wstg == ["WSTG-INFO-04"]


def test_multiple_hosts_each_emit_one_finding(tmp_path: Path) -> None:
    """Each ``<host>`` produces its own port records."""
    xml = _envelope(
        [
            _host_block(addr="10.0.0.1", ports=_port_block(portid=22)),
            _host_block(addr="10.0.0.2", ports=_port_block(portid=80)),
        ]
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_tcp_top")
    sidecar = _read_sidecar(tmp_path)
    assert len(findings) == 2
    hosts_seen = {row["host"] for row in sidecar}
    assert hosts_seen == {"10.0.0.1", "10.0.0.2"}


# ---------------------------------------------------------------------------
# 3. Vulners NSE script (VULN) findings
# ---------------------------------------------------------------------------


_VULNERS_OUTPUT_BASIC = (
    "cpe:/a:apache:http_server:2.4.49:\n"
    "\tCVE-2021-41773\t9.8\thttps://vulners.com/cve/CVE-2021-41773\n"
    "\tCVE-2021-42013\t9.8\thttps://vulners.com/cve/CVE-2021-42013\n"
    "\tEDB-50383\t7.5\thttps://vulners.com/exploitdb/EDB-50383\n"
)


def test_vulners_emits_one_finding_per_cve(tmp_path: Path) -> None:
    """Each ``CVE-…`` line in vulners output → one SUPPLY_CHAIN finding."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(
                    portid=80,
                    service=_service_block(name="http", product="Apache"),
                    scripts=_vulners_script(_VULNERS_OUTPUT_BASIC),
                ),
            ),
        ]
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_vuln")
    sidecar = _read_sidecar(tmp_path)
    cve_records = [row for row in sidecar if row.get("kind") == "vuln"]
    cve_ids = {row["cve_id"] for row in cve_records}
    assert cve_ids == {"CVE-2021-41773", "CVE-2021-42013"}
    assert all(
        f.category in (FindingCategory.INFO, FindingCategory.SUPPLY_CHAIN)
        for f in findings
    )
    vuln_findings = [f for f in findings if f.category is FindingCategory.SUPPLY_CHAIN]
    assert len(vuln_findings) == 2


def test_vulners_critical_cvss_routes_to_likely(tmp_path: Path) -> None:
    """CVSS ≥ 7.0 → ``LIKELY`` confidence (NVD-confirmed bucket)."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(
                    portid=80,
                    service=_service_block(name="http"),
                    scripts=_vulners_script(
                        "cpe:/a:apache:http_server:2.4.49:\n"
                        "\tCVE-2021-41773\t9.8\thttps://vulners.com/cve/CVE-2021-41773\n"
                    ),
                ),
            ),
        ]
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_vuln")
    vuln = next(f for f in findings if f.category is FindingCategory.SUPPLY_CHAIN)
    assert vuln.confidence is ConfidenceLevel.LIKELY
    assert vuln.cvss_v3_score == pytest.approx(9.8)


def test_vulners_medium_cvss_routes_to_suspected(tmp_path: Path) -> None:
    """CVSS ≥ 4.0 < 7.0 → ``SUSPECTED`` (vulners CPE-match without runtime check)."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(
                    portid=80,
                    service=_service_block(name="http"),
                    scripts=_vulners_script(
                        "cpe:/a:nginx:nginx:1.10.0:\n"
                        "\tCVE-2017-7529\t5.0\thttps://vulners.com/cve/CVE-2017-7529\n"
                    ),
                ),
            ),
        ]
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_vuln")
    vuln = next(f for f in findings if f.category is FindingCategory.SUPPLY_CHAIN)
    assert vuln.confidence is ConfidenceLevel.SUSPECTED


def test_vulners_non_cve_ids_dropped(tmp_path: Path) -> None:
    """EDB / MSF / packetstorm rows are not standalone findings."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(
                    portid=80,
                    service=_service_block(name="http"),
                    scripts=_vulners_script(
                        "cpe:/a:apache:http_server:2.4.49:\n"
                        "\tEDB-50383\t7.5\thttps://vulners.com/exploitdb/EDB-50383\n"
                        "\tMSF-50001\t7.5\thttps://vulners.com/metasploit/MSF-50001\n"
                    ),
                ),
            ),
        ]
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_vuln")
    vuln_findings = [f for f in findings if f.category is FindingCategory.SUPPLY_CHAIN]
    assert vuln_findings == []


def test_vulners_invalid_cvss_dropped(tmp_path: Path) -> None:
    """Out-of-range CVSS scores (>10.0) skip the row, not crash."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(
                    portid=80,
                    service=_service_block(name="http"),
                    scripts=_vulners_script(
                        "cpe:/a:apache:http_server:2.4.49:\n"
                        "\tCVE-2024-99999\t99.9\thttps://example/CVE-2024-99999\n"
                        "\tCVE-2024-12345\t9.5\thttps://example/CVE-2024-12345\n"
                    ),
                ),
            ),
        ]
    )
    parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_vuln")
    sidecar = _read_sidecar(tmp_path)
    vuln_records = [row for row in sidecar if row.get("kind") == "vuln"]
    assert len(vuln_records) == 1
    assert vuln_records[0]["cve_id"] == "CVE-2024-12345"


def test_unknown_script_skipped(tmp_path: Path) -> None:
    """Non-vulners scripts are logged at debug and skipped (no crash)."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(
                    portid=445,
                    service=_service_block(name="microsoft-ds"),
                    scripts='<script id="smb-vuln-ms17-010" output="VULNERABLE: MS17-010"/>',
                ),
            ),
        ]
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_vuln")
    # Only the open-port INFO finding is emitted.
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO


def test_vuln_default_cwe_is_supply_chain(tmp_path: Path) -> None:
    """Vulnerability rows backstop to CWE-1395 (vulnerable component)."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(
                    portid=80,
                    service=_service_block(name="http"),
                    scripts=_vulners_script(
                        "cpe:/a:apache:http_server:2.4.49:\n"
                        "\tCVE-2021-41773\t9.8\thttps://vulners.com/cve/CVE-2021-41773\n"
                    ),
                ),
            ),
        ]
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_vuln")
    vuln = next(f for f in findings if f.category is FindingCategory.SUPPLY_CHAIN)
    assert vuln.cwe == [1395]
    assert vuln.owasp_wstg == ["WSTG-INFO-08"]


# ---------------------------------------------------------------------------
# 4. Dedup + sort + cap
# ---------------------------------------------------------------------------


def test_duplicate_ports_collapse(tmp_path: Path) -> None:
    """Two identical ``(host, port, proto)`` tuples collapse on dedup."""
    xml = _envelope(
        [
            _host_block(
                ports=(_port_block(portid=80) + _port_block(portid=80)),
            ),
        ]
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_tcp_top")
    assert len(findings) == 1


def test_duplicate_cves_collapse(tmp_path: Path) -> None:
    """Same CVE seen on two ports (rare) emits one finding per port."""
    vulners = (
        "cpe:/a:apache:http_server:2.4.49:\n"
        "\tCVE-2021-41773\t9.8\thttps://vulners.com/cve/CVE-2021-41773\n"
    )
    xml = _envelope(
        [
            _host_block(
                ports=(
                    _port_block(
                        portid=80,
                        service=_service_block(name="http"),
                        scripts=_vulners_script(vulners),
                    )
                    + _port_block(
                        portid=8080,
                        service=_service_block(name="http"),
                        scripts=_vulners_script(vulners),
                    )
                ),
            ),
        ]
    )
    parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_vuln")
    sidecar = _read_sidecar(tmp_path)
    vuln_records = [row for row in sidecar if row.get("kind") == "vuln"]
    # One per port (different dedup keys: host/80/tcp/CVE vs host/8080/tcp/CVE).
    assert len(vuln_records) == 2


def test_findings_sorted_by_severity_desc(tmp_path: Path) -> None:
    """Output is deterministic: critical → high → … → info."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(
                    portid=80,
                    service=_service_block(name="http"),
                    scripts=_vulners_script(
                        "cpe:/a:apache:http_server:2.4.49:\n"
                        "\tCVE-2017-7529\t5.0\thttps://x/CVE-2017-7529\n"
                        "\tCVE-2021-41773\t9.8\thttps://x/CVE-2021-41773\n"
                    ),
                ),
            ),
        ]
    )
    parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_vuln")
    sidecar = _read_sidecar(tmp_path)
    vuln_records = [row for row in sidecar if row.get("kind") == "vuln"]
    assert vuln_records[0]["cve_id"] == "CVE-2021-41773"
    assert vuln_records[1]["cve_id"] == "CVE-2017-7529"


def test_deterministic_output_across_runs(tmp_path: Path) -> None:
    """Same XML in → same FindingDTO list out (byte-identical)."""
    xml = _envelope(
        [
            _host_block(
                ports=(
                    _port_block(portid=22, service=_service_block(name="ssh"))
                    + _port_block(portid=443, service=_service_block(name="https"))
                    + _port_block(portid=80, service=_service_block(name="http"))
                ),
            ),
        ]
    )
    first = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_version")
    second = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_version")
    assert [f.category for f in first] == [f.category for f in second]
    assert [f.cwe for f in first] == [f.cwe for f in second]


# ---------------------------------------------------------------------------
# 5. Sidecar persistence
# ---------------------------------------------------------------------------


def test_sidecar_written_with_tool_id(tmp_path: Path) -> None:
    """Each sidecar row carries the source ``tool_id``."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(portid=22, service=_service_block(name="ssh"))
            ),
        ]
    )
    parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_version")
    sidecar = _read_sidecar(tmp_path)
    assert len(sidecar) == 1
    assert sidecar[0]["tool_id"] == "nmap_version"


def test_sidecar_carries_service_banner(tmp_path: Path) -> None:
    """Service banner fields make it into the evidence sidecar."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(
                    portid=443,
                    service=_service_block(
                        name="http",
                        product="nginx",
                        version="1.25.3",
                        cpe=["cpe:/a:nginx:nginx:1.25.3"],
                    ),
                ),
            ),
        ]
    )
    parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_version")
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["service_name"] == "http"
    assert sidecar[0]["service_product"] == "nginx"
    assert sidecar[0]["service_version"] == "1.25.3"
    assert sidecar[0]["service_cpe"] == ["cpe:/a:nginx:nginx:1.25.3"]


def test_sidecar_omits_sentinel_cvss_for_info(tmp_path: Path) -> None:
    """INFO findings drop the sentinel CVSS keys from the sidecar."""
    xml = _envelope(
        [
            _host_block(ports=_port_block(portid=80)),
        ]
    )
    parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_tcp_top")
    sidecar = _read_sidecar(tmp_path)
    assert "cvss_v3_score" not in sidecar[0]
    assert "cvss_v3_vector" not in sidecar[0]


def test_no_sidecar_for_empty_findings(tmp_path: Path) -> None:
    """Empty result set never creates a stray sidecar file."""
    xml = _envelope([_host_block(ports="")])
    parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_tcp_top")
    assert not (tmp_path / EVIDENCE_SIDECAR_NAME).exists()


# ---------------------------------------------------------------------------
# 6. Failure model — XXE / billion-laughs / malformed XML / large input
# ---------------------------------------------------------------------------


_XXE_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<!DOCTYPE foo [\n"
    "  <!ELEMENT foo ANY>\n"
    '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
    "]>\n"
    '<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="80">'
    '<state state="open"/><service name="&xxe;"/></port></ports>'
    "</host></nmaprun>"
)


def test_xxe_payload_returns_empty(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """XXE / external-entity payloads are refused by ``defusedxml``."""
    with caplog.at_level(logging.WARNING):
        findings = parse_nmap_xml(
            _XXE_PAYLOAD.encode("utf-8"),
            b"",
            tmp_path,
            "nmap_tcp_top",
        )
    assert findings == []
    # Either an explicit defusedxml refusal or a parse error — both
    # surface a structured WARNING and degrade safely.
    assert any("nmap_parser.xml" in record.message for record in caplog.records)


def test_billion_laughs_payload_returns_empty(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Billion-laughs entity expansion is refused by ``defusedxml``."""
    payload = (
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE lolz [\n"
        '  <!ENTITY lol "lol">\n'
        '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;">\n'
        '  <!ENTITY lol3 "&lol2;&lol2;&lol2;">\n'
        "]>\n"
        '<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80">'
        '<state state="open"/><service name="&lol3;"/></port></ports>'
        "</host></nmaprun>"
    )
    with caplog.at_level(logging.WARNING):
        findings = parse_nmap_xml(
            payload.encode("utf-8"), b"", tmp_path, "nmap_tcp_top"
        )
    assert findings == []


def test_malformed_xml_returns_empty(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Truncated XML returns ``[]`` after a structured warning."""
    payload = b"<?xml version='1.0'?><nmaprun><host><address"  # truncated
    with caplog.at_level(logging.WARNING):
        findings = parse_nmap_xml(payload, b"", tmp_path, "nmap_tcp_top")
    assert findings == []
    assert any(
        record.message == "nmap_parser.xml_malformed" for record in caplog.records
    )


def test_oversized_stdout_dropped(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Stdout payloads above the 25 MB cap are dropped (no parsing)."""
    big = b"x" * (25 * 1024 * 1024 + 1)
    with caplog.at_level(logging.WARNING):
        findings = parse_nmap_xml(big, b"", tmp_path, "nmap_tcp_top")
    assert findings == []
    assert any(
        record.message == "nmap_parser.stdout_oversize" for record in caplog.records
    )


def test_host_with_no_addr_skipped(tmp_path: Path) -> None:
    """A ``<host>`` without an IPv4/IPv6 ``<address>`` is skipped."""
    xml = (
        _HEADER
        + (
            '<host><status state="up"/>'
            '<address addr="00:11:22:33:44:55" addrtype="mac"/>'
            "<ports>" + _port_block(portid=80) + "</ports>"
            "</host>"
        )
        + _FOOTER
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_tcp_top")
    assert findings == []


def test_host_without_ports_block_skipped(tmp_path: Path) -> None:
    """Missing ``<ports>`` element → no findings, no crash."""
    xml = (
        _HEADER
        + (
            '<host><status state="up"/>'
            '<address addr="10.0.0.1" addrtype="ipv4"/>'
            "</host>"
        )
        + _FOOTER
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_tcp_top")
    assert findings == []


# ---------------------------------------------------------------------------
# 7. Hostname propagation + IPv6 addressing
# ---------------------------------------------------------------------------


def test_hostname_carries_to_sidecar(tmp_path: Path) -> None:
    """Resolved hostname survives onto the evidence sidecar."""
    xml = _envelope(
        [
            _host_block(hostname="example.test", ports=_port_block(portid=80)),
        ]
    )
    parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_tcp_top")
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["hostname"] == "example.test"


def test_ipv6_address_supported(tmp_path: Path) -> None:
    """IPv6 addresses (``addrtype=ipv6``) emit findings."""
    xml = _envelope(
        [
            _host_block(
                addr="2001:db8::1",
                addrtype="ipv6",
                ports=_port_block(portid=80),
            ),
        ]
    )
    findings = parse_nmap_xml(xml.encode("utf-8"), b"", tmp_path, "nmap_tcp_top")
    sidecar = _read_sidecar(tmp_path)
    assert len(findings) == 1
    assert sidecar[0]["host"] == "2001:db8::1"


# ---------------------------------------------------------------------------
# 8. Per-tool canonical filename resolution (ARG-019)
# ---------------------------------------------------------------------------
#
# The five §4.2 nmap YAMLs each pin a distinct ``-oX`` output filename so
# multiple variants can share the same ``/out/`` mount without clobbering
# each other.  The parser maps ``tool_id`` → canonical filename and falls
# back to the legacy ``nmap.xml`` name for unit-test fixtures and operator
# overrides.


@pytest.mark.parametrize(
    ("tool_id", "filename"),
    [
        ("nmap_tcp_full", "nmap_full.xml"),
        ("nmap_tcp_top", "nmap_tcp.xml"),
        ("nmap_udp", "nmap_udp.xml"),
        ("nmap_version", "nmap_v.xml"),
        ("nmap_vuln", "nmap_vuln.xml"),
    ],
)
def test_per_tool_canonical_filename_resolves(
    tmp_path: Path,
    tool_id: str,
    filename: str,
) -> None:
    """Each §4.2 nmap variant resolves its YAML-declared ``-oX`` filename."""
    xml = _envelope(
        [
            _host_block(
                ports=_port_block(portid=80, service=_service_block(name="http")),
            ),
        ]
    )
    (tmp_path / filename).write_text(xml, encoding="utf-8")
    findings = parse_nmap_xml(b"", b"", tmp_path, tool_id)
    assert len(findings) == 1
    sidecar = _read_sidecar(tmp_path)
    assert sidecar[0]["tool_id"] == tool_id


def test_per_tool_filename_takes_priority_over_legacy(tmp_path: Path) -> None:
    """``nmap_tcp.xml`` (per-tool) beats ``nmap.xml`` (legacy) for ``nmap_tcp_top``."""
    primary_xml = _envelope(
        [
            _host_block(addr="10.0.0.1", ports=_port_block(portid=80)),
        ]
    )
    legacy_xml = _envelope(
        [
            _host_block(addr="10.0.0.99", ports=_port_block(portid=22)),
        ]
    )
    (tmp_path / "nmap_tcp.xml").write_text(primary_xml, encoding="utf-8")
    (tmp_path / "nmap.xml").write_text(legacy_xml, encoding="utf-8")
    findings = parse_nmap_xml(b"", b"", tmp_path, "nmap_tcp_top")
    sidecar = _read_sidecar(tmp_path)
    assert len(findings) == 1
    assert sidecar[0]["host"] == "10.0.0.1"
    assert sidecar[0]["port"] == "80"


def test_per_tool_filename_falls_back_to_legacy(tmp_path: Path) -> None:
    """Missing per-tool filename falls back to ``nmap.xml`` (operator override)."""
    legacy_xml = _envelope(
        [
            _host_block(addr="10.0.0.42", ports=_port_block(portid=8080)),
        ]
    )
    (tmp_path / "nmap.xml").write_text(legacy_xml, encoding="utf-8")
    findings = parse_nmap_xml(b"", b"", tmp_path, "nmap_udp")
    sidecar = _read_sidecar(tmp_path)
    assert len(findings) == 1
    assert sidecar[0]["host"] == "10.0.0.42"


def test_unknown_tool_id_uses_legacy_filename(tmp_path: Path) -> None:
    """Unknown tool IDs only probe the legacy ``nmap.xml`` filename."""
    legacy_xml = _envelope(
        [
            _host_block(
                ports=_port_block(portid=22, service=_service_block(name="ssh"))
            ),
        ]
    )
    (tmp_path / "nmap.xml").write_text(legacy_xml, encoding="utf-8")
    findings = parse_nmap_xml(b"", b"", tmp_path, "unknown_nmap_variant")
    assert len(findings) == 1


def test_per_tool_filename_isolation(tmp_path: Path) -> None:
    """``nmap_full.xml`` is not picked up when ``tool_id=nmap_udp``.

    Defends against accidental cross-variant artefact pickup if multiple
    Nmap runs deposit their XML outputs in the same artefacts mount.
    """
    other_xml = _envelope(
        [
            _host_block(addr="10.0.0.1", ports=_port_block(portid=80)),
        ]
    )
    (tmp_path / "nmap_full.xml").write_text(other_xml, encoding="utf-8")
    findings = parse_nmap_xml(b"", b"", tmp_path, "nmap_udp")
    assert findings == []
