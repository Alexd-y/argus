"""Integration test: F-M03 parser dispatch coverage.

Pins that the four F-M03 tools are wired into the parser dispatch registry
so raw sandbox output routes to the right parser without a bespoke
``if/elif`` in a strategy handler:

* ``rustscan``    → :class:`ParseStrategy.XML_NMAP`   → ``parse_nmap_xml``
* ``curl``        → :class:`ParseStrategy.TEXT_LINES`  → ``parse_curl``
* ``commix``      → :class:`ParseStrategy.TEXT_LINES`  → ``parse_commix``
* ``kube_hunter`` → :class:`ParseStrategy.JSON_OBJECT` → ``parse_kube_hunter_json``

The suite exercises the *public* :func:`dispatch_parse` entry point (not the
parsers directly) so a regression that drops a registration — or points a
tool at the wrong strategy — fails loudly instead of silently degrading to
an ARG-020 heartbeat.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import pytest

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import (
    dispatch_parse,
    get_registered_tool_parsers,
    reset_registry,
)

_FM03_TOOL_IDS: Final[tuple[str, ...]] = (
    "rustscan",
    "curl",
    "commix",
    "kube_hunter",
)


@pytest.fixture(autouse=True)
def _restore_registry() -> Iterator[None]:
    yield
    reset_registry()


@pytest.mark.parametrize("tool_id", _FM03_TOOL_IDS)
def test_fm03_tool_is_registered(tool_id: str) -> None:
    """Every F-M03 tool must have a parser at import time."""
    assert tool_id in get_registered_tool_parsers(), (
        f"{tool_id} must be wired into _DEFAULT_TOOL_PARSERS so dispatch "
        f"routes it to a real parser instead of a heartbeat"
    )


# ---------------------------------------------------------------------------
# rustscan → XML_NMAP
# ---------------------------------------------------------------------------


_NMAP_XML: Final[str] = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<!DOCTYPE nmaprun>\n"
    '<nmaprun scanner="nmap" args="nmap -sC -sV -oX /out/rustscan.xml" '
    'start="1700000000" version="7.94" xmloutputversion="1.05">\n'
    '<host starttime="1700000010" endtime="1700000050">'
    '<status state="up" reason="syn-ack"/>'
    '<address addr="10.0.0.1" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="80">'
    '<state state="open"/>'
    '<service name="http" product="nginx" version="1.25.3"/>'
    "</port></ports></host>"
    '<runstats><finished time="1700000060"/></runstats>\n</nmaprun>\n'
)


def test_rustscan_routes_through_nmap_parser(tmp_path: Path) -> None:
    (tmp_path / "rustscan.xml").write_text(_NMAP_XML, encoding="utf-8")
    findings = dispatch_parse(
        ParseStrategy.XML_NMAP, b"", b"", tmp_path, tool_id="rustscan"
    )
    assert findings, "rustscan XML must yield at least the open-port finding"
    assert not _is_only_heartbeat(findings)


# ---------------------------------------------------------------------------
# curl → TEXT_LINES
# ---------------------------------------------------------------------------


def test_curl_routes_through_curl_parser(tmp_path: Path) -> None:
    stdout = b"HTTP/1.1 200 OK\nServer: nginx/1.18.0\n"
    findings = dispatch_parse(
        ParseStrategy.TEXT_LINES, stdout, b"", tmp_path, tool_id="curl"
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO


# ---------------------------------------------------------------------------
# commix → TEXT_LINES
# ---------------------------------------------------------------------------


def test_commix_routes_through_commix_parser(tmp_path: Path) -> None:
    stdout = (
        b"[+] The (GET) 'addr' parameter is vulnerable to (results-based) "
        b"command injection technique.\n"
    )
    findings = dispatch_parse(
        ParseStrategy.TEXT_LINES, stdout, b"", tmp_path, tool_id="commix"
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.CMDI


# ---------------------------------------------------------------------------
# kube_hunter → JSON_OBJECT
# ---------------------------------------------------------------------------


def test_kube_hunter_routes_through_kube_hunter_parser(tmp_path: Path) -> None:
    payload = {
        "nodes": [{"type": "Node", "location": "10.0.0.1"}],
        "services": [],
        "vulnerabilities": [
            {
                "vulnerability": "Exposed sensitive interfaces",
                "category": "Information Disclosure",
                "severity": "high",
                "location": "10.0.0.1:10250",
                "vid": "KHV005",
            }
        ],
    }
    stdout = json.dumps(payload).encode("utf-8")
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT, stdout, b"", tmp_path, tool_id="kube_hunter"
    )
    assert len(findings) == 1
    assert not _is_only_heartbeat(findings)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_only_heartbeat(findings: list) -> bool:
    """True when dispatch fell back to a single ARG-020 heartbeat."""
    return len(findings) == 1 and any(
        tag.startswith("HEARTBEAT-") for tag in findings[0].owasp_wstg
    )
