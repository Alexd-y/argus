"""Cycle 6 T05 — top-20 heartbeat tools now map to first-class parsers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import HEARTBEAT_TAG_PREFIX, dispatch_parse

_T05_FIXTURE_DIR = (
    Path(__file__).resolve().parents[3] / "fixtures" / "heartbeat" / "t05"
)

# Basenames on disk in the sandbox match discovery_text_parser._DISCOVERY_CANONICAL,
# not necessarily the golden fixture filename under fixtures/heartbeat/t05/.
_ARTIFACT_BASENAME_BY_TOOL: dict[str, str] = {
    "gobuster_dir": "gobuster.txt",
    "waybackurls": "wayback.txt",
}


def _assert_no_heartbeat(findings: list[Any], tool_id: str) -> None:
    for finding in findings:
        tags = list(finding.owasp_wstg or [])
        assert HEARTBEAT_TAG_PREFIX not in tags, (
            f"{tool_id}: parser must not emit ARG-020 heartbeat, got tags={tags!r}"
        )


@pytest.mark.parametrize(
    ("tool_id", "strategy", "fixture_relpath"),
    [
        ("gobuster_dir", ParseStrategy.TEXT_LINES, "gobuster_dir.txt"),
        ("gobuster_auth", ParseStrategy.TEXT_LINES, "gobuster_auth.txt"),
        ("paramspider", ParseStrategy.TEXT_LINES, "paramspider.txt"),
        ("hakrawler", ParseStrategy.TEXT_LINES, "hakrawler.txt"),
        ("waybackurls", ParseStrategy.TEXT_LINES, "waybackurls.txt"),
        ("linkfinder", ParseStrategy.TEXT_LINES, "linkfinder.txt"),
        ("subjs", ParseStrategy.TEXT_LINES, "subjs.txt"),
        ("secretfinder", ParseStrategy.TEXT_LINES, "secretfinder.txt"),
        ("kxss", ParseStrategy.TEXT_LINES, "kxss.txt"),
        ("joomscan", ParseStrategy.TEXT_LINES, "joomscan.txt"),
        ("cmsmap", ParseStrategy.TEXT_LINES, "cmsmap.txt"),
        ("magescan", ParseStrategy.TEXT_LINES, "magescan.json"),
        ("xsstrike", ParseStrategy.JSON_OBJECT, "xsstrike.json"),
        ("xsser", ParseStrategy.JSON_OBJECT, "xsser.json"),
        ("playwright_xss_verify", ParseStrategy.JSON_OBJECT, "playwright.json"),
        ("jsql", ParseStrategy.JSON_OBJECT, "jsql.json"),
        ("ghauri", ParseStrategy.TEXT_LINES, "ghauri.log"),
        ("tplmap", ParseStrategy.TEXT_LINES, "tplmap.txt"),
        ("nosqlmap", ParseStrategy.TEXT_LINES, "nosqlmap.txt"),
        ("arachni", ParseStrategy.TEXT_LINES, "arachni.afr"),
    ],
)
def test_t05_top20_dispatch_avoids_heartbeat_path(
    tmp_path: Path,
    tool_id: str,
    strategy: ParseStrategy,
    fixture_relpath: str,
) -> None:
    """Golden fixtures prove each T05 tool hits a real parser (not heartbeat)."""
    fixture_path = _T05_FIXTURE_DIR / fixture_relpath
    assert fixture_path.is_file(), f"missing fixture {fixture_path}"
    payload = fixture_path.read_bytes()
    if fixture_relpath.endswith((".txt", ".log", ".afr")):
        on_disk = _ARTIFACT_BASENAME_BY_TOOL.get(tool_id, fixture_path.name)
        (tmp_path / on_disk).write_bytes(payload)
        stdout = b""
    else:
        stdout = payload

    findings = dispatch_parse(strategy, stdout, b"", tmp_path, tool_id)
    _assert_no_heartbeat(findings, tool_id)
    assert findings, f"{tool_id}: expected ≥1 finding from golden fixture"


@pytest.mark.parametrize(
    "tool_id",
    [
        "gobuster_dir",
        "xsstrike",
        "jsql",
        "ghauri",
    ],
)
def test_t05_stdout_only_still_non_heartbeat(tmp_path: Path, tool_id: str) -> None:
    """Operators sometimes only have stdout (no canonical artifact yet)."""
    if tool_id == "gobuster_dir":
        strategy = ParseStrategy.TEXT_LINES
        stdout = b"/api (Status: 301)\n"
    elif tool_id == "xsstrike":
        strategy = ParseStrategy.JSON_OBJECT
        stdout = json.dumps(
            {"results": [{"url": "https://stdout-only.test", "param": "x"}]}
        ).encode()
    elif tool_id == "jsql":
        strategy = ParseStrategy.JSON_OBJECT
        stdout = json.dumps(
            {"url": "https://jsql.test", "database": "db1", "tables": ["t1"]}
        ).encode()
    else:
        strategy = ParseStrategy.TEXT_LINES
        stdout = b"[+] parameter id is vulnerable. sql injection found.\n"

    findings = dispatch_parse(strategy, stdout, b"", tmp_path, tool_id)
    _assert_no_heartbeat(findings, tool_id)
    assert findings
