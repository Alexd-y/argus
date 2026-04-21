"""Integration test: katana / gospider / gau parser dispatch (Backlog/dev1_md §4.6).

Sister suite to ``test_ffuf_dispatch.py`` and ``test_dispatch_registry.py``;
this one pins the ARG-013 contract that the three JSON-emitting §4.6
crawlers route through the per-tool registry to their dedicated parser
in :mod:`src.sandbox.parsers.katana_parser`:

* ``katana``   — native ``-jsonl`` output (one request per line).
* ``gospider`` — ``--json`` output; shape adapter in the parser collapses
  gospider's ``output`` / ``stat`` onto katana's canonical
  ``request.endpoint`` / ``response.status_code``.
* ``gau``      — ``--json`` output: minimal ``{"url": "..."}`` per
  archived URL.

Pinned invariants:

1.  Each tool_id is registered against ``ParseStrategy.JSON_LINES`` and
    routes to its dedicated parser (not the global JSON_LINES default).
2.  Findings carry CWE-200 + WSTG-INFO-06/07 hints regardless of which
    tool_id triggered the dispatch.
3.  The shared evidence sidecar (``katana_findings.jsonl``) is emitted
    by every tool and stamps each record with its source ``tool_id``.
4.  The five §4.6 text-only tools (``hakrawler``, ``waybackurls``,
    ``linkfinder``, ``subjs``, ``secretfinder``) have NO JSON_LINES
    registration by design — pinned here so a future silent move into
    ``_DEFAULT_TOOL_PARSERS`` lights up the diff in CI.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import (
    dispatch_parse,
    get_registered_tool_parsers,
    reset_registry,
)
from src.sandbox.parsers.katana_parser import EVIDENCE_SIDECAR_NAME


# ---------------------------------------------------------------------------
# Hermetic registry fixture — every test starts from the default surface.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_registry() -> Iterator[None]:
    """Reset both strategy and per-tool registries around every test."""
    yield
    reset_registry()


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


# §4.6 tools that route through ``parse_*_jsonl`` in
# :mod:`src.sandbox.parsers.katana_parser`. Hard-coded so a silent shrink
# (or expansion without parser updates) breaks CI immediately.
CRAWLER_JSON_TOOL_IDS: Final[tuple[str, ...]] = ("katana", "gospider", "gau")


# §4.6 tools that emit *text* output (``parse_strategy=text_lines``) and
# therefore have NO JSON_LINES registration in the per-tool table. Pinned
# explicitly so the day a text_lines parser ships and these slots silently
# move into ``_DEFAULT_TOOL_PARSERS`` (or, worse, get cross-wired into
# JSON_LINES) the diff lights up in CI immediately.
TEXT_LINES_CRAWLER_TOOL_IDS: Final[tuple[str, ...]] = (
    "hakrawler",
    "waybackurls",
    "linkfinder",
    "subjs",
    "secretfinder",
)


def _katana_record(endpoint: str, *, method: str = "GET", status: int = 200) -> bytes:
    """Build a single katana JSONL line."""
    return json.dumps(
        {
            "request": {"endpoint": endpoint, "method": method, "tag": "form"},
            "response": {"status_code": status, "content_length": 1234},
        },
        sort_keys=True,
    ).encode("utf-8")


def _gospider_record(output: str, *, status: str = "200") -> bytes:
    """Build a single gospider JSONL line."""
    return json.dumps(
        {
            "output": output,
            "url": "https://target.example",
            "source": "scan",
            "type": "url",
            "stat": status,
        },
        sort_keys=True,
    ).encode("utf-8")


def _gau_record(url: str) -> bytes:
    """Build a single gau JSONL line (minimal shape)."""
    return json.dumps({"url": url}, sort_keys=True).encode("utf-8")


def _build_stdout(tool_id: str, urls: list[str]) -> bytes:
    """Build a per-tool JSONL stdout payload covering the supplied URLs."""
    if tool_id == "katana":
        lines = [_katana_record(url) for url in urls]
    elif tool_id == "gospider":
        lines = [_gospider_record(url) for url in urls]
    elif tool_id == "gau":
        lines = [_gau_record(url) for url in urls]
    else:  # pragma: no cover - defensive
        raise AssertionError(f"unknown tool_id={tool_id!r}")
    return b"\n".join(lines)


# ---------------------------------------------------------------------------
# Per-tool registration surface
# ---------------------------------------------------------------------------


def test_default_per_tool_registry_includes_all_crawler_json_tools() -> None:
    """Every §4.6 JSON-emitting tool must be registered."""
    registered = get_registered_tool_parsers()
    for tool_id in CRAWLER_JSON_TOOL_IDS:
        assert tool_id in registered, (
            f"{tool_id} missing from per-tool parser registry — broken "
            f"wiring in src.sandbox.parsers.__init__"
        )
    # Cross-batch coexistence: §4.4 + §4.5 wirings must survive ARG-013.
    for legacy in ("httpx", "ffuf_dir"):
        assert legacy in registered, f"{legacy} slot must survive ARG-013 registration"


# ---------------------------------------------------------------------------
# Routing — happy path for every member of the family
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CRAWLER_JSON_TOOL_IDS)
def test_dispatch_routes_each_crawler_tool_to_katana_parser(
    tool_id: str, tmp_path: Path
) -> None:
    """Same URL set routed via every JSON-crawler tool_id yields three findings."""
    urls = [
        "https://target.example/admin",
        "https://target.example/api/v1",
        "https://target.example/login",
    ]
    stdout = _build_stdout(tool_id, urls)

    artifacts_dir = tmp_path / tool_id
    findings = dispatch_parse(
        ParseStrategy.JSON_LINES,
        stdout,
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )

    assert len(findings) == 3, f"{tool_id}: expected 3 findings, got {len(findings)}"
    assert all(isinstance(f, FindingDTO) for f in findings)
    assert all(f.category is FindingCategory.INFO for f in findings)
    assert all(f.cwe == [200] for f in findings), (
        f"{tool_id}: every finding must carry CWE-200 (Information Exposure)"
    )
    assert all(f.confidence == ConfidenceLevel.SUSPECTED for f in findings)


@pytest.mark.parametrize("tool_id", CRAWLER_JSON_TOOL_IDS)
def test_dispatch_writes_shared_sidecar_with_correct_tool_id(
    tool_id: str, tmp_path: Path
) -> None:
    """Every crawler tool_id triggers the shared ``katana_findings.jsonl``."""
    urls = ["https://target/x", "https://target/y"]
    stdout = _build_stdout(tool_id, urls)

    artifacts_dir = tmp_path / tool_id
    findings = dispatch_parse(
        ParseStrategy.JSON_LINES,
        stdout,
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )

    assert len(findings) == 2
    sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file(), (
        f"{tool_id}: katana parser family must write evidence sidecar at {sidecar}"
    )
    lines = [line for line in sidecar.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert {rec["endpoint"] for rec in parsed} == {
        "https://target/x",
        "https://target/y",
    }
    assert all(rec["tool_id"] == tool_id for rec in parsed), (
        f"{tool_id}: every sidecar record must tag its source tool_id"
    )


@pytest.mark.parametrize("tool_id", CRAWLER_JSON_TOOL_IDS)
def test_dispatch_attaches_consistent_owasp_wstg_hints(
    tool_id: str, tmp_path: Path
) -> None:
    """All §4.6 JSON tools share the WSTG-INFO-06/07 hint set."""
    stdout = _build_stdout(tool_id, ["https://target/page"])
    findings = dispatch_parse(
        ParseStrategy.JSON_LINES,
        stdout,
        b"",
        tmp_path,
        tool_id=tool_id,
    )
    assert len(findings) == 1
    assert findings[0].owasp_wstg == ["WSTG-INFO-06", "WSTG-INFO-07"]


# ---------------------------------------------------------------------------
# Negative path — text_lines tools must not cross-wire into JSON_LINES
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", TEXT_LINES_CRAWLER_TOOL_IDS)
def test_text_lines_crawlers_have_no_json_lines_parser(
    tool_id: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """``hakrawler``/``waybackurls``/``linkfinder``/``subjs``/``secretfinder``
    use ``parse_strategy=text_lines`` and MUST NOT be registered against
    ``ParseStrategy.JSON_LINES``.

    A JSON_LINES dispatch with one of these tool_ids must therefore
    fall through to the ``parsers.dispatch.unmapped_tool`` structured
    warning AND emit one ARG-020 heartbeat finding (so the orchestrator
    can distinguish "tool ran but parser deferred" from a silent skip).
    """
    stdout = _katana_record("https://target/")

    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = dispatch_parse(
            ParseStrategy.JSON_LINES,
            stdout,
            b"",
            tmp_path,
            tool_id=tool_id,
        )

    assert len(findings) == 1, (
        f"{tool_id}: expected exactly one heartbeat via JSON_LINES dispatch, "
        f"got {len(findings)} findings"
    )
    heartbeat = findings[0]
    assert heartbeat.category is FindingCategory.INFO
    assert "ARGUS-HEARTBEAT" in heartbeat.owasp_wstg
    assert f"HEARTBEAT-{tool_id}" in heartbeat.owasp_wstg
    assert any(
        (
            "parsers.dispatch.unmapped_tool" in record.getMessage()
            or getattr(record, "event", "") == "parsers_dispatch_unmapped_tool"
        )
        and getattr(record, "tool_id", None) == tool_id
        for record in caplog.records
    ), (
        f"{tool_id}: missing parsers.dispatch.unmapped_tool warning; "
        f"got {[r.getMessage() for r in caplog.records]}"
    )


# ---------------------------------------------------------------------------
# Determinism — three dispatches against three tool_ids agree on count
# ---------------------------------------------------------------------------


def test_dispatch_routing_is_deterministic_across_crawler_family(
    tmp_path: Path,
) -> None:
    """Same URL set through three tool_ids => same fingerprint shape.

    The fingerprint we pin is ``(count, ordered_endpoints, ordered_methods)``.
    The status_code may legitimately differ between tools (gau records
    have no status; gospider strings → ints; katana ints), so we exclude
    it from the determinism contract — only the *endpoint*+*method*
    surface area must agree.
    """
    urls = [
        "https://target/a",
        "https://target/b",
        "https://target/c",
    ]

    fingerprints: list[tuple[int, tuple[str, ...], tuple[str, ...]]] = []
    for tool_id in CRAWLER_JSON_TOOL_IDS:
        artifacts_dir = tmp_path / tool_id
        stdout = _build_stdout(tool_id, urls)
        findings = dispatch_parse(
            ParseStrategy.JSON_LINES,
            stdout,
            b"",
            artifacts_dir,
            tool_id=tool_id,
        )
        sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
        records: list[dict[str, Any]] = [
            json.loads(line)
            for line in sidecar.read_text(encoding="utf-8").splitlines()
            if line
        ]
        endpoints = tuple(rec["endpoint"] for rec in records)
        methods = tuple(rec["method"] for rec in records)
        fingerprints.append((len(findings), endpoints, methods))

    first = fingerprints[0]
    assert all(snap == first for snap in fingerprints[1:]), (
        f"dispatch routing is non-deterministic across the crawler family: "
        f"{fingerprints}"
    )
