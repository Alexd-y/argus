"""End-to-end integration test: ARG-012 §4.5 ``ffuf_dir`` vertical slice.

Sister suite to ``test_arg011_end_to_end.py`` — ARG-011 covers the httpx
JSON_LINES path; this file covers the ARG-012 JSON_OBJECT path through
``ffuf_dir`` as the canonical content-discovery scanner.

Wires up the three ARG-012 subsystems against the *real*
:class:`src.sandbox.tool_registry.ToolRegistry` and the *real*
:mod:`src.sandbox.parsers` registry — no mocks for the registry layers,
only the raw ffuf output is synthesised:

1.  Loading the production catalog through :class:`ToolRegistry` yields a
    descriptor for ``ffuf_dir`` whose ``parse_strategy`` is JSON_OBJECT
    (the canonical strategy for the §4.5 batch).
2.  Rendering ``descriptor.command_template`` with the in-band sandbox
    placeholders (``url``, ``wordlist``, ``out_dir``) produces a clean
    argv whose tokens contain neither shell metacharacters nor unrendered
    ``{...}`` placeholders.
3.  Feeding a synthetic ffuf JSON envelope (3 records spanning 2xx / 3xx
    / 5xx) into :func:`dispatch_parse` with the descriptor's strategy
    yields exactly three :class:`FindingDTO`s of category
    :class:`FindingCategory.INFO` (CWE-200 — Information Exposure),
    each carrying the ffuf_dir-specific OWASP-WSTG hints
    (WSTG-CONFIG-04 + WSTG-CONFIG-06).
4.  The parser-side evidence sidecar (``ffuf_findings.jsonl``) is
    written into the artefact directory.

Fails closed if any of those layers regresses — a missing per-tool
parser registration, an argv that grew shell metachars, or a
parse_strategy drift in the YAML.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import dispatch_parse
from src.sandbox.parsers.ffuf_parser import EVIDENCE_SIDECAR_NAME
from src.sandbox.templating import render_argv
from src.sandbox.tool_registry import ToolRegistry


# ---------------------------------------------------------------------------
# Shell metacharacters audited on the rendered argv. Mirrors the static
# audit done at YAML-author time in test_yaml_content_discovery_semantics.py.
# ---------------------------------------------------------------------------


_SHELL_METACHARS: Final[tuple[str, ...]] = (
    ";",
    "|",
    "&&",
    "||",
    "&",
    "`",
    "$(",
    ">",
    "<",
    "\n",
    "\r",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def catalog_dir() -> Path:
    """Resolve ``backend/config/tools/`` from this test file's location.

    ``parents`` indices for ``backend/tests/integration/sandbox/<file>.py``:
    ``[0]=sandbox, [1]=integration, [2]=tests, [3]=backend``.
    """
    here = Path(__file__).resolve()
    backend_dir = here.parents[3]
    catalog = backend_dir / "config" / "tools"
    assert catalog.is_dir(), f"expected catalog dir at {catalog}"
    return catalog


@pytest.fixture(scope="module")
def loaded_registry(catalog_dir: Path) -> ToolRegistry:
    """Load the real signed catalog exactly as the application does at startup."""
    registry = ToolRegistry(tools_dir=catalog_dir)
    registry.load()
    return registry


def _ffuf_record(
    *,
    url: str,
    status: int,
    length: int = 1234,
    words: int = 100,
    lines: int = 10,
) -> dict[str, Any]:
    """Build a synthetic ffuf JSON record matching the real tool's shape."""
    return {
        "url": url,
        "status": status,
        "length": length,
        "words": words,
        "lines": lines,
    }


def _ffuf_envelope(*records: dict[str, Any]) -> bytes:
    """Encode ``records`` as the JSON envelope ``ffuf -of json`` emits."""
    return json.dumps({"results": list(records)}, sort_keys=True).encode("utf-8")


# ---------------------------------------------------------------------------
# YAML → render
# ---------------------------------------------------------------------------


def test_ffuf_dir_descriptor_loads_with_json_object_strategy(
    loaded_registry: ToolRegistry,
) -> None:
    """The catalog must expose ``ffuf_dir`` with JSON_OBJECT dispatch strategy."""
    descriptor = loaded_registry.get("ffuf_dir")
    assert descriptor is not None, "ffuf_dir missing from loaded catalog"
    assert descriptor.parse_strategy is ParseStrategy.JSON_OBJECT
    assert descriptor.image == "argus-kali-web:latest"


def test_ffuf_dir_argv_renders_clean_with_placeholders(
    loaded_registry: ToolRegistry,
) -> None:
    """Render with sandbox-internal placeholders and audit the argv.

    The ``url`` / ``wordlist`` / ``out_dir`` triple matches the §4.5 contract
    for content-discovery tools. ``render_argv`` validates every placeholder
    value against the templating allow-list; we then re-audit the rendered
    tokens as defence-in-depth: no shell metachars, no leftover ``{...}``.
    """
    descriptor = loaded_registry.get("ffuf_dir")
    assert descriptor is not None

    argv = render_argv(
        list(descriptor.command_template),
        {
            "url": "https://target.example",
            "wordlist": "/wordlists/raft-medium-directories.txt",
            "out_dir": "/out",
        },
    )

    assert argv, "rendered argv must be non-empty"
    assert argv[0] == "ffuf", f"first token must be the binary, got {argv[0]!r}"

    offenders: list[tuple[str, str]] = []
    for token in argv:
        if "{" in token or "}" in token:
            offenders.append((token, "unrendered placeholder"))
        for meta in _SHELL_METACHARS:
            if meta in token:
                offenders.append((token, meta))
    assert not offenders, (
        f"rendered ffuf_dir argv contains shell metachars / placeholders: {offenders}"
    )


# ---------------------------------------------------------------------------
# Render → dispatch → findings
# ---------------------------------------------------------------------------


def test_dispatch_parse_with_three_records_yields_three_findings(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """Feed 3 synthetic ffuf records through the real dispatch pipeline.

    Spans 2xx / 3xx / 5xx so the test also pins the
    status-code-to-confidence mapping documented in
    ``src.sandbox.parsers.ffuf_parser._confidence_for_status``.
    """
    descriptor = loaded_registry.get("ffuf_dir")
    assert descriptor is not None

    raw_stdout = _ffuf_envelope(
        _ffuf_record(url="https://target/admin", status=200),
        _ffuf_record(url="https://target/login", status=301),
        _ffuf_record(url="https://target/api/v1/", status=500),
    )

    findings = dispatch_parse(
        descriptor.parse_strategy,
        raw_stdout,
        b"",
        tmp_path,
        tool_id="ffuf_dir",
    )

    assert len(findings) == 3, (
        f"expected 3 findings (one per record), got {len(findings)}"
    )
    for finding in findings:
        # Content discovery is INFO category in the parser layer.
        assert finding.category is FindingCategory.INFO
        # CWE-200: Information Exposure (universal across the §4.5 batch).
        assert 200 in finding.cwe, (
            f"finding must include CWE-200 (Information Exposure), got {finding.cwe}"
        )
        # ffuf_dir-specific OWASP-WSTG hints (Backlog/dev1_md §4.5).
        assert "WSTG-CONFIG-04" in finding.owasp_wstg
        assert "WSTG-CONFIG-06" in finding.owasp_wstg

    # Confidence ordering: findings come out sorted by (url, status), so
    # the order is admin (200) < api/v1/ (500) < login (301).  The 5xx
    # status promotes /api/v1/ to LIKELY; the others stay SUSPECTED.
    confidences = [f.confidence for f in findings]
    assert confidences == [
        ConfidenceLevel.SUSPECTED,  # admin 200
        ConfidenceLevel.LIKELY,  # api/v1 500
        ConfidenceLevel.SUSPECTED,  # login 301
    ], f"unexpected confidence order: {confidences}"


def test_dispatch_parse_writes_evidence_sidecar(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """The ffuf parser must persist a JSONL sidecar in ``artifacts_dir``."""
    descriptor = loaded_registry.get("ffuf_dir")
    assert descriptor is not None

    raw_stdout = _ffuf_envelope(
        _ffuf_record(url="https://target/a", status=200),
        _ffuf_record(url="https://target/b", status=200),
        _ffuf_record(url="https://target/c", status=200),
    )

    findings = dispatch_parse(
        descriptor.parse_strategy,
        raw_stdout,
        b"",
        tmp_path,
        tool_id="ffuf_dir",
    )

    assert len(findings) == 3
    sidecar = tmp_path / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file(), "ffuf parser must write an evidence sidecar"
    lines = [line for line in sidecar.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 3, f"sidecar must hold one record per finding, got {lines}"
    parsed = [json.loads(line) for line in lines]
    urls = sorted(rec["url"] for rec in parsed)
    assert urls == ["https://target/a", "https://target/b", "https://target/c"]
    # The sidecar must tag the source tool_id so a downstream consumer
    # can route per-tool processing without re-parsing the raw output.
    assert all(rec["tool_id"] == "ffuf_dir" for rec in parsed)


def test_dispatch_parse_dedups_by_url_status_pair(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """Recursion produces duplicate ``(url, status)`` rows; parser collapses
    them to one finding.  Pinned end-to-end so a future change to the dedup
    key (or its removal) breaks CI immediately.
    """
    descriptor = loaded_registry.get("ffuf_dir")
    assert descriptor is not None

    # Eight records, but only TWO unique (url, status) pairs.
    raw_stdout = _ffuf_envelope(
        *([_ffuf_record(url="https://target/admin", status=200)] * 4),
        *([_ffuf_record(url="https://target/login", status=403)] * 4),
    )

    findings = dispatch_parse(
        descriptor.parse_strategy,
        raw_stdout,
        b"",
        tmp_path,
        tool_id="ffuf_dir",
    )

    assert len(findings) == 2, (
        f"dedup by (url, status) must collapse 8 → 2 findings, got {len(findings)}"
    )
