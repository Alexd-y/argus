"""End-to-end integration test: ARG-013 §4.6 ``katana`` vertical slice.

Wires up the three subsystems ARG-013 ships in lockstep — YAML descriptor,
templating-rendered argv, parser dispatch — against the real
:mod:`src.sandbox.tool_registry` and the real
:mod:`src.sandbox.parsers` registry. No mocks for the registry layers;
only the *raw* katana output is synthesised.

Concretely the test verifies:

1.  Loading the production catalog through :class:`ToolRegistry` yields a
    descriptor for ``katana`` whose ``parse_strategy`` is JSON_LINES.
2.  Rendering ``descriptor.command_template`` with ``url=...`` /
    ``out_dir=/out`` produces a clean argv whose tokens are free of any
    shell metacharacters or unrendered placeholders.
3.  Feeding a synthetic katana JSONL stdout (3 records, including one
    duplicate that must collapse on dedup) into :func:`dispatch_parse`
    with the descriptor's strategy yields exactly two
    :class:`FindingDTO` records of category :class:`FindingCategory.INFO`,
    carrying CWE-200 and the WSTG-INFO-06 / WSTG-INFO-07 hint set.
4.  The shared evidence sidecar (``katana_findings.jsonl``) is written
    to the artefacts directory with one record per finding, each
    stamped with ``tool_id=katana``.

Sister vertical slices for ``gospider`` and ``gau`` are pinned in the
companion :mod:`test_katana_dispatch` integration suite.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

import pytest

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import dispatch_parse
from src.sandbox.parsers._base import SENTINEL_CVSS_SCORE
from src.sandbox.parsers.katana_parser import EVIDENCE_SIDECAR_NAME
from src.sandbox.templating import render_argv
from src.sandbox.tool_registry import ToolRegistry


# Shell metacharacters audited on the rendered argv. Mirrors the static
# audit done at YAML-author time in test_yaml_crawler_semantics.py.
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


def _katana_record(
    *,
    endpoint: str,
    method: str = "GET",
    status_code: int = 200,
    content_length: int = 1234,
    content_type: str = "text/html",
) -> dict[str, Any]:
    """Build a synthetic katana JSON record of the shape the real tool emits."""
    return {
        "timestamp": "2026-04-18T10:00:00Z",
        "request": {"endpoint": endpoint, "method": method, "tag": "form"},
        "response": {
            "status_code": status_code,
            "content_length": content_length,
            "content_type": content_type,
        },
    }


def _katana_jsonl(*records: dict[str, Any]) -> bytes:
    """Encode ``records`` as the JSONL bytes katana emits with ``-jsonl``."""
    return ("\n".join(json.dumps(r, sort_keys=True) for r in records)).encode("utf-8")


# ---------------------------------------------------------------------------
# YAML → render
# ---------------------------------------------------------------------------


def test_katana_descriptor_loads_with_json_lines_strategy(
    loaded_registry: ToolRegistry,
) -> None:
    """The catalog must expose ``katana`` with JSON_LINES dispatch strategy."""
    descriptor = loaded_registry.get("katana")
    assert descriptor is not None, "katana missing from loaded catalog"
    assert descriptor.parse_strategy is ParseStrategy.JSON_LINES
    assert descriptor.image == "argus-kali-web:latest"
    assert descriptor.network_policy.name == "recon-active-tcp"


def test_katana_argv_renders_clean_with_url_out_placeholders(
    loaded_registry: ToolRegistry,
) -> None:
    """Render with sandbox-internal /out + url placeholders and audit the argv.

    ``render_argv`` validates every placeholder value and refuses any that
    contains shell-meaningful characters. We then re-audit the output as
    defence-in-depth: rendered tokens must contain no metacharacter and no
    leftover ``{...}`` sequence (a bug class where a placeholder name is
    misspelled and silently survives substitution would otherwise hide).
    """
    descriptor = loaded_registry.get("katana")
    assert descriptor is not None

    argv = render_argv(
        list(descriptor.command_template),
        {"url": "https://target.example", "out_dir": "/out"},
    )

    assert argv, "rendered argv must be non-empty"
    assert argv[0] == "katana", f"first token must be the binary, got {argv[0]!r}"

    offenders: list[tuple[str, str]] = []
    for token in argv:
        if "{" in token or "}" in token:
            offenders.append((token, "unrendered placeholder"))
        for meta in _SHELL_METACHARS:
            if meta in token:
                offenders.append((token, meta))
    assert not offenders, (
        f"rendered katana argv contains shell metachars / placeholders: {offenders}"
    )


# ---------------------------------------------------------------------------
# Render → dispatch → findings
# ---------------------------------------------------------------------------


def test_dispatch_parse_with_three_records_dedup_to_two_findings(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """Feed 3 synthetic katana records (one duplicate) through the dispatch
    pipeline; the duplicate ``(endpoint, method)`` collapses to one finding.
    """
    descriptor = loaded_registry.get("katana")
    assert descriptor is not None

    raw_stdout = _katana_jsonl(
        _katana_record(endpoint="https://a.example/login"),
        _katana_record(endpoint="https://b.example/api/v1", method="POST"),
        # Duplicate of the first record — must collapse on dedup.
        _katana_record(endpoint="https://a.example/login"),
    )

    findings = dispatch_parse(
        descriptor.parse_strategy,
        raw_stdout,
        b"",
        tmp_path,
        tool_id="katana",
    )

    assert len(findings) == 2, (
        f"expected 2 findings (3 records − 1 dup), got {len(findings)}"
    )
    for finding in findings:
        assert finding.category is FindingCategory.INFO
        assert finding.cvss_v3_score == SENTINEL_CVSS_SCORE
        assert finding.cwe == [200]
        assert "WSTG-INFO-06" in finding.owasp_wstg
        assert "WSTG-INFO-07" in finding.owasp_wstg


def test_dispatch_parse_writes_evidence_sidecar(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """The katana parser must persist a JSONL sidecar in ``artifacts_dir``."""
    descriptor = loaded_registry.get("katana")
    assert descriptor is not None

    raw_stdout = _katana_jsonl(
        _katana_record(endpoint="https://a.example/x"),
        _katana_record(endpoint="https://b.example/y"),
        _katana_record(endpoint="https://c.example/z"),
    )

    dispatch_parse(
        descriptor.parse_strategy,
        raw_stdout,
        b"",
        tmp_path,
        tool_id="katana",
    )

    sidecar = tmp_path / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file(), "katana parser must write an evidence sidecar"
    lines = [line for line in sidecar.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 3, f"sidecar must hold one record per finding, got {lines}"
    parsed = [json.loads(line) for line in lines]
    endpoints = sorted(rec["endpoint"] for rec in parsed)
    assert endpoints == [
        "https://a.example/x",
        "https://b.example/y",
        "https://c.example/z",
    ]
    assert all(rec["tool_id"] == "katana" for rec in parsed), (
        "every sidecar record must tag tool_id=katana"
    )
