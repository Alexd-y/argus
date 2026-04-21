"""End-to-end integration test: ARG-011 §4.4 ``httpx`` vertical slice.

Wires up the three subsystems ARG-011 ships in lockstep — YAML descriptor,
templating-rendered argv, parser dispatch — against the real
:mod:`src.sandbox.tool_registry` and the real
:mod:`src.sandbox.parsers` registry. No mocks for the registry layers;
only the *raw* httpx output is synthesised.

Concretely the test verifies:

1.  Loading the production catalog through :class:`ToolRegistry` yields a
    descriptor for ``httpx`` whose ``parse_strategy`` is JSON_LINES.
2.  Rendering ``descriptor.command_template`` with ``in_dir=/in`` /
    ``out_dir=/out`` produces a clean argv whose tokens are free of any
    shell metacharacters or unrendered placeholders.
3.  Feeding a synthetic httpx JSONL stdout (3 records) into
    :func:`dispatch_parse` with the descriptor's strategy yields exactly
    three :class:`FindingDTO` records of category :class:`FindingCategory.INFO`
    (the parser layer's representation of "tech disclosure" — see CWE-200
    / WSTG-INFO-02 + WSTG-INFO-08 mapping in ``httpx_parser.py``) carrying
    the sentinel ``cvss_v3_score == 0.0`` (info severity).
4.  The evidence sidecar JSONL is written to the artefacts directory.

This test fails closed if any of those steps regresses — a missing parser
registration, an argv that grew shell metachars, or a parse_strategy drift
in the YAML.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

import pytest

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import dispatch_parse
from src.sandbox.parsers._base import SENTINEL_CVSS_SCORE
from src.sandbox.parsers.httpx_parser import EVIDENCE_SIDECAR_NAME
from src.sandbox.templating import render_argv
from src.sandbox.tool_registry import ToolRegistry


# Shell metacharacters audited on the rendered argv. Mirrors the static
# audit done at YAML-author time in test_yaml_http_fingerprint_semantics.py.
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


def _httpx_record(
    *,
    url: str,
    status_code: int,
    title: str,
    tech: list[str],
    webserver: str | None = None,
) -> dict[str, object]:
    """Build a synthetic httpx JSON record of the shape the real tool emits."""
    record: dict[str, object] = {
        "url": url,
        "status_code": status_code,
        "title": title,
        "tech": tech,
    }
    if webserver is not None:
        record["webserver"] = webserver
    return record


def _httpx_jsonl(*records: dict[str, object]) -> bytes:
    """Encode ``records`` as the JSONL bytes httpx emits with ``-json``."""
    return ("\n".join(json.dumps(r, sort_keys=True) for r in records)).encode("utf-8")


# ---------------------------------------------------------------------------
# YAML → render
# ---------------------------------------------------------------------------


def test_httpx_descriptor_loads_with_json_lines_strategy(
    loaded_registry: ToolRegistry,
) -> None:
    """The catalog must expose ``httpx`` with JSON_LINES dispatch strategy."""
    descriptor = loaded_registry.get("httpx")
    assert descriptor is not None, "httpx missing from loaded catalog"
    assert descriptor.parse_strategy is ParseStrategy.JSON_LINES
    assert descriptor.image == "argus-kali-web:latest"


def test_httpx_argv_renders_clean_with_in_out_placeholders(
    loaded_registry: ToolRegistry,
) -> None:
    """Render with sandbox-internal /in /out placeholders and audit the argv.

    ``render_argv`` validates every placeholder value and refuses any that
    contains shell-meaningful characters. We then re-audit the output as
    defence-in-depth: rendered tokens must contain no metacharacter and no
    leftover ``{...}`` sequence (a bug class where a placeholder name is
    misspelled and silently survives substitution would otherwise hide).
    """
    descriptor = loaded_registry.get("httpx")
    assert descriptor is not None

    argv = render_argv(
        list(descriptor.command_template),
        {"in_dir": "/in", "out_dir": "/out"},
    )

    assert argv, "rendered argv must be non-empty"
    assert argv[0] == "httpx", f"first token must be the binary, got {argv[0]!r}"

    offenders: list[tuple[str, str]] = []
    for token in argv:
        if "{" in token or "}" in token:
            offenders.append((token, "unrendered placeholder"))
        for meta in _SHELL_METACHARS:
            if meta in token:
                offenders.append((token, meta))
    assert not offenders, (
        f"rendered httpx argv contains shell metachars / placeholders: {offenders}"
    )


# ---------------------------------------------------------------------------
# Render → dispatch → findings
# ---------------------------------------------------------------------------


def test_dispatch_parse_with_three_records_yields_three_findings(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """Feed 3 synthetic httpx records through the real dispatch pipeline."""
    descriptor = loaded_registry.get("httpx")
    assert descriptor is not None

    raw_stdout = _httpx_jsonl(
        _httpx_record(
            url="https://a.example",
            status_code=200,
            title="A — Home",
            tech=["Nginx", "Cloudflare"],
            webserver="nginx/1.21.6",
        ),
        _httpx_record(
            url="https://b.example",
            status_code=301,
            title="B — Redirect",
            tech=["Apache"],
            webserver="Apache/2.4.54",
        ),
        _httpx_record(
            url="https://c.example",
            status_code=403,
            title="C — Forbidden",
            tech=["IIS"],
            webserver="Microsoft-IIS/10.0",
        ),
    )

    findings = dispatch_parse(
        descriptor.parse_strategy,
        raw_stdout,
        b"",
        tmp_path,
        tool_id="httpx",
    )

    assert len(findings) == 3, (
        f"expected 3 findings (one per record), got {len(findings)}"
    )
    for finding in findings:
        # The httpx parser maps tech-disclosure findings to the INFO category
        # with the sentinel CVSS score; this is the parser-layer representation
        # of "tech disclosure" called out in the cycle plan.
        assert finding.category is FindingCategory.INFO
        assert finding.cvss_v3_score == SENTINEL_CVSS_SCORE
        assert 200 in finding.cwe, (
            f"finding must include CWE-200 (Information Exposure), got {finding.cwe}"
        )
        assert "WSTG-INFO-02" in finding.owasp_wstg
        assert "WSTG-INFO-08" in finding.owasp_wstg


def test_dispatch_parse_writes_evidence_sidecar(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """The httpx parser must persist a JSONL sidecar in ``artifacts_dir``."""
    descriptor = loaded_registry.get("httpx")
    assert descriptor is not None

    raw_stdout = _httpx_jsonl(
        _httpx_record(
            url="https://a.example",
            status_code=200,
            title="A",
            tech=["Nginx"],
        ),
        _httpx_record(
            url="https://b.example",
            status_code=200,
            title="B",
            tech=["Apache"],
        ),
        _httpx_record(
            url="https://c.example",
            status_code=200,
            title="C",
            tech=["IIS"],
        ),
    )

    dispatch_parse(
        descriptor.parse_strategy,
        raw_stdout,
        b"",
        tmp_path,
        tool_id="httpx",
    )

    sidecar = tmp_path / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file(), "httpx parser must write an evidence sidecar"
    lines = [line for line in sidecar.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 3, f"sidecar must hold one record per finding, got {lines}"
    parsed = [json.loads(line) for line in lines]
    urls = sorted(rec["url"] for rec in parsed)
    assert urls == ["https://a.example", "https://b.example", "https://c.example"]
