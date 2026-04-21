"""Integration test: ffuf-family parser dispatch routing (Backlog/dev1_md §4.5).

Sister suite to ``test_dispatch_registry.py`` — that file pins generic
registry semantics (default surface, override, fail-soft); this one pins the
ARG-012 contract that every JSON-emitting content-discovery tool fans out
to the same :func:`parse_ffuf_json` entry point through the registry:

* ``ffuf_dir``, ``ffuf_vhost``, ``ffuf_param``  — native ffuf JSON envelope.
* ``feroxbuster``                                 — JSONL stream variant.
* ``dirsearch``                                   — JSON envelope with the
  hyphenated ``content-length`` field.
* ``arjun``                                       — top-level dict keyed
  by URL (real ``arjun -oJ`` shape); handled via the tool_id-aware branch
  in ``_extract_findings_list``.
* ``kiterunner``                                  — kr's JSON shape that
  broadly aligns with the ffuf envelope.
* ``wfuzz``                                       — wfuzz's top-level JSON
  array (from ``-o json -f path,json``).

The four invariants we re-assert under the *real* dispatch path:

1.  Each tool_id is registered against ``ParseStrategy.JSON_OBJECT`` and
    is routed to ``parse_ffuf_json`` (not the global JSON_OBJECT default).
2.  Findings carry CWE-200 + the per-tool OWASP-WSTG hint declared in the
    parser, regardless of which tool_id triggered the dispatch.
3.  Routing is deterministic: the same input bytes against any of the
    family tool_ids yields the same number of findings (i.e. the tool_id
    string only changes the per-tool metadata, not the parsing logic).
4.  Routing under an *unmapped* JSON_OBJECT tool_id falls through to the
    structured ``parsers.dispatch.unmapped_tool`` warning (no findings,
    no exception) — the per-tool registration is required, not optional.
    The two §4.5 text-only tools (``gobuster_dir`` / ``paramspider``)
    have no JSON_OBJECT registration by design and are pinned here so a
    future silent registration cannot land without an explicit test diff.

Each test snapshots / restores the registry via :func:`reset_registry` so
ordering with the rest of the integration suite stays hermetic.
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
from src.sandbox.parsers.ffuf_parser import EVIDENCE_SIDECAR_NAME


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


# Tools wired to ``parse_ffuf_json`` by ``backend/src/sandbox/parsers/__init__.py``.
# Hard-coded so a silent shrink (or expansion without parser updates) of the
# §4.5 batch breaks CI immediately.  All eight share the JSON_OBJECT strategy
# and accept the synthetic ``{"results": [{"url": ..., "status": ...}]}``
# envelope used in this suite (arjun's tool_id-aware branch in
# ``_extract_findings_list`` falls through to the standard envelope handler
# when the synthetic shape is fed in — see :func:`_iter_arjun_items`).
FFUF_FAMILY_TOOL_IDS: Final[tuple[str, ...]] = (
    "ffuf_dir",
    "ffuf_vhost",
    "ffuf_param",
    "feroxbuster",
    "dirsearch",
    "arjun",
    "kiterunner",
    "wfuzz",
)


# §4.5 tools that emit *text* output (``parse_strategy=text_lines``) and
# therefore have NO JSON_OBJECT registration in the per-tool table.  Pinned
# explicitly so the day a text_lines parser ships and these slots silently
# move into ``_DEFAULT_TOOL_PARSERS`` (or, worse, get cross-wired into
# JSON_OBJECT) the diff lights up in CI immediately.
TEXT_LINES_TOOL_IDS_UNMAPPED_FROM_JSON_OBJECT: Final[tuple[str, ...]] = (
    "gobuster_dir",
    "paramspider",
)


def _ffuf_envelope(*records: dict[str, Any]) -> bytes:
    """Encode ``records`` as the single-document JSON envelope ffuf emits."""
    return json.dumps({"results": list(records)}, sort_keys=True).encode("utf-8")


def _record(*, url: str, status: int, length: int = 1234) -> dict[str, Any]:
    return {"url": url, "status": status, "length": length}


# ---------------------------------------------------------------------------
# Per-tool registration surface
# ---------------------------------------------------------------------------


def test_default_per_tool_registry_includes_all_ffuf_family_tools() -> None:
    """Every §4.5 JSON tool must be registered in the per-tool registry."""
    registered = get_registered_tool_parsers()
    for tool_id in FFUF_FAMILY_TOOL_IDS:
        assert tool_id in registered, (
            f"{tool_id} missing from per-tool parser registry — broken "
            f"wiring in src.sandbox.parsers.__init__"
        )
    # httpx is the JSON_LINES alpha citizen — must coexist with ffuf family.
    assert "httpx" in registered, "httpx slot must survive ffuf-family registration"


# ---------------------------------------------------------------------------
# Routing — happy path for every member of the family
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", FFUF_FAMILY_TOOL_IDS)
def test_dispatch_routes_each_ffuf_family_tool_to_ffuf_parser(
    tool_id: str, tmp_path: Path
) -> None:
    """Same input bytes routed via every family tool_id yield the same shape.

    Validates the registration wiring AND the per-tool branching inside
    ``parse_ffuf_json``: the tool_id only mutates the OWASP-WSTG hint;
    the FindingDTO count and confidence-by-status mapping stay constant.

    The URL only lives in the evidence sidecar (FindingDTO has no ``title``
    field), so we cross-reference the sidecar's ``(url, status)`` tuples
    against the in-order findings to verify per-status confidence.
    """
    stdout = _ffuf_envelope(
        _record(url="https://target/admin", status=200),
        _record(url="https://target/login", status=401),
        _record(url="https://target/api/v1", status=500),
    )

    artifacts_dir = tmp_path / tool_id
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        stdout,
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )

    assert len(findings) == 3, f"{tool_id}: expected 3 findings, got {len(findings)}"
    assert all(isinstance(f, FindingDTO) for f in findings)
    assert all(f.category is FindingCategory.INFO for f in findings)
    assert all(200 in f.cwe for f in findings), (
        f"{tool_id}: every finding must carry CWE-200 (Information Exposure)"
    )

    # Reconstruct (url -> confidence) by zipping the sidecar with findings.
    # Both are emitted in the same order (sorted by (url, status)) — see
    # ``_extract_findings_list`` in the parser.
    sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
    sidecar_records = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line
    ]
    confidence_by_url = {
        rec["url"]: finding.confidence
        for rec, finding in zip(sidecar_records, findings, strict=True)
    }
    assert confidence_by_url["https://target/admin"] == ConfidenceLevel.SUSPECTED, (
        f"{tool_id}: 200 must stay SUSPECTED, got {confidence_by_url}"
    )
    assert confidence_by_url["https://target/api/v1"] == ConfidenceLevel.LIKELY, (
        f"{tool_id}: 5xx must promote to LIKELY, got {confidence_by_url}"
    )
    assert confidence_by_url["https://target/login"] == ConfidenceLevel.LIKELY, (
        f"{tool_id}: 401 must promote to LIKELY, got {confidence_by_url}"
    )


@pytest.mark.parametrize("tool_id", FFUF_FAMILY_TOOL_IDS)
def test_dispatch_writes_evidence_sidecar_for_each_ffuf_family_tool(
    tool_id: str, tmp_path: Path
) -> None:
    """Every family tool_id triggers the ffuf evidence sidecar on dispatch."""
    stdout = _ffuf_envelope(
        _record(url="https://target/x", status=200),
        _record(url="https://target/y", status=403),
    )

    artifacts_dir = tmp_path / tool_id
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        stdout,
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )

    assert len(findings) == 2
    sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file(), (
        f"{tool_id}: ffuf parser must write evidence sidecar at {sidecar}"
    )
    lines = [line for line in sidecar.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 2, (
        f"{tool_id}: sidecar must hold one JSONL record per finding, got {lines}"
    )
    parsed = [json.loads(line) for line in lines]
    assert {rec["url"] for rec in parsed} == {
        "https://target/x",
        "https://target/y",
    }
    assert all(rec["tool_id"] == tool_id for rec in parsed), (
        f"{tool_id}: every sidecar record must tag its source tool_id"
    )


# ---------------------------------------------------------------------------
# Per-tool OWASP hint differentiation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool_id", "expected_owasp"),
    [
        ("ffuf_dir", ["WSTG-CONFIG-04", "WSTG-CONFIG-06"]),
        ("ffuf_vhost", ["WSTG-INFO-04"]),
        ("ffuf_param", ["WSTG-INPV-04"]),
        ("feroxbuster", ["WSTG-CONFIG-04", "WSTG-CONFIG-06"]),
        ("dirsearch", ["WSTG-CONFIG-04", "WSTG-CONFIG-06"]),
        ("arjun", ["WSTG-INPV-04"]),
        ("kiterunner", ["WSTG-CONFIG-04", "WSTG-CONFIG-06"]),
        ("wfuzz", ["WSTG-INPV-04"]),
    ],
)
def test_dispatch_attaches_per_tool_owasp_wstg_hint(
    tool_id: str, expected_owasp: list[str], tmp_path: Path
) -> None:
    """Routing through dispatch preserves the per-tool OWASP-WSTG mapping
    encoded in :mod:`ffuf_parser` — the same hint set must show up
    regardless of how the parser is invoked (direct vs. via dispatch).
    """
    stdout = _ffuf_envelope(_record(url="https://target/", status=200))

    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        stdout,
        b"",
        tmp_path,
        tool_id=tool_id,
    )

    assert len(findings) == 1
    assert findings[0].owasp_wstg == expected_owasp, (
        f"{tool_id}: dispatch lost the per-tool OWASP-WSTG hint; "
        f"got {findings[0].owasp_wstg}, expected {expected_owasp}"
    )


# ---------------------------------------------------------------------------
# Negative path — JSON_OBJECT tool with no per-tool registration
# ---------------------------------------------------------------------------


def test_unmapped_json_object_tool_emits_heartbeat_with_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A JSON_OBJECT tool_id with no per-tool registration must:

    * not raise,
    * return one ARG-020 heartbeat finding (so the orchestrator / UI can
      surface "tool ran but parser deferred" instead of confusing it with
      "tool ran and found nothing"),
    * emit the ``parsers.dispatch.unmapped_tool`` structured warning.

    Pins the contract that per-tool registration is mandatory: a future
    JSON_OBJECT tool that lands without a parser fail-softs to the
    heartbeat path instead of silently swallowing data into an empty
    default.
    """
    stdout = _ffuf_envelope(_record(url="https://target/", status=200))

    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = dispatch_parse(
            ParseStrategy.JSON_OBJECT,
            stdout,
            b"",
            tmp_path,
            tool_id="some_future_json_object_tool",
        )

    assert len(findings) == 1
    heartbeat = findings[0]
    assert heartbeat.category is FindingCategory.INFO
    assert "ARGUS-HEARTBEAT" in heartbeat.owasp_wstg
    assert "HEARTBEAT-some_future_json_object_tool" in heartbeat.owasp_wstg
    assert any(
        "parsers.dispatch.unmapped_tool" in record.getMessage()
        or getattr(record, "event", "") == "parsers_dispatch_unmapped_tool"
        for record in caplog.records
    ), f"missing structured warning; got {[r.getMessage() for r in caplog.records]}"


@pytest.mark.parametrize("tool_id", TEXT_LINES_TOOL_IDS_UNMAPPED_FROM_JSON_OBJECT)
def test_text_lines_tools_have_no_json_object_parser(
    tool_id: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """``gobuster_dir`` / ``paramspider`` use ``parse_strategy=text_lines``
    and MUST NOT be registered against ``ParseStrategy.JSON_OBJECT``.

    A JSON_OBJECT dispatch with one of these tool_ids therefore fail-softs
    to the ``parsers.dispatch.unmapped_tool`` structured warning AND emits
    one ARG-020 heartbeat finding.  Pins the routing-table contract so
    the day a TEXT_LINES parser ships and these slots silently move into
    ``_DEFAULT_TOOL_PARSERS`` (or, worse, get cross-wired into JSON_OBJECT)
    the diff lights up here in CI immediately.
    """
    stdout = _ffuf_envelope(_record(url="https://target/", status=200))

    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = dispatch_parse(
            ParseStrategy.JSON_OBJECT,
            stdout,
            b"",
            tmp_path,
            tool_id=tool_id,
        )

    assert len(findings) == 1, (
        f"{tool_id}: expected one heartbeat via JSON_OBJECT misroute, "
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


def test_arjun_real_shape_via_dispatch_emits_finding(tmp_path: Path) -> None:
    """Real ``arjun -oJ`` output (top-level dict keyed by URL) routes
    through dispatch and produces a finding.  Companion to the unit test
    in ``test_ffuf_parser.py`` — pins the wiring across the dispatch
    boundary, not just the parser surface.
    """
    payload = {
        "https://target/api/users": [
            {"name": "user_id", "method": "GET", "type": "Form"},
            {"name": "page", "method": "GET", "type": "Form"},
        ]
    }
    stdout = json.dumps(payload).encode("utf-8")

    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        stdout,
        b"",
        tmp_path,
        tool_id="arjun",
    )

    # Two parameters under one URL collapse via the (url, status=200)
    # dedup key into exactly one finding.
    assert len(findings) == 1
    assert findings[0].owasp_wstg == ["WSTG-INPV-04"]
    sidecar = tmp_path / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file()
    sidecar_records = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line
    ]
    assert sidecar_records[0]["url"] == "https://target/api/users"
    assert sidecar_records[0]["parameter_name"] == "user_id"
    assert sidecar_records[0]["method"] == "GET"


# ---------------------------------------------------------------------------
# Determinism — five identical dispatches against five tool_ids agree on
# the count + the URL set; only the per-tool metadata may differ.
# ---------------------------------------------------------------------------


def test_dispatch_routing_is_deterministic_across_family(tmp_path: Path) -> None:
    """Same bytes routed through five tool_ids => same finding fingerprint.

    The fingerprint we pin is ``(count, ordered_confidences,
    sorted_sidecar_urls)`` — the OWASP-WSTG hints are intentionally
    excluded because they're per-tool by design.
    """
    stdout = _ffuf_envelope(
        _record(url="https://target/a", status=200),
        _record(url="https://target/b", status=301),
        _record(url="https://target/c", status=403),
        _record(url="https://target/d", status=500),
    )

    snapshots: list[tuple[int, tuple[ConfidenceLevel, ...], tuple[str, ...]]] = []
    for tool_id in FFUF_FAMILY_TOOL_IDS:
        artifacts_dir = tmp_path / tool_id
        findings = dispatch_parse(
            ParseStrategy.JSON_OBJECT,
            stdout,
            b"",
            artifacts_dir,
            tool_id=tool_id,
        )
        sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
        sidecar_urls = tuple(
            sorted(
                json.loads(line)["url"]
                for line in sidecar.read_text(encoding="utf-8").splitlines()
                if line
            )
        )
        confidences = tuple(f.confidence for f in findings)
        snapshots.append((len(findings), confidences, sidecar_urls))

    # All snapshots must agree — the ONLY thing tool_id changes is per-tool
    # metadata (OWASP-WSTG hint), which is asserted separately above.
    first = snapshots[0]
    assert all(snap == first for snap in snapshots[1:]), (
        f"dispatch routing is non-deterministic across the family: {snapshots}"
    )
