"""Integration test: interactsh / oastify parser dispatch (Backlog/dev1_md §4.11).

Sister suite to ``test_wpscan_dispatch.py`` and ``test_katana_dispatch.py``;
this one pins the ARG-017 contract that the two JSONL-emitting §4.11 OAST
receivers route through the per-tool registry to the dedicated
:func:`src.sandbox.parsers.interactsh_parser.parse_interactsh_jsonl`:

* ``interactsh_client`` — flagship OOB receiver from Project Discovery; the
  canonical OAST plane the orchestrator embeds OAST tokens against.
* ``oastify_client``    — upstream-compatible mirror; emits the same wire
  shape interactsh does (``-o /out/interactsh.jsonl``) so both route
  through the same parser.

Pinned invariants:

1. Both tool_ids are registered against
   :class:`~src.sandbox.adapter_base.ParseStrategy.JSON_LINES` and route
   to the dedicated interactsh parser (not the global JSON_LINES handler
   used by ``httpx``).
2. The shared evidence sidecar
   :data:`~src.sandbox.parsers.interactsh_parser.EVIDENCE_SIDECAR_NAME`
   is emitted by every dispatch and stamps each record with its source
   ``tool_id`` so the two callers stay demultiplexable downstream.
3. The remaining three §4.11 tools (``ssrfmap`` / ``gopherus`` /
   ``oast_dns_probe``) ship with text- / non-OAST parse strategies and
   therefore have NO JSON_LINES registration. Pinned so a silent
   reroute lights up CI.
4. Dispatch is fail-soft against malformed JSONL — a poisoned line emits
   the structured ``parsers.jsonl.malformed`` warning without aborting.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Final

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
from src.sandbox.parsers.interactsh_parser import EVIDENCE_SIDECAR_NAME


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


# §4.11 tools that route through ``parse_interactsh_jsonl``. Hard-coded so a
# silent shrink breaks CI immediately.
OAST_JSONL_TOOL_IDS: Final[tuple[str, ...]] = (
    "interactsh_client",
    "oastify_client",
)


# §4.11 tools that emit *text* output (or no JSONL) and therefore have NO
# JSON_LINES registration. Pinned explicitly so a future silent move into
# ``_DEFAULT_TOOL_PARSERS`` lights up the diff in CI.
NON_JSONL_OAST_TOOL_IDS: Final[tuple[str, ...]] = (
    "ssrfmap",
    "gopherus",
    "oast_dns_probe",
)


def _http_record(
    *,
    unique_id: str = "c2vhx10sxxx",
    full_id: str = "c2vhx10sxxx.oast.argus.local",
    remote_address: str = "203.0.113.55:48372",
    timestamp: str = "2026-04-19T12:34:56Z",
) -> dict[str, object]:
    return {
        "protocol": "http",
        "unique-id": unique_id,
        "full-id": full_id,
        "remote-address": remote_address,
        "timestamp": timestamp,
        "raw-request": (
            "GET /tok HTTP/1.1\r\nHost: oast.argus.local\r\n"
            "User-Agent: curl/8.0\r\n\r\n"
        ),
        "raw-response": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    }


def _dns_record(
    *,
    unique_id: str = "dns_id",
    full_id: str = "dns.oast.argus.local",
    remote_address: str = "198.51.100.10:53",
    timestamp: str = "2026-04-19T12:00:00Z",
) -> dict[str, object]:
    return {
        "protocol": "dns",
        "unique-id": unique_id,
        "full-id": full_id,
        "remote-address": remote_address,
        "timestamp": timestamp,
        "q-type": "A",
    }


def _to_jsonl(records: list[dict[str, object]]) -> bytes:
    return ("\n".join(json.dumps(r) for r in records) + "\n").encode("utf-8")


# ---------------------------------------------------------------------------
# Per-tool registration surface
# ---------------------------------------------------------------------------


def test_default_per_tool_registry_includes_all_oast_jsonl_tools() -> None:
    """Every §4.11 JSONL-emitting tool must be registered."""
    registered = get_registered_tool_parsers()
    for tool_id in OAST_JSONL_TOOL_IDS:
        assert tool_id in registered, (
            f"{tool_id} missing from per-tool parser registry — broken "
            f"wiring in src.sandbox.parsers.__init__"
        )
    # Cross-batch coexistence: previous wirings must survive ARG-017.
    for legacy in ("httpx", "ffuf_dir", "katana", "wpscan", "nuclei", "dalfox"):
        assert legacy in registered, f"{legacy} slot must survive ARG-017 registration"


# ---------------------------------------------------------------------------
# Routing — happy path for every JSONL-emitting OAST tool
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", OAST_JSONL_TOOL_IDS)
def test_dispatch_routes_each_oast_tool_to_interactsh_parser(
    tool_id: str, tmp_path: Path
) -> None:
    """Both §4.11 JSONL tool_ids dispatch via JSON_LINES and produce findings."""
    findings = dispatch_parse(
        ParseStrategy.JSON_LINES,
        _to_jsonl([_http_record()]),
        b"",
        tmp_path / tool_id,
        tool_id=tool_id,
    )

    assert findings, f"{tool_id}: dispatch produced no findings"
    assert all(isinstance(f, FindingDTO) for f in findings)
    assert findings[0].category is FindingCategory.SSRF
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


@pytest.mark.parametrize("tool_id", OAST_JSONL_TOOL_IDS)
def test_dispatch_writes_shared_sidecar_with_correct_tool_id(
    tool_id: str, tmp_path: Path
) -> None:
    """Each OAST dispatch emits a per-finding sidecar tagged with the tool_id."""
    artifacts_dir = tmp_path / tool_id
    findings = dispatch_parse(
        ParseStrategy.JSON_LINES,
        _to_jsonl([_http_record()]),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings

    sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file(), (
        f"{tool_id}: interactsh parser must write evidence sidecar at {sidecar}"
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


def test_dispatch_dns_callback_emits_info_likely(tmp_path: Path) -> None:
    """DNS callbacks ride the same dispatch path → INFO/LIKELY findings."""
    findings = dispatch_parse(
        ParseStrategy.JSON_LINES,
        _to_jsonl([_dns_record()]),
        b"",
        tmp_path,
        tool_id="interactsh_client",
    )

    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_dispatch_canonical_artifact_takes_precedence_over_stdout(
    tmp_path: Path,
) -> None:
    """Canonical ``interactsh.jsonl`` is preferred when both sources exist;
    the dedup pass folds the stdout duplicate into one finding.
    """
    artifacts_dir = tmp_path / "interactsh_client"
    artifacts_dir.mkdir()
    record = _http_record(unique_id="dedup_me")
    (artifacts_dir / "interactsh.jsonl").write_bytes(_to_jsonl([record]))

    findings = dispatch_parse(
        ParseStrategy.JSON_LINES,
        _to_jsonl([record]),  # stdout duplicate
        b"",
        artifacts_dir,
        tool_id="interactsh_client",
    )
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Negative path — non-JSONL §4.11 tools must not cross-wire
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", NON_JSONL_OAST_TOOL_IDS)
def test_non_jsonl_oast_tools_have_no_json_lines_parser(
    tool_id: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """text_lines §4.11 tools must NOT be reachable via JSON_LINES dispatch.

    A misrouted JSON_LINES dispatch fail-softs to
    ``parsers.dispatch.unmapped_tool`` AND emits one ARG-020 heartbeat
    finding so the orchestrator can distinguish "tool ran but parser
    deferred" from a silent skip.
    """
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = dispatch_parse(
            ParseStrategy.JSON_LINES,
            _to_jsonl([_http_record()]),
            b"",
            tmp_path,
            tool_id=tool_id,
        )

    assert len(findings) == 1, (
        f"{tool_id}: expected one heartbeat via JSON_LINES misroute, "
        f"got {len(findings)} findings"
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


# ---------------------------------------------------------------------------
# Fail-soft on malformed JSONL — must not abort the run
# ---------------------------------------------------------------------------


def test_dispatch_is_failsoft_on_malformed_jsonl(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A poisoned JSONL line emits the malformed warning, but the run survives.

    The good record before the poison line still produces a finding — the
    parser must not abort on the first decode error.
    """
    good = json.dumps(_http_record(unique_id="survivor"))
    poisoned = good + "\nthis is not json\n"
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = dispatch_parse(
            ParseStrategy.JSON_LINES,
            poisoned.encode("utf-8"),
            b"",
            tmp_path,
            tool_id="interactsh_client",
        )

    assert len(findings) == 1
    assert any(
        getattr(record, "event", "") == "parsers_jsonl_malformed"
        for record in caplog.records
    ), "missing parsers.jsonl.malformed warning"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_dispatch_is_deterministic_across_repeated_runs(tmp_path: Path) -> None:
    """Two dispatch calls on the same payload produce identical sidecars."""
    artifacts_a = tmp_path / "a"
    artifacts_b = tmp_path / "b"
    payload = _to_jsonl([_http_record(), _dns_record()])
    dispatch_parse(
        ParseStrategy.JSON_LINES,
        payload,
        b"",
        artifacts_a,
        tool_id="interactsh_client",
    )
    dispatch_parse(
        ParseStrategy.JSON_LINES,
        payload,
        b"",
        artifacts_b,
        tool_id="interactsh_client",
    )
    sidecar_a = (artifacts_a / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    sidecar_b = (artifacts_b / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert sidecar_a == sidecar_b


# ---------------------------------------------------------------------------
# Cross-tool isolation: interactsh_client and oastify_client are distinct
# ---------------------------------------------------------------------------


def test_each_oast_tool_writes_to_its_own_artifacts_dir(tmp_path: Path) -> None:
    """interactsh_client and oastify_client run independently."""
    interactsh_dir = tmp_path / "interactsh_client"
    oastify_dir = tmp_path / "oastify_client"
    payload = _to_jsonl([_http_record()])

    dispatch_parse(
        ParseStrategy.JSON_LINES,
        payload,
        b"",
        interactsh_dir,
        tool_id="interactsh_client",
    )
    dispatch_parse(
        ParseStrategy.JSON_LINES,
        payload,
        b"",
        oastify_dir,
        tool_id="oastify_client",
    )

    interactsh_sidecar = (interactsh_dir / EVIDENCE_SIDECAR_NAME).read_text(
        encoding="utf-8"
    )
    oastify_sidecar = (oastify_dir / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")

    assert json.loads(interactsh_sidecar.strip())["tool_id"] == "interactsh_client"
    assert json.loads(oastify_sidecar.strip())["tool_id"] == "oastify_client"
