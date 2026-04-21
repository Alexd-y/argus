"""Integration test: ARG-020 heartbeat finding contract.

ARG-020 (Cycle 2 capstone) replaced the silent ``return []`` fail-soft
branches in :mod:`src.sandbox.parsers` with a structured heartbeat
:class:`FindingDTO`.  This module pins the heartbeat's full DTO
contract — category / severity / CVSS / CWE / SSVC / WSTG tags — so a
future refactor cannot weaken it without breaking a focused test, and
exercises every code path that currently emits one (unmapped tool inside
a known strategy AND unknown strategy).

The contract is deliberately split out from
:mod:`tests.integration.sandbox.parsers.test_dispatch_registry` (which
covers the broader dispatch wiring) so a developer reading the heartbeat
contract does not have to sift through unrelated registry-override / hot-
swap tests.

Hermetic by design: the autouse :func:`reset_registry` fixture restores
the default registry around every test, so unrelated suites running in
the same session cannot bleed state in.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingStatus,
    SSVCDecision,
)
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import (
    HEARTBEAT_TAG_PREFIX,
    dispatch_parse,
    reset_registry,
)


# ---------------------------------------------------------------------------
# Hermetic registry fixture (ARG-020 default surface).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_registry() -> Iterator[None]:
    """Snapshot + restore the registry around every test."""
    yield
    reset_registry()


# ---------------------------------------------------------------------------
# Full DTO contract — pinned because the heartbeat is the only new
# write-path the orchestrator / UI consume from ``dispatch_parse``.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("strategy", "tool_id", "expected_strategy_value"),
    [
        # Path 1: unmapped tool inside a known strategy (closure branch).
        pytest.param(
            ParseStrategy.JSON_LINES,
            "tool_does_not_exist",
            "json_lines",
            id="unmapped_tool_known_strategy",
        ),
        # Path 2: unknown strategy (top-level dispatch branch).  ``CSV``
        # is intentionally NOT in the default surface (pinned by
        # ``test_default_registry_does_not_register_unimplemented_strategies``
        # in ``test_dispatch_registry``).
        pytest.param(
            ParseStrategy.CSV,
            "tool_under_csv",
            "csv",
            id="unknown_strategy",
        ),
    ],
)
def test_heartbeat_finding_dto_contract(
    strategy: ParseStrategy,
    tool_id: str,
    expected_strategy_value: str,
    tmp_path: Path,
) -> None:
    """Heartbeat carries the canonical ARG-020 DTO surface for both branches.

    Pins the operator-visible contract:

    * **Category / severity** — :data:`FindingCategory.INFO` and CVSS 0.0
      so the normaliser maps it onto severity ``info`` and the heartbeat
      can never raise the scan's worst-severity bar.
    * **CWE-1059** (Insufficient Technical Documentation) — the catalog
      shipped the tool but ARGUS lacks the technical wiring to interpret
      its output, which is exactly what the CWE codifies.
    * **Confidence / status / SSVC** — ``SUSPECTED`` / ``NEW`` /
      ``TRACK`` so triage tooling does not auto-prioritise these.
    * **WSTG tags** — exactly three identifiers in order:
      ``ARGUS-HEARTBEAT``, ``HEARTBEAT-{tool_id}``,
      ``HEARTBEAT-STRATEGY-{strategy.value}`` so the UI / query layer
      can pivot on any of the three without parsing free-form fields.
    """
    findings = dispatch_parse(
        strategy,
        b"raw stdout that should be ignored",
        b"raw stderr that should be ignored",
        tmp_path,
        tool_id=tool_id,
    )

    assert len(findings) == 1, (
        f"heartbeat path must emit exactly one finding, got {len(findings)}"
    )
    heartbeat = findings[0]

    assert heartbeat.category is FindingCategory.INFO
    assert heartbeat.cvss_v3_score == 0.0
    assert heartbeat.cwe == [1059], (
        "heartbeat must declare CWE-1059 (Insufficient Technical Documentation) "
        "so coverage gaps are aggregable in the UI"
    )
    assert heartbeat.confidence is ConfidenceLevel.SUSPECTED
    assert heartbeat.status is FindingStatus.NEW
    assert heartbeat.ssvc_decision is SSVCDecision.TRACK
    assert heartbeat.owasp_wstg == [
        HEARTBEAT_TAG_PREFIX,
        f"HEARTBEAT-{tool_id}",
        f"HEARTBEAT-STRATEGY-{expected_strategy_value}",
    ]


# ---------------------------------------------------------------------------
# Path-specific structured warning + heartbeat behaviour.
# ---------------------------------------------------------------------------


def test_heartbeat_unmapped_tool_logs_structured_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Closure branch: ``parsers.dispatch.unmapped_tool`` warning + heartbeat.

    The structured ``extra`` payload must include the canonical fields
    (``event``, ``tool_id``, ``parse_strategy``, ``artifacts_dir``,
    ``stdout_len``, ``stderr_len``) so the JSON log shipper indexes them.
    """
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = dispatch_parse(
            ParseStrategy.JSON_LINES,
            b"some-stdout",
            b"some-stderr-bytes",
            tmp_path,
            tool_id="future_jsonl_tool",
        )

    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO
    assert "HEARTBEAT-future_jsonl_tool" in findings[0].owasp_wstg

    matching = [
        record
        for record in caplog.records
        if getattr(record, "event", "") == "parsers_dispatch_unmapped_tool"
    ]
    assert matching, (
        "expected exactly one parsers_dispatch_unmapped_tool log record "
        f"in the warning stream, got {[r.getMessage() for r in caplog.records]}"
    )
    record = matching[-1]
    assert record.levelno == logging.WARNING
    assert getattr(record, "tool_id") == "future_jsonl_tool"
    assert getattr(record, "parse_strategy") == "json_lines"
    assert getattr(record, "artifacts_dir") == str(tmp_path)
    assert getattr(record, "stdout_len") == len(b"some-stdout")
    assert getattr(record, "stderr_len") == len(b"some-stderr-bytes")


def test_heartbeat_no_handler_logs_structured_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Dispatch branch: ``parsers.dispatch.no_handler`` warning + heartbeat.

    The structured ``extra`` payload must include the canonical fields
    (``event``, ``parse_strategy``, ``tool_id``, ``artifacts_dir``,
    ``stdout_len``, ``stderr_len``) so a coverage gap is queryable in
    the log pipeline without grepping free-form messages.
    """
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = dispatch_parse(
            ParseStrategy.XML_GENERIC,
            b"<root/>",
            b"",
            tmp_path,
            tool_id="future_xml_tool",
        )

    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO
    assert "HEARTBEAT-STRATEGY-xml_generic" in findings[0].owasp_wstg

    matching = [
        record
        for record in caplog.records
        if getattr(record, "event", "") == "parsers_dispatch_no_handler"
    ]
    assert matching, (
        "expected exactly one parsers_dispatch_no_handler log record in the "
        f"warning stream, got {[r.getMessage() for r in caplog.records]}"
    )
    record = matching[-1]
    assert record.levelno == logging.WARNING
    assert getattr(record, "parse_strategy") == "xml_generic"
    assert getattr(record, "tool_id") == "future_xml_tool"
    assert getattr(record, "artifacts_dir") == str(tmp_path)
    assert getattr(record, "stdout_len") == len(b"<root/>")
    assert getattr(record, "stderr_len") == 0


# ---------------------------------------------------------------------------
# Cross-cutting properties.
# ---------------------------------------------------------------------------


def test_heartbeat_returns_fresh_dto_per_dispatch(tmp_path: Path) -> None:
    """Repeated dispatches return distinct DTO instances (no shared caching).

    The heartbeat carries :data:`SENTINEL_UUID` for ``id`` / ``scan_id`` /
    ``tool_run_id`` like every other parser-layer finding (the
    :class:`src.findings.normalizer.Normalizer` re-derives the real IDs
    from the ingest context, see ``parsers/_base.py``).  But the
    *Python objects* themselves must be freshly constructed per call so
    repeated coverage-gap signals are observable downstream and a future
    "cache the heartbeat" optimisation cannot silently collapse them
    into a single record before the normaliser runs.
    """
    first = dispatch_parse(
        ParseStrategy.JSON_LINES,
        b"",
        b"",
        tmp_path,
        tool_id="future_jsonl_tool",
    )
    second = dispatch_parse(
        ParseStrategy.JSON_LINES,
        b"",
        b"",
        tmp_path,
        tool_id="future_jsonl_tool",
    )

    assert len(first) == 1
    assert len(second) == 1
    assert first[0] is not second[0], (
        "each dispatch must construct a fresh FindingDTO; a shared "
        "object reference would let a downstream mutation in one stream "
        "leak into another"
    )
    assert first[0].owasp_wstg == second[0].owasp_wstg, (
        "the WSTG tag set is the stable key the orchestrator pivots on"
    )
    # Sentinels are intentional: the normalizer overrides them with the
    # real ingest-context IDs.  Pinning this so a future "let's just put a
    # uuid4() in the heartbeat" change does not silently break the
    # parser-layer / normaliser contract.
    assert first[0].id == second[0].id == UUID(int=0)
    assert first[0].scan_id == UUID(int=0)
    assert first[0].tool_run_id == UUID(int=0)


def test_heartbeat_does_not_inherit_severity_from_inputs(
    tmp_path: Path,
) -> None:
    """Heartbeat severity stays at ``info`` regardless of tool output size.

    The fail-soft branch must never pretend to know how severe the
    underlying finding might have been — large stdout / stderr payloads
    are NOT a signal of a critical finding, just of a coverage gap.
    """
    huge_stdout = b"A" * 1024
    huge_stderr = b"B" * 1024

    findings = dispatch_parse(
        ParseStrategy.JSON_LINES,
        huge_stdout,
        huge_stderr,
        tmp_path,
        tool_id="future_jsonl_tool",
    )

    assert len(findings) == 1
    heartbeat = findings[0]
    assert heartbeat.cvss_v3_score == 0.0
    assert heartbeat.category is FindingCategory.INFO


def test_heartbeat_unique_per_tool_within_strategy(tmp_path: Path) -> None:
    """Two different tool_ids on the same strategy produce distinguishable tags.

    Operators query coverage gaps per-tool, so the strategy-level signal
    is not enough — the ``HEARTBEAT-{tool_id}`` tag must vary.
    """
    a = dispatch_parse(
        ParseStrategy.JSON_LINES, b"", b"", tmp_path, tool_id="alpha_tool"
    )
    b = dispatch_parse(
        ParseStrategy.JSON_LINES, b"", b"", tmp_path, tool_id="beta_tool"
    )

    assert len(a) == 1
    assert len(b) == 1
    assert "HEARTBEAT-alpha_tool" in a[0].owasp_wstg
    assert "HEARTBEAT-beta_tool" in b[0].owasp_wstg
    # Both share the strategy tag — pivot key for "coverage gap on json_lines".
    assert "HEARTBEAT-STRATEGY-json_lines" in a[0].owasp_wstg
    assert "HEARTBEAT-STRATEGY-json_lines" in b[0].owasp_wstg


def test_heartbeat_carries_ssvc_track_decision(tmp_path: Path) -> None:
    """SSVC decision must be ``TRACK`` — never ``ATTEND`` / ``ACT``.

    Pinned because a heartbeat does not represent an exploitable
    finding; auto-escalating it to ``ATTEND`` / ``ACT`` would page the
    on-call for what is in fact a parser-coverage gap.
    """
    findings = dispatch_parse(
        ParseStrategy.JSON_LINES,
        b"",
        b"",
        tmp_path,
        tool_id="future_jsonl_tool",
    )

    assert len(findings) == 1
    assert findings[0].ssvc_decision is SSVCDecision.TRACK
