"""Unit tests for :meth:`ShellToolAdapter.parse_output` dispatch wiring.

ARG-016/017 — Reviewer C3, refreshed by ARG-020 (cycle 2 capstone).

The adapter base no longer ships an inert ``parse_output`` stub: it
dispatches into :func:`src.sandbox.parsers.dispatch_parse` which routes
``(parse_strategy, tool_id)`` to the registered parser. These tests cover
the three branches that matter for production:

* **Happy path** — a strategy + tool_id pair with a registered parser
  (``json_lines`` + ``httpx``) produces real :class:`FindingDTO` instances
  and the legacy ``tool_adapter.parse_output_not_implemented`` warning is
  silent.
* **Unmapped tool** — a strategy with a handler but a tool_id that has no
  per-tool parser (``json_lines`` + ``unmapped_tool_xyz``) fail-soft
  emits a single :class:`FindingDTO` heartbeat (ARG-020:
  ``FindingCategory.INFO``, ``ARGUS-HEARTBEAT`` tag) AND a structured
  ``parsers.dispatch.unmapped_tool`` WARNING.
* **Binary blob short-circuit** — ``binary_blob`` returns ``[]`` *before*
  hitting the dispatch layer, so neither warning nor heartbeat fires.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path

import pytest

from src.pipeline.contracts.finding_dto import FindingCategory, FindingDTO
from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor
from src.sandbox.parsers import HEARTBEAT_TAG_PREFIX


def _httpx_payload(
    sample_descriptor_payload: Callable[..., dict[str, object]],
    *,
    tool_id: str = "httpx",
) -> dict[str, object]:
    payload = sample_descriptor_payload(tool_id)
    payload.update(
        {
            "category": "web_va",
            "phase": "vuln_analysis",
            "command_template": ["httpx", "-u", "{url}"],
            "parse_strategy": "json_lines",
            "evidence_artifacts": [],
            "cwe_hints": [],
            "owasp_wstg": [],
        }
    )
    return payload


_HTTPX_JSONL_FIXTURE = (
    json.dumps(
        {
            "url": "https://example.com",
            "status_code": 200,
            "title": "Example Domain",
            "tech": ["Nginx"],
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    + "\n"
)


def test_parse_output_dispatches_to_registered_handler(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    """JSON_LINES + ``httpx`` round-trips through the dispatch table."""
    descriptor = ToolDescriptor(**_httpx_payload(sample_descriptor_payload))  # type: ignore[arg-type]
    adapter = ShellToolAdapter(descriptor)

    with caplog.at_level(logging.WARNING):
        findings = adapter.parse_output(
            _HTTPX_JSONL_FIXTURE.encode("utf-8"),
            b"",
            tmp_path,
        )

    assert findings, "httpx parser must emit at least one finding for a valid record"
    assert all(isinstance(f, FindingDTO) for f in findings)
    assert not any(
        "parse_output_not_implemented" in r.message for r in caplog.records
    ), "legacy stub warning must not fire once dispatch_parse is wired in"
    assert not any("parsers.dispatch.no_handler" in r.message for r in caplog.records)
    assert not any(
        "parsers.dispatch.unmapped_tool" in r.message for r in caplog.records
    )


def test_parse_output_unmapped_tool_emits_heartbeat_and_warns(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    """Registered strategy + unmapped tool_id ⇒ one heartbeat + structured warning.

    ARG-020 (cycle 2 capstone) upgraded the fail-soft contract from ``[]``
    to ``[heartbeat]`` so the orchestrator / UI can surface
    "tool ran, parser deferred" without confusing it with
    "tool ran, found nothing".  The structured warning still fires so the
    operator sees the gap in real time.
    """
    payload = _httpx_payload(sample_descriptor_payload, tool_id="unmapped_tool_xyz")
    descriptor = ToolDescriptor(**payload)  # type: ignore[arg-type]
    adapter = ShellToolAdapter(descriptor)

    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = adapter.parse_output(
            _HTTPX_JSONL_FIXTURE.encode("utf-8"), b"", tmp_path
        )

    assert len(findings) == 1, (
        "unmapped-tool fail-soft must emit exactly one heartbeat FindingDTO"
    )
    heartbeat = findings[0]
    assert isinstance(heartbeat, FindingDTO)
    assert heartbeat.category is FindingCategory.INFO
    assert heartbeat.cvss_v3_score == 0.0
    assert HEARTBEAT_TAG_PREFIX in heartbeat.owasp_wstg
    assert "HEARTBEAT-unmapped_tool_xyz" in heartbeat.owasp_wstg
    assert "HEARTBEAT-STRATEGY-json_lines" in heartbeat.owasp_wstg

    assert any("parsers.dispatch.unmapped_tool" in r.message for r in caplog.records), [
        r.message for r in caplog.records
    ]


def test_parse_output_binary_blob_short_circuits_dispatch(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    """``binary_blob`` skips the dispatch layer entirely (no warnings)."""
    payload = sample_descriptor_payload()
    payload.update(
        {
            "parse_strategy": "binary_blob",
            "evidence_artifacts": [],
            "cwe_hints": [],
            "owasp_wstg": [],
        }
    )
    descriptor = ToolDescriptor(**payload)  # type: ignore[arg-type]
    adapter = ShellToolAdapter(descriptor)

    with caplog.at_level(logging.WARNING):
        findings = adapter.parse_output(b"\x00\x01binary", b"", tmp_path)

    assert findings == []
    assert not any("parsers.dispatch" in r.message for r in caplog.records)
    assert not any("parse_output_not_implemented" in r.message for r in caplog.records)
