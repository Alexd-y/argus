"""Unit tests for :mod:`src.sandbox.adapter_base`.

Covers Backlog/dev1_md §3 — the :class:`ToolAdapter` Protocol and its concrete
:class:`ShellToolAdapter` base implementation. The Protocol is duck-typed
(``runtime_checkable``); the base class must satisfy it without any extra
boilerplate so concrete tool adapters can subclass it freely.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from src.pipeline.contracts.finding_dto import FindingCategory
from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import TargetKind, TargetSpec, ToolJob
from src.sandbox.adapter_base import (
    AdapterExecutionError,
    NetworkPolicyRef,
    ParseStrategy,
    ResourceLimits,
    ShellToolAdapter,
    ToolAdapter,
    ToolCategory,
    ToolDescriptor,
)
from src.sandbox.parsers import HEARTBEAT_TAG_PREFIX
from src.sandbox.templating import TemplateRenderError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_descriptor(
    sample_descriptor_payload: Callable[..., dict[str, object]],
    **overrides: object,
) -> ToolDescriptor:
    payload = sample_descriptor_payload()
    payload.update(overrides)
    return ToolDescriptor(**payload)  # type: ignore[arg-type]


def _make_job(
    descriptor: ToolDescriptor,
    parameters: dict[str, str] | None = None,
    target: TargetSpec | None = None,
) -> ToolJob:
    return ToolJob(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        tool_id=descriptor.tool_id,
        phase=descriptor.phase,
        risk_level=descriptor.risk_level,
        target=target or TargetSpec(kind=TargetKind.HOST, host="example.com"),
        parameters=parameters or {"host": "example.com", "out_dir": "/out/job-1"},
        outputs_dir="/out/job-1",
        timeout_s=60,
        correlation_id="ut-test",
    )


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


def test_network_policy_ref_minimal() -> None:
    ref = NetworkPolicyRef(name="recon")
    assert ref.name == "recon"
    assert ref.egress_allowlist == []
    assert ref.dns_resolvers == []


def test_network_policy_ref_is_frozen() -> None:
    ref = NetworkPolicyRef(name="recon")
    with pytest.raises(ValidationError):
        ref.name = "other"  # type: ignore[misc]


def test_resource_limits_happy() -> None:
    limits = ResourceLimits(
        cpu_limit="500m", memory_limit="256Mi", default_timeout_s=300
    )
    assert limits.pids_limit == 256


def test_resource_limits_rejects_zero_timeout() -> None:
    with pytest.raises(ValidationError):
        ResourceLimits(cpu_limit="500m", memory_limit="256Mi", default_timeout_s=0)


# ---------------------------------------------------------------------------
# ToolDescriptor
# ---------------------------------------------------------------------------


def test_tool_descriptor_happy(
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    descriptor = _make_descriptor(sample_descriptor_payload)
    assert descriptor.tool_id == "nmap_quick"
    assert descriptor.category is ToolCategory.RECON
    assert descriptor.phase is ScanPhase.RECON
    assert descriptor.parse_strategy is ParseStrategy.XML_NMAP


def test_tool_descriptor_is_frozen(
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    descriptor = _make_descriptor(sample_descriptor_payload)
    with pytest.raises(ValidationError):
        descriptor.tool_id = "other"  # type: ignore[misc]


def test_tool_descriptor_rejects_extra_fields(
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_descriptor_payload()
    payload["extra_field"] = "nope"
    with pytest.raises(ValidationError):
        ToolDescriptor(**payload)  # type: ignore[arg-type]


def test_tool_descriptor_rejects_bad_tool_id(
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_descriptor_payload()
    payload["tool_id"] = "BadID"
    with pytest.raises(ValidationError):
        ToolDescriptor(**payload)  # type: ignore[arg-type]


def test_tool_descriptor_resource_limits_view(
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    descriptor = _make_descriptor(sample_descriptor_payload)
    limits = descriptor.resource_limits()
    assert limits.cpu_limit == descriptor.cpu_limit
    assert limits.memory_limit == descriptor.memory_limit
    assert limits.default_timeout_s == descriptor.default_timeout_s
    assert limits.pids_limit == descriptor.pids_limit


# ---------------------------------------------------------------------------
# ShellToolAdapter
# ---------------------------------------------------------------------------


def test_shell_adapter_conforms_to_protocol(
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    descriptor = _make_descriptor(sample_descriptor_payload)
    adapter = ShellToolAdapter(descriptor)
    assert isinstance(adapter, ToolAdapter)


def test_shell_adapter_mirrors_descriptor_attributes(
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    descriptor = _make_descriptor(sample_descriptor_payload)
    adapter = ShellToolAdapter(descriptor)
    assert adapter.tool_id == descriptor.tool_id
    assert adapter.category is descriptor.category
    assert adapter.phase is descriptor.phase
    assert adapter.risk_level is descriptor.risk_level
    assert adapter.requires_approval == descriptor.requires_approval
    assert adapter.network_policy == descriptor.network_policy
    assert adapter.seccomp_profile == descriptor.seccomp_profile
    assert adapter.default_timeout_s == descriptor.default_timeout_s
    assert adapter.cpu_limit == descriptor.cpu_limit
    assert adapter.memory_limit == descriptor.memory_limit


def test_shell_adapter_build_command_renders_argv(
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    descriptor = _make_descriptor(sample_descriptor_payload)
    adapter = ShellToolAdapter(descriptor)
    job = _make_job(descriptor)
    argv = adapter.build_command(job)
    assert argv == ["nmap", "-Pn", "-T4", "example.com", "-oX", "/out/job-1/nmap.xml"]


def test_shell_adapter_build_command_rejects_mismatched_tool_id(
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    descriptor = _make_descriptor(sample_descriptor_payload)
    adapter = ShellToolAdapter(descriptor)
    job = ToolJob(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        tool_id="other_tool",
        phase=descriptor.phase,
        risk_level=descriptor.risk_level,
        target=TargetSpec(kind=TargetKind.HOST, host="example.com"),
        parameters={"host": "example.com", "out_dir": "/out/job-1"},
        outputs_dir="/out/job-1",
        timeout_s=60,
        correlation_id="ut-test",
    )
    with pytest.raises(AdapterExecutionError):
        adapter.build_command(job)


def test_shell_adapter_parse_output_default_emits_heartbeat_and_warns(
    caplog: pytest.LogCaptureFixture,
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    """Strategies without a registered handler fail-soft via the dispatch layer.

    ``csv`` is a canonical example — no parser is registered for it yet, so
    ``dispatch_parse`` emits a single :class:`FindingDTO` heartbeat
    (``FindingCategory.INFO``, ``ARGUS-HEARTBEAT`` tag) AND a structured
    ``parsers.dispatch.no_handler`` WARNING.  This replaces the legacy
    ``tool_adapter.parse_output_not_implemented`` warning emitted before
    the dispatch layer was wired into :meth:`ShellToolAdapter.parse_output`.

    Note: ``xml_nmap`` was the original sentinel here, but ARG-019 wired
    :func:`src.sandbox.parsers.nmap_parser.parse_nmap_xml` against it, so
    we now use ``csv`` (deferred to a future cycle) to exercise the
    no-handler fail-soft path.

    ARG-020 (cycle 2 capstone): the dispatch contract upgraded the
    fail-soft branch from ``[]`` to ``[heartbeat]`` so the orchestrator /
    UI can distinguish "tool ran but parser deferred" from "tool ran and
    found nothing".  The structured warning is unchanged.
    """
    descriptor = _make_descriptor(
        sample_descriptor_payload,
        parse_strategy="csv",
    )
    adapter = ShellToolAdapter(descriptor)
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        result = adapter.parse_output(b"col1,col2\nvalue,42\n", b"", Path("/out/job-1"))

    assert len(result) == 1, (
        "no-handler fail-soft must emit exactly one heartbeat FindingDTO"
    )
    heartbeat = result[0]
    assert heartbeat.category is FindingCategory.INFO
    assert heartbeat.cvss_v3_score == 0.0
    assert HEARTBEAT_TAG_PREFIX in heartbeat.owasp_wstg
    assert f"HEARTBEAT-{descriptor.tool_id}" in heartbeat.owasp_wstg
    assert "HEARTBEAT-STRATEGY-csv" in heartbeat.owasp_wstg

    assert any("parsers.dispatch.no_handler" in r.message for r in caplog.records), [
        r.message for r in caplog.records
    ]
    assert not any(
        "parse_output_not_implemented" in r.message for r in caplog.records
    ), "legacy warning must be retired once dispatch_parse is wired in"


def test_shell_adapter_parse_output_binary_blob_does_not_warn(
    caplog: pytest.LogCaptureFixture,
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    """``binary_blob`` short-circuits before the dispatch layer.

    Binary evidence is consumed downstream; the FindingDTO normaliser is
    intentionally skipped, so neither the legacy nor the new warning may
    fire.
    """
    descriptor = _make_descriptor(
        sample_descriptor_payload,
        parse_strategy="binary_blob",
        evidence_artifacts=[],
        cwe_hints=[],
        owasp_wstg=[],
    )
    adapter = ShellToolAdapter(descriptor)
    with caplog.at_level(logging.WARNING):
        result = adapter.parse_output(b"\x00\x01", b"", Path("/out/job-1"))
    assert result == []
    assert not any("parse_output_not_implemented" in r.message for r in caplog.records)
    assert not any("parsers.dispatch" in r.message for r in caplog.records)


def test_shell_adapter_collect_evidence_default_returns_empty(
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    descriptor = _make_descriptor(sample_descriptor_payload)
    adapter = ShellToolAdapter(descriptor)
    job = _make_job(descriptor)
    assert adapter.collect_evidence(job, Path("/tmp")) == []


def test_shell_adapter_constructor_rejects_invalid_template(
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_descriptor_payload()
    payload["command_template"] = ["nmap", "{secret_key_no_no}"]
    descriptor = ToolDescriptor(**payload)  # type: ignore[arg-type]
    with pytest.raises(TemplateRenderError):
        ShellToolAdapter(descriptor)


def test_shell_adapter_descriptor_property_round_trips(
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    descriptor = _make_descriptor(sample_descriptor_payload)
    adapter = ShellToolAdapter(descriptor)
    assert adapter.descriptor is descriptor
