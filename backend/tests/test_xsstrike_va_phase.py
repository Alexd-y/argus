"""XSS-002: XSStrike phase in VA pipeline — intel merge and raw sink behavior (mocked adapter)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle

from src.recon.vulnerability_analysis.pipeline import (
    RAW_PHASE_VULN_ANALYSIS,
    _run_xsstrike_va_phase,
)


def _bundle_with_param_jobs() -> VulnerabilityAnalysisInputBundle:
    return VulnerabilityAnalysisInputBundle(
        engagement_id="e1",
        params_inventory=[
            {"param": "a", "route": "/one", "host": "example.com"},
            {"param": "b", "route": "/two", "host": "example.com"},
        ],
    )


@pytest.mark.asyncio
async def test_run_xsstrike_va_phase_merges_intel_and_sinks_raw() -> None:
    """Mock run_with_capture; assert intel_findings append order and sink_raw_* calls."""
    bundle = _bundle_with_param_jobs()
    bundle = bundle.model_copy(
        update={"intel_findings": [{"source": "prior", "id": "p0"}]}
    )

    mock_instance = MagicMock()
    mock_instance.run_with_capture = AsyncMock(
        side_effect=[
            ([{"f": "one"}], "stdout_a", "stderr_a"),
            ([{"f": "two"}], "stdout_b", "stderr_b"),
        ]
    )

    log_lines: list[str] = []

    def _log(msg: str) -> None:
        log_lines.append(msg)

    with (
        patch(
            "src.recon.vulnerability_analysis.pipeline.XSStrikeAdapter",
            return_value=mock_instance,
        ),
        patch(
            "src.recon.vulnerability_analysis.pipeline.sink_raw_text"
        ) as mock_sink_text,
        patch(
            "src.recon.vulnerability_analysis.pipeline.sink_raw_json"
        ) as mock_sink_json,
    ):
        out = await _run_xsstrike_va_phase(
            bundle,
            tenant_id_raw="tenant-1",
            scan_id_raw="scan-99",
            va_raw_log=_log,
        )

    assert out.intel_findings == [
        {"source": "prior", "id": "p0"},
        {"f": "one"},
        {"f": "two"},
    ]

    assert mock_instance.run_with_capture.await_count == 2
    first_call = mock_instance.run_with_capture.await_args_list[0]
    assert "example.com" in first_call.args[0] and "a" in first_call.args[0]
    assert first_call.args[1] == {}
    second = mock_instance.run_with_capture.await_args_list[1]
    assert "b" in second.args[0]

    text_calls = [c.kwargs for c in mock_sink_text.call_args_list]
    assert len(text_calls) == 6
    for c in text_calls:
        assert c["tenant_id"] == "tenant-1"
        assert c["scan_id"] == "scan-99"
        assert c["phase"] == RAW_PHASE_VULN_ANALYSIS
        assert c["ext"] == "txt"

    stdout_types = [c["artifact_type"] for c in text_calls if "stdout" in c["artifact_type"]]
    stderr_types = [c["artifact_type"] for c in text_calls if "stderr" in c["artifact_type"]]
    audit_types = [c["artifact_type"] for c in text_calls if "http_audit" in c["artifact_type"]]
    assert len(stdout_types) == 2 and len(stderr_types) == 2 and len(audit_types) == 2
    texts_by_kind: dict[str, list[str]] = {"stdout": [], "stderr": [], "audit": []}
    for c in text_calls:
        at = c["artifact_type"]
        if "stdout" in at:
            texts_by_kind["stdout"].append(c["text"])
        elif "stderr" in at:
            texts_by_kind["stderr"].append(c["text"])
        elif "http_audit" in at:
            texts_by_kind["audit"].append(c["text"])
    assert set(texts_by_kind["stdout"]) == {"stdout_a", "stdout_b"}
    assert set(texts_by_kind["stderr"]) == {"stderr_a", "stderr_b"}
    assert len(texts_by_kind["audit"]) == 2

    merged_json_calls = [
        c
        for c in mock_sink_json.call_args_list
        if c.kwargs.get("artifact_type") == "tool_xsstrike_findings_merged"
    ]
    assert len(merged_json_calls) == 1
    mj = merged_json_calls[0].kwargs
    assert mj["payload"] == [{"f": "one"}, {"f": "two"}]
    assert mj["phase"] == RAW_PHASE_VULN_ANALYSIS

    assert any("xsstrike_phase_done jobs=2 findings_normalized=2" in line for line in log_lines)


@pytest.mark.asyncio
async def test_run_xsstrike_va_phase_no_jobs_short_circuits() -> None:
    bundle = VulnerabilityAnalysisInputBundle(engagement_id="e1")

    with patch(
        "src.recon.vulnerability_analysis.pipeline.XSStrikeAdapter"
    ) as mock_cls:
        out = await _run_xsstrike_va_phase(
            bundle,
            tenant_id_raw=None,
            scan_id_raw="job-x",
            va_raw_log=lambda _m: None,
        )

    mock_cls.assert_not_called()
    assert out is bundle


@pytest.mark.asyncio
async def test_run_xsstrike_va_phase_adapter_error_still_sinks_and_merges_empty() -> None:
    bundle = _bundle_with_param_jobs().model_copy(
        update={"intel_findings": [{"kept": True}]}
    )

    mock_instance = MagicMock()
    mock_instance.run_with_capture = AsyncMock(side_effect=RuntimeError("xsstrike_failed"))

    log_lines: list[str] = []

    with (
        patch(
            "src.recon.vulnerability_analysis.pipeline.XSStrikeAdapter",
            return_value=mock_instance,
        ),
        patch("src.recon.vulnerability_analysis.pipeline.sink_raw_text") as mock_sink_text,
        patch("src.recon.vulnerability_analysis.pipeline.sink_raw_json") as mock_sink_json,
    ):
        out = await _run_xsstrike_va_phase(
            bundle,
            tenant_id_raw="t",
            scan_id_raw="s",
            va_raw_log=log_lines.append,
        )

    assert out.intel_findings == [{"kept": True}]
    assert mock_instance.run_with_capture.await_count == 2
    assert all("xsstrike_job_error" in line for line in log_lines[:2])
    assert any("findings_normalized=0" in line for line in log_lines)

    merged = [
        c.kwargs
        for c in mock_sink_json.call_args_list
        if c.kwargs.get("artifact_type") == "tool_xsstrike_findings_merged"
    ]
    assert len(merged) == 1 and merged[0]["payload"] == []

    for c in mock_sink_text.call_args_list:
        at = c.kwargs["artifact_type"]
        if "http_audit" in at:
            assert "curl" in c.kwargs["text"]
        else:
            assert c.kwargs["text"] == ""
