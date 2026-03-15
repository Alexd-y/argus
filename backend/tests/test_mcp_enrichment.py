"""Tests for MCP enrichment/correlation helpers for Threat Modeling and VA."""

from __future__ import annotations

import json
from pathlib import Path

from app.schemas.threat_modeling.schemas import EntryPoint, ThreatModelInputBundle
from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle
from src.recon.mcp.audit import MCP_AUDIT_LOG_FILENAME
from src.recon.mcp.policy import (
    THREAT_MODELING_POLICY_ID,
    VULNERABILITY_ANALYSIS_POLICY_ID,
    evaluate_threat_modeling_policy,
    evaluate_vulnerability_analysis_policy,
)
from src.recon.threat_modeling.mcp_enrichment import enrich_with_mcp
from src.recon.vulnerability_analysis.mcp_enrichment import enrich_va_bundle_with_mcp


class TestEvaluateThreatModelingPolicy:
    """evaluate_threat_modeling_policy behavior."""

    def test_fetch_allowed_valid_url(self) -> None:
        d = evaluate_threat_modeling_policy(
            tool_name="fetch",
            operation="enrichment",
            args={"url": "https://example.com/api"},
        )
        assert d.allowed is True
        assert d.policy_id == THREAT_MODELING_POLICY_ID

    def test_fetch_denied_missing_url(self) -> None:
        d = evaluate_threat_modeling_policy(
            tool_name="fetch",
            operation="enrichment",
            args={},
        )
        assert d.allowed is False
        assert "missing" in d.reason.lower()

    def test_read_file_allowed_safe_path(self) -> None:
        d = evaluate_threat_modeling_policy(
            tool_name="read_file",
            operation="enrichment",
            args={"path": "stage2_structured.json"},
        )
        assert d.allowed is True

    def test_read_file_denied_path_traversal(self) -> None:
        d = evaluate_threat_modeling_policy(
            tool_name="read_file",
            operation="enrichment",
            args={"path": "../../../etc/passwd"},
        )
        assert d.allowed is False
        assert "path" in d.reason.lower()

    def test_tool_not_allowlisted(self) -> None:
        d = evaluate_threat_modeling_policy(
            tool_name="dangerous_tool",
            operation="enrichment",
            args={},
        )
        assert d.allowed is False
        assert "tool" in d.reason.lower()


class TestEvaluateVulnerabilityAnalysisPolicy:
    """evaluate_vulnerability_analysis_policy behavior."""

    def test_fetch_allowed_valid_url(self) -> None:
        d = evaluate_vulnerability_analysis_policy(
            tool_name="fetch",
            operation="enrichment",
            args={"url": "https://example.com/api"},
        )
        assert d.allowed is True
        assert d.policy_id == VULNERABILITY_ANALYSIS_POLICY_ID

    def test_fetch_denied_missing_url(self) -> None:
        d = evaluate_vulnerability_analysis_policy(
            tool_name="fetch",
            operation="enrichment",
            args={},
        )
        assert d.allowed is False
        assert "missing" in d.reason.lower()

    def test_read_file_allowed_safe_path(self) -> None:
        d = evaluate_vulnerability_analysis_policy(
            tool_name="read_file",
            operation="enrichment",
            args={"path": "stage2_structured.json"},
        )
        assert d.allowed is True

    def test_operation_not_allowlisted(self) -> None:
        d = evaluate_vulnerability_analysis_policy(
            tool_name="fetch",
            operation="endpoint_extraction",
            args={"url": "https://example.com/"},
        )
        assert d.allowed is False
        assert "operation" in d.reason.lower()

    def test_denylist_keyword_rejected(self) -> None:
        d = evaluate_vulnerability_analysis_policy(
            tool_name="fetch",
            operation="enrichment",
            args={"url": "https://example.com/", "payload": "sqli"},
        )
        assert d.allowed is False
        assert "denylist" in d.reason.lower()


class TestEnrichWithMCP:
    """enrich_with_mcp behavior."""

    def test_empty_mcp_tools_returns_empty(self) -> None:
        bundle = ThreatModelInputBundle(engagement_id="e1")
        traces = enrich_with_mcp(bundle, [], "run1", "job1")
        assert traces == []

    def test_no_allowlisted_tools_returns_empty(self) -> None:
        bundle = ThreatModelInputBundle(engagement_id="e1")
        traces = enrich_with_mcp(bundle, ["unknown_tool"], "run1", "job1")
        assert traces == []

    def test_fetch_invocation_trace_format(self, tmp_path: Path) -> None:
        bundle = ThreatModelInputBundle(
            engagement_id="e1",
            entry_points=[
                EntryPoint(
                    id="ep1",
                    name="API",
                    entry_type="rest",
                    host_or_component="https://example.com/api",
                ),
            ],
        )
        traces = enrich_with_mcp(
            bundle,
            ["fetch"],
            "run1",
            "job1",
            recon_dir=tmp_path,
            timeout=1.0,
        )

        assert len(traces) >= 1
        t = traces[0]
        assert t.tool_name == "fetch"
        assert t.invocation_id.startswith("run1:job1:mcp:fetch:")
        assert "url" in t.input_summary
        assert "status" in t.output_summary or "body_preview" in t.output_summary

    def test_read_file_with_recon_dir(self, tmp_path: Path) -> None:
        (tmp_path / "artifact.json").write_text('{"x": 1}', encoding="utf-8")
        bundle = ThreatModelInputBundle(
            engagement_id="e1",
            artifact_refs=["artifact.json"],
        )
        traces = enrich_with_mcp(
            bundle,
            ["read_file"],
            "run1",
            "job1",
            recon_dir=tmp_path,
        )

        assert len(traces) == 1
        t = traces[0]
        assert t.tool_name == "read_file"
        assert t.invocation_id.startswith("run1:job1:mcp:read_file:")
        assert t.input_summary.get("path") == "artifact.json"
        assert "lines" in t.output_summary or "error" in t.output_summary

    def test_read_file_skipped_without_recon_dir(self) -> None:
        bundle = ThreatModelInputBundle(
            engagement_id="e1",
            artifact_refs=["stage2_structured.json"],
        )
        traces = enrich_with_mcp(bundle, ["read_file"], "run1", "job1")
        assert traces == []

    def test_audit_context_written(self, tmp_path: Path) -> None:
        bundle = ThreatModelInputBundle(
            engagement_id="e1",
            entry_points=[
                EntryPoint(
                    id="ep1",
                    name="API",
                    entry_type="rest",
                    host_or_component="https://example.com/",
                ),
            ],
        )
        enrich_with_mcp(
            bundle,
            ["fetch"],
            "run1",
            "job1",
            recon_dir=tmp_path,
            timeout=1.0,
        )

        audit_log = tmp_path / MCP_AUDIT_LOG_FILENAME
        if audit_log.exists():
            lines = [line for line in audit_log.read_text(encoding="utf-8").splitlines() if line.strip()]
            assert any("fetch" in json.loads(line).get("tool", "") for line in lines)


class TestEnrichVaBundleWithMCP:
    """enrich_va_bundle_with_mcp behavior."""

    def test_empty_mcp_tools_returns_empty(self) -> None:
        bundle = VulnerabilityAnalysisInputBundle(engagement_id="e1")
        traces = enrich_va_bundle_with_mcp(bundle, [], "run1", "job1")
        assert traces == []

    def test_no_allowlisted_tools_returns_empty(self) -> None:
        bundle = VulnerabilityAnalysisInputBundle(engagement_id="e1")
        traces = enrich_va_bundle_with_mcp(bundle, ["unknown_tool"], "run1", "job1")
        assert traces == []

    def test_fetch_from_entry_points(self, tmp_path: Path) -> None:
        from app.schemas.threat_modeling.schemas import EntryPoint

        bundle = VulnerabilityAnalysisInputBundle(
            engagement_id="e1",
            entry_points=[
                EntryPoint(
                    id="ep1",
                    name="API",
                    entry_type="rest",
                    host_or_component="https://example.com/api",
                ),
            ],
        )
        traces = enrich_va_bundle_with_mcp(
            bundle,
            ["fetch"],
            "run1",
            "job1",
            recon_dir=tmp_path,
            timeout=1.0,
        )
        assert len(traces) >= 1
        t = traces[0]
        assert t.tool_name == "fetch"
        assert t.invocation_id.startswith("run1:job1:mcp:fetch:")

    def test_read_file_with_recon_dir(self, tmp_path: Path) -> None:
        (tmp_path / "artifact.json").write_text('{"x": 1}', encoding="utf-8")
        bundle = VulnerabilityAnalysisInputBundle(
            engagement_id="e1",
            artifact_refs=["artifact.json"],
        )
        traces = enrich_va_bundle_with_mcp(
            bundle,
            ["read_file"],
            "run1",
            "job1",
            recon_dir=tmp_path,
        )
        assert len(traces) == 1
        t = traces[0]
        assert t.tool_name == "read_file"
        assert t.input_summary.get("path") == "artifact.json"

    def test_url_artifact_refs_skipped_for_read_file(self, tmp_path: Path) -> None:
        bundle = VulnerabilityAnalysisInputBundle(
            engagement_id="e1",
            artifact_refs=["https://example.com/page"],
        )
        traces = enrich_va_bundle_with_mcp(
            bundle,
            ["read_file"],
            "run1",
            "job1",
            recon_dir=tmp_path,
        )
        assert traces == []
