"""Tests for Stage 1 MCP policy enforcement and audit linkage artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from src.recon.mcp.audit import MCP_AUDIT_LOG_FILENAME, MCP_AUDIT_META_FILENAME, mcp_audit_context
from src.recon.mcp.client import fetch_url_mcp
from src.recon.mcp.policy import evaluate_recon_stage1_policy, sanitize_args
from src.recon.reporting.stage1_contract import (
    STAGE1_BASELINE_ARTIFACTS,
    STAGE1_REPORT_SECTIONS,
    build_stage1_contract_snapshot,
)
from src.recon.reporting.stage1_report_generator import generate_stage1_report


def test_mcp_policy_denied_operation_is_fail_closed_and_audited(tmp_path: Path) -> None:
    with mcp_audit_context(
        stage="recon_stage1",
        run_id="run-1",
        job_id="job-1",
        recon_dir=tmp_path,
        trace_id="trace-1",
    ):
        result = fetch_url_mcp(
            "https://example.com/",
            timeout=1.0,
            operation="exploit_payload_delivery",
        )

    assert result["exists"] is False
    assert result["notes"] == "mcp_operation_denied_by_policy"

    audit_log = tmp_path / MCP_AUDIT_LOG_FILENAME
    assert audit_log.exists()
    lines = [line for line in audit_log.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines
    event = json.loads(lines[-1])
    assert event["allowed"] is False
    assert event["stage"] == "recon_stage1"
    assert event["run_id"] == "run-1"
    assert event["job_id"] == "job-1"
    assert event["trace_id"] == "trace-1"
    assert event["tool"] == "fetch"
    assert event["operation"] == "exploit_payload_delivery"
    assert "url" in event["args_sanitized"]


def test_mcp_policy_allowed_operation_is_audited(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "src.recon.mcp.client._fetch_via_mcp_sync",
        lambda _url, _timeout: {
            "status": 200,
            "headers": {},
            "body": "<html>ok</html>",
            "content_type": "text/html",
            "exists": True,
            "notes": "",
        },
    )

    with mcp_audit_context(
        stage="recon_stage1",
        run_id="run-2",
        job_id="job-2",
        recon_dir=tmp_path,
        trace_id="trace-2",
    ):
        result = fetch_url_mcp(
            "https://example.com/callback?token=very-secret&next=/home",
            timeout=1.0,
            operation="route_endpoint_extraction",
        )

    assert result["exists"] is True
    audit_log = tmp_path / MCP_AUDIT_LOG_FILENAME
    lines = [line for line in audit_log.read_text(encoding="utf-8").splitlines() if line.strip()]
    event = json.loads(lines[-1])
    assert event["allowed"] is True
    assert event["decision_reason"] == "allowed"
    assert "very-secret" not in json.dumps(event["args_sanitized"])
    assert "token=%5BREDACTED%5D" in event["args_sanitized"]["url"]


def test_stage1_report_writes_contract_and_mcp_linkage_artifacts(tmp_path: Path) -> None:
    scope_dir = tmp_path / "00_scope"
    domains_dir = tmp_path / "01_domains"
    subdomains_dir = tmp_path / "02_subdomains"
    dns_dir = tmp_path / "03_dns"
    live_dir = tmp_path / "04_live_hosts"
    scope_dir.mkdir()
    domains_dir.mkdir()
    subdomains_dir.mkdir()
    dns_dir.mkdir()
    live_dir.mkdir()

    (scope_dir / "scope.txt").write_text("example.com\n*.example.com", encoding="utf-8")
    (domains_dir / "whois.txt").write_text("Domain Name: example.com", encoding="utf-8")
    (domains_dir / "ns.txt").write_text("example.com. nameserver = ns1.example.com.", encoding="utf-8")
    (subdomains_dir / "subdomains_clean.txt").write_text("www.example.com", encoding="utf-8")
    (dns_dir / "resolved.txt").write_text("www.example.com -> 93.184.216.34", encoding="utf-8")
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.com,https://example.com/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )

    generate_stage1_report(
        tmp_path,
        use_mcp=False,
        fetch_func=lambda _url: {"status": 200, "content_type": "text/plain", "exists": True, "notes": "mock"},
        headers_fetch_func=lambda url, _timeout=10.0: {"status_code": 200, "headers": {}, "url": url},
    )

    contract_path = tmp_path / "stage1_contract_baseline.json"
    assert contract_path.exists()
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    assert contract["stage"] == "recon_stage1"
    assert contract["run_id"] == tmp_path.name
    assert contract["job_id"] == f"{tmp_path.name}-stage1"
    assert len(contract["report_sections_required"]) == 16

    meta_path = tmp_path / MCP_AUDIT_META_FILENAME
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["stage"] == "recon_stage1"
    assert meta["run_id"] == tmp_path.name
    assert meta["job_id"] == f"{tmp_path.name}-stage1"

    assert (tmp_path / MCP_AUDIT_LOG_FILENAME).exists()


def test_stage1_contract_snapshot_includes_required_baseline_lists_and_links() -> None:
    snapshot = json.loads(
        build_stage1_contract_snapshot(run_id="run-x", job_id="job-x", trace_id="trace-x")
    )

    assert snapshot["contract_name"] == "argus_stage1_recon_baseline"
    assert snapshot["contract_version"] == "2026-03-12-stage1-a"
    assert snapshot["stage"] == "recon_stage1"
    assert snapshot["run_id"] == "run-x"
    assert snapshot["job_id"] == "job-x"
    assert snapshot["run_link"] == "recon://runs/run-x"
    assert snapshot["job_link"] == "recon://jobs/job-x"
    assert snapshot["trace_id"] == "trace-x"
    assert snapshot["artifacts_required"] == list(STAGE1_BASELINE_ARTIFACTS)
    assert snapshot["report_sections_required"] == list(STAGE1_REPORT_SECTIONS)


def test_stage1_contract_includes_rec108_ai_persistence_artifacts() -> None:
    required_rec108_artifacts = {
        "js_routes.csv",
        "js_api_refs.csv",
        "js_integrations.csv",
        "js_config_hints.csv",
        "input_surfaces.csv",
        "route_params_map.csv",
        "graphql_candidates.csv",
        "json_endpoint_candidates.csv",
        "frontend_backend_boundaries.md",
        "app_flow_hints.md",
        "host_security_posture.csv",
        "control_inconsistencies.md",
        "response_similarity.csv",
        "catch_all_evidence.md",
        "content_clusters.csv",
        "redirect_clusters.csv",
        "anomaly_validation.csv",
        "hostname_behavior_matrix.csv",
        "stage2_preparation.md",
        "ai_persistence_manifest.json",
    }
    required_ai_bundle_artifacts = {
        "ai_js_findings_analysis_raw.json",
        "ai_js_findings_analysis_normalized.json",
        "ai_js_findings_analysis_input_bundle.json",
        "ai_js_findings_analysis_validation.json",
        "ai_js_findings_analysis_rendered_prompt.md",
        "ai_parameter_input_analysis_raw.json",
        "ai_parameter_input_analysis_normalized.json",
        "ai_parameter_input_analysis_input_bundle.json",
        "ai_parameter_input_analysis_validation.json",
        "ai_parameter_input_analysis_rendered_prompt.md",
        "ai_api_surface_inference_raw.json",
        "ai_api_surface_inference_normalized.json",
        "ai_api_surface_inference_input_bundle.json",
        "ai_api_surface_inference_validation.json",
        "ai_api_surface_inference_rendered_prompt.md",
        "ai_headers_tls_summary_raw.json",
        "ai_headers_tls_summary_normalized.json",
        "ai_headers_tls_summary_input_bundle.json",
        "ai_headers_tls_summary_validation.json",
        "ai_headers_tls_summary_rendered_prompt.md",
        "ai_content_similarity_interpretation_raw.json",
        "ai_content_similarity_interpretation_normalized.json",
        "ai_content_similarity_interpretation_input_bundle.json",
        "ai_content_similarity_interpretation_validation.json",
        "ai_content_similarity_interpretation_rendered_prompt.md",
        "ai_anomaly_interpretation_raw.json",
        "ai_anomaly_interpretation_normalized.json",
        "ai_anomaly_interpretation_input_bundle.json",
        "ai_anomaly_interpretation_validation.json",
        "ai_anomaly_interpretation_rendered_prompt.md",
        "ai_stage2_preparation_summary_raw.json",
        "ai_stage2_preparation_summary_normalized.json",
        "ai_stage2_preparation_summary_input_bundle.json",
        "ai_stage2_preparation_summary_validation.json",
        "ai_stage2_preparation_summary_rendered_prompt.md",
        "ai_stage3_preparation_summary_raw.json",
        "ai_stage3_preparation_summary_normalized.json",
        "ai_stage3_preparation_summary_input_bundle.json",
        "ai_stage3_preparation_summary_validation.json",
        "ai_stage3_preparation_summary_rendered_prompt.md",
    }
    artifacts = set(STAGE1_BASELINE_ARTIFACTS)
    assert required_rec108_artifacts.issubset(artifacts)
    assert required_ai_bundle_artifacts.issubset(artifacts)


def test_stage1_contract_sections_8_14_are_present_with_expected_ids() -> None:
    expected_sections = {
        8: "section-08-javascript-frontend-analysis",
        9: "section-09-parameters-input-surfaces",
        10: "section-10-api-surface-mapping",
        11: "section-11-headers-cookies-tls-analysis",
        12: "section-12-content-similarity-and-routing-behavior",
        13: "section-13-anomaly-validation",
        14: "section-14-stage-2-preparation",
    }
    sections_by_index = {section["index"]: section["id"] for section in STAGE1_REPORT_SECTIONS}
    assert expected_sections == {idx: sections_by_index[idx] for idx in range(8, 15)}


def test_policy_denies_on_denylist_keyword_even_for_allowlisted_operation() -> None:
    decision = evaluate_recon_stage1_policy(
        tool_name="fetch",
        operation="route_endpoint_extraction",
        args={"url": "https://example.com/", "hint": "payload probe"},
    )
    assert decision.allowed is False
    assert decision.reason == "denylist_keyword:payload"


def test_policy_is_fail_closed_when_url_missing() -> None:
    decision = evaluate_recon_stage1_policy(
        tool_name="fetch",
        operation="endpoint_extraction",
        args={},
    )
    assert decision.allowed is False
    assert decision.reason == "missing_url_argument"


def test_deny_decision_writes_clear_audit_event_and_linkage(tmp_path: Path) -> None:
    with mcp_audit_context(
        stage="recon_stage1",
        run_id="run-deny",
        job_id="job-deny",
        recon_dir=tmp_path,
        trace_id="trace-deny",
    ):
        result = fetch_url_mcp(
            "https://example.com/",
            timeout=1.0,
            operation="exploit_payload_delivery",
        )

    assert result["exists"] is False
    assert result["notes"] == "mcp_operation_denied_by_policy"

    lines = [
        line
        for line in (tmp_path / MCP_AUDIT_LOG_FILENAME).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    event = json.loads(lines[-1])
    assert event["event_type"] == "mcp_invocation_audit"
    assert event["allowed"] is False
    assert event["decision_reason"] == "operation_not_allowlisted"
    assert event["run_link"] == "recon://runs/run-deny"
    assert event["job_link"] == "recon://jobs/job-deny"


def test_deny_audit_event_sanitizes_sensitive_url_query_values(tmp_path: Path) -> None:
    with mcp_audit_context(
        stage="recon_stage1",
        run_id="run-deny-sanitize",
        job_id="job-deny-sanitize",
        recon_dir=tmp_path,
        trace_id="trace-deny-sanitize",
    ):
        result = fetch_url_mcp(
            "https://example.com/callback?token=very-secret&next=/home",
            timeout=1.0,
            operation="exploit_payload_delivery",
        )

    assert result["exists"] is False
    assert result["notes"] == "mcp_operation_denied_by_policy"

    lines = [
        line
        for line in (tmp_path / MCP_AUDIT_LOG_FILENAME).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    event = json.loads(lines[-1])
    assert event["allowed"] is False
    assert event["decision_reason"] == "operation_not_allowlisted"
    assert "very-secret" not in json.dumps(event["args_sanitized"])
    assert "token=%5BREDACTED%5D" in event["args_sanitized"]["url"]


def test_sanitize_args_redacts_nested_secrets_and_keeps_non_sensitive_fields() -> None:
    raw_args = {
        "url": "https://example.com/",
        "token": "very-secret-token",
        "headers": {
            "Authorization": "Bearer secret-auth",
            "X-Trace-Id": "trace-123",
        },
        "nested": {
            "api_key": "key-123",
            "cookie": "session=abc",
            "safe_field": "ok",
        },
        "list_data": [
            {"secret": "hidden"},
            {"value": "visible"},
        ],
    }
    sanitized = sanitize_args(raw_args)

    assert sanitized["url"] == "https://example.com/"
    assert sanitized["token"] == "[REDACTED]"
    assert sanitized["headers"]["Authorization"] == "[REDACTED]"
    assert sanitized["headers"]["X-Trace-Id"] == "trace-123"
    assert sanitized["nested"]["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["cookie"] == "[REDACTED]"
    assert sanitized["nested"]["safe_field"] == "ok"
    assert sanitized["list_data"][0]["secret"] == "[REDACTED]"
    assert sanitized["list_data"][1]["value"] == "visible"
    assert "very-secret-token" not in json.dumps(sanitized)
    assert "secret-auth" not in json.dumps(sanitized)


def test_sanitize_args_redacts_secret_patterns_in_values_and_url_query() -> None:
    raw_args = {
        "url": "https://example.com/callback?token=abc123&q=safe",
        "message": "authorization=Bearer secret-token-value",
        "safe_note": "normal text",
    }

    sanitized = sanitize_args(raw_args)

    assert "token=abc123" not in sanitized["url"]
    assert "%5BREDACTED%5D" in sanitized["url"]
    assert sanitized["message"] == "[REDACTED]"
    assert sanitized["safe_note"] == "normal text"


def test_fetch_url_mcp_fail_closed_error_notes_do_not_leak_exception_details(
    monkeypatch,
) -> None:
    def _raise(_url: str, _timeout: float) -> dict:
        raise RuntimeError("token=very-secret internal stack detail")

    monkeypatch.setattr("src.recon.mcp.client._fetch_via_mcp_sync", _raise)

    result = fetch_url_mcp(
        "https://example.com/?token=very-secret",
        timeout=1.0,
        operation="endpoint_extraction",
    )

    assert result["exists"] is False
    assert result["notes"] == "mcp_fetch_failed"
    assert "very-secret" not in json.dumps(result)


def test_fetch_url_mcp_logs_redacted_url_in_structured_extra(
    monkeypatch,
    caplog,
) -> None:
    def _raise(_url: str, _timeout: float) -> dict:
        raise RuntimeError("upstream failure")

    monkeypatch.setattr("src.recon.mcp.client._fetch_via_mcp_sync", _raise)

    with caplog.at_level("INFO", logger="src.recon.mcp.client"):
        fetch_url_mcp(
            "https://example.com/callback?token=very-secret&next=/home",
            timeout=1.0,
            operation="endpoint_extraction",
        )

    records = [record for record in caplog.records if record.message == "mcp_fetch_failed"]
    assert records
    record = records[-1]
    assert hasattr(record, "url")
    assert "very-secret" not in record.url
    assert "token=%5BREDACTED%5D" in record.url
