"""Tests for Stage 1 enrichment builder artifacts and AI task persistence."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from src.recon.reporting.stage1_enrichment_builder import (
    _build_anomaly_validation_rows,
    _build_redirect_clusters,
    _build_response_similarity_from_redirect,
    _build_stage3_readiness,
    _route_classification,
    _validate_schema,
    build_stage1_enrichment_artifacts,
)


def _csv_rows(content: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(content)))


def test_stage1_enrichment_generates_expected_artifacts_and_content(tmp_path: Path) -> None:
    recon_dir = tmp_path / "acme-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.com,https://example.com/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )
    endpoint_path = recon_dir / "endpoint_inventory.csv"
    endpoint_path.write_text(
        "url,status,content_type,exists,notes\n"
        "https://example.com/api/openapi.json,200,application/json,yes,mock\n",
        encoding="utf-8",
        newline="",
    )

    def mock_fetch(url: str) -> dict[str, str | int]:
        normalized = url.rstrip("/")
        if normalized in {"https://example.com", "https://example.com/login"}:
            return {
                "status": 200,
                "content_type": "text/html",
                "body": (
                    "<html><head><title>Example</title></head><body>"
                    '<a href="/portal?search=term">Portal</a>'
                    '<form action="/api/v1/auth/login" method="post">'
                    '<input name="username" type="text" required>'
                    '<input name="redirect" type="url">'
                    "</form>"
                    '<script src="/static/app.js"></script>'
                    "</body></html>"
                ),
            }
        if normalized == "https://example.com/static/app.js":
            return {
                "status": 200,
                "content_type": "application/javascript",
                "body": (
                    "const feature_flag = true;\n"
                    "const route='/account/settings';\n"
                    "fetch('/api/v1/users/42');\n"
                    "const gql='/graphql';\n"
                    "window.__CONFIG__ = {};\n"
                    "const framework='react';\n"
                    "const hidden='internal';\n"
                ),
            }
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.com"],
        endpoint_inventory_path=endpoint_path,
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    required_artifacts = {
        "route_inventory.csv",
        "route_classification.csv",
        "public_pages.csv",
        "forms_inventory.csv",
        "params_inventory.csv",
        "js_bundle_inventory.csv",
        "js_findings.md",
        "api_surface.csv",
        "content_clusters.csv",
        "redirect_clusters.csv",
        "anomaly_validation.md",
    }
    assert required_artifacts.issubset(outputs.keys())

    route_rows = _csv_rows(outputs["route_inventory.csv"])
    assert route_rows
    assert all(row["run_id"] == "acme-stage1" for row in route_rows)
    assert all(row["job_id"] == "acme-stage1-stage1" for row in route_rows)
    assert all(row["evidence_ref"] for row in route_rows)
    assert any(row["classification"] for row in route_rows)
    assert all(row["fetch_backend"] == "custom_fetch" for row in route_rows if row["fetch_backend"])

    route_classification_rows = _csv_rows(outputs["route_classification.csv"])
    assert route_classification_rows
    expected_cols = {"route", "host", "classification", "discovery_source", "evidence_ref"}
    assert all(expected_cols.issubset(row.keys()) for row in route_classification_rows)
    assert all(row["route"] for row in route_classification_rows)
    assert all(row["host"] for row in route_classification_rows)
    assert any(row["classification"] == "login_flow" for row in route_classification_rows)

    public_rows = _csv_rows(outputs["public_pages.csv"])
    assert public_rows
    assert all(row["evidence_ref"] for row in public_rows)
    assert all(row["fetch_backend"] == "custom_fetch" for row in public_rows if row["fetch_backend"])

    forms_rows = _csv_rows(outputs["forms_inventory.csv"])
    assert forms_rows
    assert all(row["run_id"] == "acme-stage1" for row in forms_rows)
    assert all(row["job_id"] == "acme-stage1-stage1" for row in forms_rows)
    assert all(row["input_type"] for row in forms_rows)
    assert all(row["classification"] for row in forms_rows)
    assert all(row["evidence_ref"] for row in forms_rows)

    params_rows = _csv_rows(outputs["params_inventory.csv"])
    assert params_rows
    assert all(row["param_category"] for row in params_rows)
    assert all(row["evidence_ref"] for row in params_rows)

    js_bundle_rows = _csv_rows(outputs["js_bundle_inventory.csv"])
    assert js_bundle_rows
    assert all(row["evidence_ref"] for row in js_bundle_rows)
    assert all(row["fetch_backend"] == "custom_fetch" for row in js_bundle_rows if row["fetch_backend"])

    api_rows = _csv_rows(outputs["api_surface.csv"])
    assert api_rows
    assert all(row["run_id"] == "acme-stage1" for row in api_rows)
    assert all(row["job_id"] == "acme-stage1-stage1" for row in api_rows)
    assert all(row["api_type"] for row in api_rows)
    assert all(row["evidence_ref"] for row in api_rows)
    assert any(row["source"] for row in api_rows)
    assert all(row["fetch_backend"] for row in api_rows)

    js_findings = outputs["js_findings.md"]
    assert "Run ID: `acme-stage1`" in js_findings
    assert "Job ID: `acme-stage1-stage1`" in js_findings
    assert "evidence:" in js_findings

    app_flow_hints = outputs["app_flow_hints.md"]
    assert "Route Classification Summary" in app_flow_hints
    assert "Routes by Classification" in app_flow_hints


def test_stage1_enrichment_persists_ai_raw_and_normalized_outputs_with_valid_schema(
    tmp_path: Path,
) -> None:
    recon_dir = tmp_path / "tenant-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.org,https://example.org/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )

    def mock_fetch(url: str) -> dict[str, str | int]:
        normalized = url.rstrip("/")
        if normalized == "https://example.org":
            return {
                "status": 200,
                "content_type": "text/html",
                "body": (
                    "<html><body>"
                    '<a href="/contact?q=test">Contact</a>'
                    '<form action="/api/v2/search" method="get">'
                    '<input name="query" type="search">'
                    "</form>"
                    '<script src="/assets/main.js"></script>'
                    "</body></html>"
                ),
            }
        if normalized == "https://example.org/assets/main.js":
            return {
                "status": 200,
                "content_type": "application/javascript",
                "body": "fetch('/api/v2/search'); const route='/portal'; const framework='vue';",
            }
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.org"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    task_names = (
        "js_findings_analysis",
        "parameter_input_analysis",
        "api_surface_inference",
        "headers_tls_summary",
        "content_similarity_interpretation",
        "anomaly_interpretation",
        "stage2_preparation_summary",
        "stage3_preparation_summary",
    )
    for task_name in task_names:
        raw_key = f"ai_{task_name}_raw.json"
        normalized_key = f"ai_{task_name}_normalized.json"
        assert raw_key in outputs
        assert normalized_key in outputs

        raw_doc = json.loads(outputs[raw_key])
        normalized_doc = json.loads(outputs[normalized_key])

        assert raw_doc["run_id"] == "tenant-stage1"
        assert raw_doc["job_id"] == "tenant-stage1-stage1"
        assert normalized_doc["run_id"] == "tenant-stage1"
        assert normalized_doc["job_id"] == "tenant-stage1-stage1"

        assert raw_doc["validation"]["is_valid"] is True
        assert raw_doc["validation"]["errors"] == []
        assert normalized_doc["validation"]["is_valid"] is True
        assert normalized_doc["validation"]["errors"] == []


def test_stage1_enrichment_ai_tasks_5_8_include_links_and_evidence_refs(tmp_path: Path) -> None:
    recon_dir = tmp_path / "links-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.io,https://example.io/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )
    (recon_dir / "headers_detailed.csv").write_text(
        "host_url,security_header_score,cookie_count,cookies_secure\n"
        "https://example.io,5,1,1\n",
        encoding="utf-8",
        newline="",
    )
    (recon_dir / "tls_summary.md").write_text(
        "# TLS / Certificate Summary\n\n- [Evidence] Host: `https://example.io`\n",
        encoding="utf-8",
    )

    def mock_fetch(url: str) -> dict[str, str | int]:
        normalized = url.rstrip("/")
        if normalized == "https://example.io":
            return {
                "status": 200,
                "content_type": "text/html",
                "body": (
                    "<html><body>"
                    '<a href="/admin">Admin</a>'
                    '<script src="/assets/main.js"></script>'
                    "</body></html>"
                ),
            }
        if normalized == "https://example.io/assets/main.js":
            return {
                "status": 200,
                "content_type": "application/javascript",
                "body": "fetch('/api/v1/users'); const route='/portal';",
            }
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.io"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    tasks_5_8 = (
        "headers_tls_summary",
        "content_similarity_interpretation",
        "anomaly_interpretation",
        "stage2_preparation_summary",
        "stage3_preparation_summary",
    )
    for task_name in tasks_5_8:
        raw_doc = json.loads(outputs[f"ai_{task_name}_raw.json"])
        normalized_doc = json.loads(outputs[f"ai_{task_name}_normalized.json"])

        assert raw_doc["run_link"] == "recon://runs/links-stage1"
        assert raw_doc["job_link"] == "recon://jobs/links-stage1-stage1"
        assert normalized_doc["run_link"] == "recon://runs/links-stage1"
        assert normalized_doc["job_link"] == "recon://jobs/links-stage1-stage1"
        assert raw_doc["validation"]["is_valid"] is True
        assert normalized_doc["validation"]["is_valid"] is True

    headers_norm = json.loads(outputs["ai_headers_tls_summary_normalized.json"])
    controls = headers_norm["output"]["controls"]
    assert controls
    assert all(item["evidence_refs"] for item in controls)
    assert all(any(ref.startswith("headers_detailed.csv:") for ref in item["evidence_refs"]) for item in controls)

    content_norm = json.loads(outputs["ai_content_similarity_interpretation_normalized.json"])
    clusters = content_norm["output"]["clusters"]
    if clusters:
        assert all(item["evidence_refs"] for item in clusters)

    anomaly_norm = json.loads(outputs["ai_anomaly_interpretation_normalized.json"])
    anomalies = anomaly_norm["output"]["anomalies"]
    if anomalies:
        assert all(item["evidence_refs"] for item in anomalies)

    stage2_norm = json.loads(outputs["ai_stage2_preparation_summary_normalized.json"])
    next_steps = stage2_norm["output"]["next_steps"]
    assert next_steps
    assert all(step["evidence_refs"] for step in next_steps)
    assert any("anomaly_validation.md" in ref for step in next_steps for ref in step["evidence_refs"])

    stage3_norm = json.loads(outputs["ai_stage3_preparation_summary_normalized.json"])
    stage3_next_steps = stage3_norm["output"]["next_steps"]
    assert stage3_next_steps
    assert all(step["evidence_refs"] for step in stage3_next_steps)
    assert any("stage3_readiness.json" in ref for step in stage3_next_steps for ref in step["evidence_refs"])


def test_stage2_preparation_source_artifacts_exclude_missing_stage2_inputs(tmp_path: Path) -> None:
    recon_dir = tmp_path / "stage2-artifacts-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.org,https://example.org/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )

    def mock_fetch(url: str) -> dict[str, str | int]:
        if url.rstrip("/") == "https://example.org":
            return {
                "status": 200,
                "content_type": "text/html",
                "body": "<html><body><a href='/admin'>Admin</a></body></html>",
            }
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.org"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    raw_doc = json.loads(outputs["ai_stage2_preparation_summary_raw.json"])
    normalized_doc = json.loads(outputs["ai_stage2_preparation_summary_normalized.json"])
    input_bundle_doc = json.loads(outputs["ai_stage2_preparation_summary_input_bundle.json"])

    assert "stage2_inputs.md" not in raw_doc["evidence_trace"]["source_artifacts"]
    assert "stage2_inputs.md" not in normalized_doc["evidence_trace"]["source_artifacts"]
    assert "stage2_inputs.md" not in input_bundle_doc["source_artifacts"]


def test_stage1_enrichment_skips_out_of_scope_script_fetch_and_marks_reason(tmp_path: Path) -> None:
    recon_dir = tmp_path / "scope-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.net,https://example.net/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )

    fetched_urls: list[str] = []

    def mock_fetch(url: str) -> dict[str, str | int]:
        fetched_urls.append(url)
        normalized = url.rstrip("/")
        if normalized == "https://example.net":
            return {
                "status": 200,
                "content_type": "text/html",
                "body": (
                    "<html><body>"
                    '<script src="https://cdn.evil.test/malicious.js"></script>'
                    '<script src="/assets/app.js"></script>'
                    "</body></html>"
                ),
            }
        if normalized == "https://example.net/assets/app.js":
            return {
                "status": 200,
                "content_type": "application/javascript",
                "body": "const route='/portal';",
            }
        if normalized == "https://cdn.evil.test/malicious.js":
            raise AssertionError("Out-of-scope JS must not be fetched")
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.net"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    js_bundle_rows = _csv_rows(outputs["js_bundle_inventory.csv"])
    out_scope_rows = [r for r in js_bundle_rows if "cdn.evil.test" in r["script_url"]]
    assert out_scope_rows
    assert all(row["skipped_reason"] == "out_of_scope" for row in out_scope_rows)
    assert all(row["fetch_status"] == "0" for row in out_scope_rows)
    assert not any("cdn.evil.test/malicious.js" in url for url in fetched_urls)


def test_stage1_enrichment_updates_js_bundle_rows_with_sanitized_urls(tmp_path: Path) -> None:
    recon_dir = tmp_path / "js-sanitize-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.net,https://example.net/?token=seed,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )

    fetched_urls: list[str] = []

    def mock_fetch(url: str) -> dict[str, str | int]:
        fetched_urls.append(url)
        normalized = url.split("?", 1)[0].rstrip("/")
        if normalized == "https://example.net":
            return {
                "status": 200,
                "content_type": "text/html",
                "body": (
                    "<html><body>"
                    '<script src="/assets/app.js?token=jssecret"></script>'
                    '<script src="https://cdn.evil.test/malicious.js?token=evil"></script>'
                    "</body></html>"
                ),
            }
        if normalized == "https://example.net/assets/app.js":
            return {
                "status": 200,
                "content_type": "application/javascript",
                "body": "const route='/portal';",
            }
        if normalized == "https://cdn.evil.test/malicious.js":
            raise AssertionError("Out-of-scope JS must not be fetched")
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.net/?token=seed"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    js_bundle_rows = _csv_rows(outputs["js_bundle_inventory.csv"])
    assert js_bundle_rows

    same_origin_rows = [row for row in js_bundle_rows if "example.net/assets/app.js" in row["script_url"]]
    assert same_origin_rows
    assert all("%5BREDACTED%5D" in row["script_url"] for row in same_origin_rows)
    assert all(row["fetch_status"] == "200" for row in same_origin_rows)
    assert all(row["skipped_reason"] == "" for row in same_origin_rows)

    out_scope_rows = [row for row in js_bundle_rows if "cdn.evil.test/malicious.js" in row["script_url"]]
    assert out_scope_rows
    assert all(row["skipped_reason"] == "out_of_scope" for row in out_scope_rows)
    assert all(row["fetch_status"] == "0" for row in out_scope_rows)
    assert not any("cdn.evil.test/malicious.js" in url for url in fetched_urls)


def test_stage1_enrichment_skips_out_of_scope_crawl_targets_before_fetch(tmp_path: Path) -> None:
    recon_dir = tmp_path / "crawl-scope-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.net,https://example.net/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )
    endpoint_path = recon_dir / "endpoint_inventory.csv"
    endpoint_path.write_text(
        "url,status,content_type,exists,notes\n"
        "https://evil.test/admin,200,text/html,yes,seeded-by-fixture\n",
        encoding="utf-8",
        newline="",
    )

    fetched_urls: list[str] = []

    def mock_fetch(url: str) -> dict[str, str | int]:
        fetched_urls.append(url)
        normalized = url.rstrip("/")
        if normalized == "https://example.net":
            return {"status": 200, "content_type": "text/html", "body": "<html><body>ok</body></html>"}
        if normalized == "https://evil.test/admin":
            raise AssertionError("Out-of-scope crawl target must not be fetched")
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.net"],
        endpoint_inventory_path=endpoint_path,
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    route_rows = _csv_rows(outputs["route_inventory.csv"])
    skipped = [
        row
        for row in route_rows
        if row["url"] == "https://evil.test/admin" and row["discovery_source"] == "public_crawl"
    ]
    assert skipped
    assert all(row["skipped_reason"] == "out_of_scope" for row in skipped)
    assert all(row["fetch_backend"] == "scope_filter" for row in skipped)
    assert not any("evil.test/admin" in url for url in fetched_urls)


def test_route_classification_returns_login_flow_for_login_path() -> None:
    """Unit test: _route_classification returns login_flow for paths containing 'login'."""
    assert _route_classification("/login") == "login_flow"
    assert _route_classification("https://example.com/LOGIN") == "login_flow"
    assert _route_classification("/auth/login") == "login_flow"


def test_route_classification_returns_login_flow_for_signin_path() -> None:
    """Unit test: _route_classification returns login_flow for paths containing 'signin'."""
    assert _route_classification("/signin") == "login_flow"
    assert _route_classification("/api/signin") == "login_flow"


def test_route_classification_returns_password_reset_for_reset_path() -> None:
    """Unit test: _route_classification returns password_reset_flow for reset/forgot paths."""
    assert _route_classification("/reset-password") == "password_reset_flow"
    assert _route_classification("/forgot") == "password_reset_flow"


def test_route_classification_returns_public_page_for_unknown_path() -> None:
    """Unit test: _route_classification returns public_page when no marker matches."""
    assert _route_classification("/") == "public_page"
    assert _route_classification("/about") == "public_page"
    assert _route_classification("/docs") == "public_page"


def test_route_classification_all_markers() -> None:
    """Unit test: _route_classification covers all classification markers."""
    markers = [
        ("/login", "login_flow"),
        ("/signin", "login_flow"),
        ("/reset", "password_reset_flow"),
        ("/forgot", "password_reset_flow"),
        ("/contact", "contact_flow"),
        ("/portal", "portal_flow"),
        ("/admin", "admin_flow"),
        ("/account", "account_flow"),
        ("/user", "user_flow"),
    ]
    for path, expected in markers:
        assert _route_classification(path) == expected, f"path={path}"


def test_build_stage3_readiness_status_ready_when_high_scores() -> None:
    """Unit test: _build_stage3_readiness returns ready_for_stage3 when avg >= 0.7."""
    route_rows = [{"route": f"/r{i}", "host": "example.com"} for i in range(25)]
    params_rows = [{"param_name": f"p{i}"} for i in range(20)]
    api_rows = [{"path": f"/api/{i}"} for i in range(12)]
    content_rows = [{"cluster_id": "c1", "host": "example.com"} for _ in range(5)]
    redirect_rows = [{"redirect_cluster_id": "r1", "host": "example.com"} for _ in range(5)]
    result = _build_stage3_readiness(
        route_classification_rows=route_rows,
        params_rows=params_rows,
        api_rows=api_rows,
        content_cluster_rows=content_rows,
        redirect_cluster_rows=redirect_rows,
        frontend_backend_boundaries_md="# Boundaries\n",
    )
    assert result.status == "ready_for_stage3"
    assert result.coverage_scores.route >= 0.7
    assert result.coverage_scores.boundary_mapping == 1.0


def test_build_stage3_readiness_status_partially_ready() -> None:
    """Unit test: _build_stage3_readiness returns partially_ready_for_stage3 when 0.3 <= avg < 0.7."""
    route_rows = [{"route": f"/r{i}", "host": "example.com"} for i in range(10)]
    params_rows = [{"param_name": f"p{i}"} for i in range(15)]
    result = _build_stage3_readiness(
        route_classification_rows=route_rows,
        params_rows=params_rows,
        api_rows=[],
        content_cluster_rows=[],
        redirect_cluster_rows=[],
        frontend_backend_boundaries_md="",
    )
    assert result.status == "partially_ready_for_stage3"
    assert result.coverage_scores.route == 0.5
    assert result.coverage_scores.input_surface == 1.0


def test_build_stage3_readiness_status_not_ready() -> None:
    """Unit test: _build_stage3_readiness returns not_ready_for_stage3 when avg < 0.3."""
    result = _build_stage3_readiness(
        route_classification_rows=[],
        params_rows=[],
        api_rows=[],
        content_cluster_rows=[],
        redirect_cluster_rows=[],
        frontend_backend_boundaries_md="",
    )
    assert result.status == "not_ready_for_stage3"
    assert "route_classification.csv" in result.missing_evidence
    assert "content_clusters.csv or redirect_clusters.csv" in result.missing_evidence


def test_build_stage3_readiness_content_score_uses_redirect_when_content_empty() -> None:
    """Unit test: content_anomaly score uses redirect_clusters when content_clusters empty."""
    redirect_rows = [{"redirect_cluster_id": "r1", "host": f"host{i}.example.com"} for i in range(12)]
    result = _build_stage3_readiness(
        route_classification_rows=[{"route": "/", "host": "example.com"}],
        params_rows=[],
        api_rows=[],
        content_cluster_rows=[],
        redirect_cluster_rows=redirect_rows,
        frontend_backend_boundaries_md="",
    )
    assert result.coverage_scores.content_anomaly == 1.0


def test_build_response_similarity_from_redirect_when_content_empty() -> None:
    """REC-007: response_similarity.csv populated from redirect_clusters when content_clusters empty."""
    redirect_clusters = [
        {
            "redirect_cluster_id": "redirect_cluster_1",
            "host": "mail.example.com",
            "source_url": "https://mail.example.com/",
            "cluster_type": "redirect_to_root",
            "redirect_target": "https://example.com/",
            "evidence_ref": "http_probe:https://mail.example.com/",
        },
        {
            "redirect_cluster_id": "redirect_cluster_1",
            "host": "webmail.example.com",
            "source_url": "https://webmail.example.com/",
            "cluster_type": "redirect_to_root",
            "redirect_target": "https://example.com/",
            "evidence_ref": "http_probe:https://webmail.example.com/",
        },
    ]
    rows = _build_response_similarity_from_redirect(
        run_id="run-1",
        job_id="job-1",
        trace_id="trace-1",
        redirect_clusters=redirect_clusters,
    )
    assert len(rows) == 2
    assert all(r["similarity_type"] == "redirect" for r in rows)
    assert all(r["shared_redirect_target"] == "https://example.com/" for r in rows)
    assert rows[0]["host"] == "mail.example.com"
    assert rows[1]["host"] == "webmail.example.com"
    assert rows[0]["cluster_id"] == "redirect_cluster_1"


def test_build_anomaly_validation_rows_from_redirect_when_content_empty() -> None:
    """REC-007: anomaly_validation.csv populated from redirect_clusters with shared_with_root, suspicious_host."""
    redirect_clusters = [
        {
            "host": "mail.example.com",
            "status": "301",
            "suspicious_host": "yes",
            "shared_with_root": "yes",
            "evidence_ref": "http_probe:https://mail.example.com/",
        },
        {
            "host": "api.example.com",
            "status": "302",
            "suspicious_host": "no",
            "shared_with_root": "yes",
            "evidence_ref": "http_probe:https://api.example.com/",
        },
    ]
    rows = _build_anomaly_validation_rows(
        run_id="run-1",
        job_id="job-1",
        trace_id="trace-1",
        content_clusters=[],
        redirect_clusters=redirect_clusters,
    )
    assert len(rows) == 2
    hosts = {r["host"] for r in rows}
    assert hosts == {"mail.example.com", "api.example.com"}
    assert all("classification" in r for r in rows)
    assert all("confidence" in r for r in rows)
    assert all("redirect_clusters.csv" in r["evidence_refs"] for r in rows)


def test_stage1_enrichment_fallback_when_content_clusters_empty(tmp_path: Path) -> None:
    """REC-011: Integration test - full pipeline when content_clusters empty uses redirect fallback."""
    recon_dir = tmp_path / "content-empty-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "www.example.com,https://www.example.com/,https,301,,nginx,https://example.com/\n"
        "mail.example.com,https://mail.example.com/,https,302,,nginx,https://example.com/\n"
        "example.com,https://example.com/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )

    def mock_fetch(url: str) -> dict[str, str | int]:
        if "example.com" in url:
            return {"status": 404, "content_type": "text/html", "body": ""}
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.com"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    content_rows = _csv_rows(outputs["content_clusters.csv"])
    assert len(content_rows) == 0, "content_clusters must be empty when no HTML pages fetched"

    redirect_rows = _csv_rows(outputs["redirect_clusters.csv"])
    assert len(redirect_rows) >= 2, "redirect_clusters populated from http_probe"

    response_similarity_rows = _csv_rows(outputs["response_similarity.csv"])
    assert len(response_similarity_rows) >= 2, "response_similarity from redirect fallback"
    assert all(r["similarity_type"] == "redirect" for r in response_similarity_rows)

    anomaly_rows = _csv_rows(outputs["anomaly_validation.csv"])
    assert len(anomaly_rows) >= 2, "anomaly_validation from redirect fallback"

    stage3_readiness = json.loads(outputs["stage3_readiness.json"])
    assert stage3_readiness["status"] in (
        "ready_for_stage3",
        "partially_ready_for_stage3",
        "not_ready_for_stage3",
    )
    assert "coverage_scores" in stage3_readiness
    assert stage3_readiness["coverage_scores"]["content_anomaly"] > 0

    stage3_norm = json.loads(outputs["ai_stage3_preparation_summary_normalized.json"])
    assert stage3_norm["output"]["next_steps"]
    assert stage3_norm["validation"]["is_valid"] is True


def test_redirect_clusters_skip_rows_without_valid_redirect_target() -> None:
    rows = [
        {"host": "app.example.com", "url": "https://app.example.com/", "status": "301", "redirect": ""},
        {"host": "api.example.com", "url": "https://api.example.com/", "status": "302", "redirect": "/signin"},
        {
            "host": "www.example.com",
            "url": "https://www.example.com/",
            "status": "301",
            "redirect": "https://example.com/login",
        },
    ]

    clusters = _build_redirect_clusters(
        run_id="run-1",
        job_id="job-1",
        http_probe_rows=rows,
    )

    assert len(clusters) == 1
    assert clusters[0]["host"] == "www.example.com"
    assert clusters[0]["redirect_target"] == "https://example.com/login"
    assert clusters[0]["redirect_cluster_id"] == "redirect_cluster_1"


def test_validate_schema_rejects_boolean_as_number() -> None:
    errors = _validate_schema(True, {"type": "number"})
    assert errors == ["$: expected number"]


def test_validate_schema_rejects_malformed_schema_items() -> None:
    errors = _validate_schema(["x"], {"type": "array", "items": "string"})
    assert errors == ["$: malformed schema (items must be object)"]


def test_validate_schema_rejects_malformed_property_schema_when_key_present() -> None:
    errors = _validate_schema(
        {"payload": "ok"},
        {
            "type": "object",
            "properties": {
                "payload": {},
            },
        },
    )
    assert errors == ["$.payload: malformed schema type 'None'"]


def test_stage1_enrichment_safe_outputs_are_metadata_only(tmp_path: Path) -> None:
    recon_dir = tmp_path / "safe-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.safe,https://example.safe/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )

    def mock_fetch(url: str) -> dict[str, str | int]:
        if url.rstrip("/") == "https://example.safe":
            return {
                "status": 200,
                "content_type": "text/html",
                "body": "<html><body><a href='/portal'>Portal</a></body></html>",
            }
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.safe"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    assert "authorized safe recon only" in outputs["anomaly_validation.md"].lower()
    assert "source artifacts" in outputs["anomaly_validation.md"].lower()


def test_stage1_enrichment_redacts_sensitive_query_and_form_values_in_outputs(
    tmp_path: Path,
) -> None:
    recon_dir = tmp_path / "redact-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.sec,https://example.sec/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )

    def mock_fetch(url: str) -> dict[str, str | int]:
        normalized = url.rstrip("/")
        if normalized == "https://example.sec":
            return {
                "status": 200,
                "content_type": "text/html",
                "body": (
                    "<html><body>"
                    '<a href="/portal?token=abc123&search=term">Portal</a>'
                    '<form action="/api/v1/auth/login?code=xyz&next=/home" method="post">'
                    '<input name="password" type="password" required>'
                    "</form>"
                    "</body></html>"
                ),
            }
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.sec"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    params_rows = _csv_rows(outputs["params_inventory.csv"])
    token_rows = [row for row in params_rows if row["param_name"] == "token"]
    assert token_rows
    assert all(row["example_value"] == "[REDACTED]" for row in token_rows)
    assert all("abc123" not in row["context_url"] for row in token_rows)

    route_rows = _csv_rows(outputs["route_inventory.csv"])
    assert "token=abc123" not in json.dumps(route_rows)
    assert any("%5BREDACTED%5D" in row["url"] for row in route_rows if "token=" in row["url"])

    forms_rows = _csv_rows(outputs["forms_inventory.csv"])
    assert forms_rows
    assert all("code=xyz" not in row["action"] for row in forms_rows)

    api_rows = _csv_rows(outputs["api_surface.csv"])
    assert api_rows
    assert all("code=xyz" not in row["full_url"] for row in api_rows)


def test_stage1_enrichment_redacts_sensitive_query_values_in_evidence_refs(
    tmp_path: Path,
) -> None:
    recon_dir = tmp_path / "evidence-redact-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.sec,https://example.sec/?token=abc123,https,200,Example,nginx,"
        "https://example.sec/login?code=xyz\n",
        encoding="utf-8",
        newline="",
    )

    def mock_fetch(url: str) -> dict[str, str | int]:
        normalized = url.split("?", 1)[0].rstrip("/")
        if normalized == "https://example.sec":
            return {
                "status": 200,
                "content_type": "text/html",
                "body": (
                    "<html><body>"
                    '<a href="/portal?session=s3cr3t">Portal</a>'
                    '<form action="/api/v1/auth/login?password=supersecret" method="post">'
                    '<input name="username" type="text">'
                    "</form>"
                    '<script src="/assets/app.js?token=jssecret"></script>'
                    "</body></html>"
                ),
            }
        if normalized == "https://example.sec/assets/app.js":
            return {
                "status": 200,
                "content_type": "application/javascript",
                "body": "const route='/account'; fetch('/api/v1/user');",
            }
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.sec"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    evidence_refs: list[str] = []
    for artifact_name in (
        "route_inventory.csv",
        "public_pages.csv",
        "forms_inventory.csv",
        "params_inventory.csv",
        "js_bundle_inventory.csv",
        "api_surface.csv",
        "content_clusters.csv",
        "redirect_clusters.csv",
    ):
        for row in _csv_rows(outputs[artifact_name]):
            value = row.get("evidence_ref", "")
            if value:
                evidence_refs.append(value)

    assert evidence_refs
    serialized = json.dumps(evidence_refs)
    for secret in ("abc123", "xyz", "s3cr3t", "supersecret", "jssecret"):
        assert secret not in serialized
    assert any("%5BREDACTED%5D" in ref for ref in evidence_refs)


def test_stage1_enrichment_logs_redacted_url_in_structured_extra(
    tmp_path: Path,
    caplog,
) -> None:
    recon_dir = tmp_path / "log-redact-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.sec,https://example.sec/?token=logsecret,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )

    def failing_fetch(_url: str) -> dict[str, str | int]:
        raise RuntimeError("fetch failed")

    with caplog.at_level("INFO", logger="src.recon.reporting.stage1_enrichment_builder"):
        build_stage1_enrichment_artifacts(
            recon_dir=recon_dir,
            live_hosts=["https://example.sec"],
            fetch_func=failing_fetch,
            use_mcp=False,
        )

    records = [
        record
        for record in caplog.records
        if record.message == "stage1_enrichment_fetch_custom_failed"
    ]
    assert records
    redacted_record = next(
        (record for record in records if hasattr(record, "url") and "token=%5BREDACTED%5D" in record.url),
        None,
    )
    assert redacted_record is not None
    assert "logsecret" not in redacted_record.url


def test_stage1_enrichment_ai_and_support_artifacts_do_not_leak_sensitive_values(
    tmp_path: Path,
) -> None:
    recon_dir = tmp_path / "leak-guard-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.sec,https://example.sec/?token=seed-secret,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )

    def mock_fetch(url: str) -> dict[str, str | int]:
        normalized = url.split("?", 1)[0].rstrip("/")
        if normalized == "https://example.sec":
            return {
                "status": 200,
                "content_type": "text/html",
                "body": (
                    "<html><body>"
                    '<a href="/portal?session=portal-secret">Portal</a>'
                    '<form action="/api/v1/auth/login?code=form-secret" method="post">'
                    '<input name="password" type="password" required>'
                    "</form>"
                    '<script src="/assets/app.js?api_key=js-secret"></script>'
                    "</body></html>"
                ),
            }
        if normalized == "https://example.sec/assets/app.js":
            return {
                "status": 200,
                "content_type": "application/javascript",
                "body": (
                    "fetch('/api/v1/users?token=api-secret');"
                    "const deep='authorization=Bearer bearer-secret';"
                ),
            }
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.sec/?token=seed-secret"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    serialized_outputs = json.dumps(outputs, ensure_ascii=False)
    for secret in (
        "seed-secret",
        "portal-secret",
        "form-secret",
        "js-secret",
        "api-secret",
        "bearer-secret",
    ):
        assert secret not in serialized_outputs


def test_rec004_input_surfaces_populated_from_params_and_forms(tmp_path: Path) -> None:
    """REC-004: input_surfaces.csv populated from params_inventory + forms_inventory."""
    recon_dir = tmp_path / "rec004-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.com,https://example.com/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )

    def mock_fetch(url: str) -> dict[str, str | int]:
        if "example.com" in url:
            return {
                "status": 200,
                "content_type": "text/html",
                "body": (
                    "<html><body>"
                    '<a href="/search?q=test">Search</a>'
                    '<form action="/login" method="post">'
                    '<input name="username" type="text" required>'
                    '<input name="redirect" type="hidden">'
                    '<input type="submit" value="Go">'
                    "</form></body></html>"
                ),
            }
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.com"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    input_surfaces = _csv_rows(outputs["input_surfaces.csv"])
    assert input_surfaces
    surface_names = [r["surface_name"] for r in input_surfaces]
    assert "username" in surface_names
    assert "redirect" in surface_names
    assert "q" in surface_names
    assert all(r["surface_name"] for r in input_surfaces)
    assert not any(r["surface_name"] == "submit" or r["surface_name"] == "" for r in input_surfaces)


def test_rec004_route_params_map_includes_candidate_hints(tmp_path: Path) -> None:
    """REC-004: route_params_map.csv includes route candidate paths + common params."""
    recon_dir = tmp_path / "rec004-route-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.com,https://example.com/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )

    def mock_fetch(url: str) -> dict[str, str | int]:
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.com"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    route_params = _csv_rows(outputs["route_params_map.csv"])
    login_rows = [r for r in route_params if "/login" in r.get("route_path", "") or "/login" in r.get("context_url", "")]
    assert login_rows
    assert any("redirect" in r.get("param_names", "") for r in login_rows)
    assert any("route_candidate_hint" in r.get("sources", "") for r in route_params)


def test_rec004_http_probe_url_params_extracted_when_not_crawled(tmp_path: Path) -> None:
    """REC-004: params from http_probe URL query strings when URL not in crawl_targets."""
    recon_dir = tmp_path / "rec004-probe-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    lines = ["host,url,scheme,status,title,server,redirect"]
    for i in range(125):
        host = f"host{i}.example.com"
        url = f"https://{host}/" if i != 121 else f"https://{host}/login?redirect=/dashboard&next=/home"
        lines.append(f"{host},{url},https,200,,nginx,")
    (live_dir / "http_probe.csv").write_text("\n".join(lines), encoding="utf-8", newline="")

    def mock_fetch(_url: str) -> dict[str, str | int]:
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://host0.example.com"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    params = _csv_rows(outputs["params_inventory.csv"])
    http_probe_params = [p for p in params if p.get("param_source") == "http_probe_url"]
    assert http_probe_params, "Expected params from http_probe URLs beyond crawl limit"
    param_names = {p["param_name"] for p in http_probe_params}
    assert "redirect" in param_names
    assert "next" in param_names


def test_stage1_enrichment_inline_script_extraction_populates_js_artifacts(tmp_path: Path) -> None:
    """REC-003: Inline scripts populate js_routes, js_api_refs, js_integrations, js_config_hints."""
    recon_dir = tmp_path / "inline-js-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.com,https://example.com/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )

    def mock_fetch(url: str) -> dict[str, str | int]:
        normalized = url.rstrip("/")
        if normalized == "https://example.com":
            return {
                "status": 200,
                "content_type": "text/html",
                "body": (
                    "<html><head><title>SPA</title></head><body>"
                    '<script>'
                    "fetch('/api/v1/users');"
                    "axios.get('/graphql');"
                    "const route = '/account/settings';"
                    "window.__CONFIG__ = { apiUrl: '/api' };"
                    "const third = 'https://cdnjs.cloudflare.com/lib.js';"
                    "</script>"
                    '<script src="https://cdn.evil.test/out-of-scope.js"></script>'
                    "</body></html>"
                ),
            }
        if "cdn.evil.test" in normalized:
            return {"status": 404, "content_type": "text/plain", "body": ""}
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.com"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    js_routes = _csv_rows(outputs["js_routes.csv"])
    js_api_refs = _csv_rows(outputs["js_api_refs.csv"])
    js_integrations = _csv_rows(outputs["js_integrations.csv"])
    js_config_hints = _csv_rows(outputs["js_config_hints.csv"])
    js_bundle_rows = _csv_rows(outputs["js_bundle_inventory.csv"])
    js_findings = outputs["js_findings.md"]

    assert js_bundle_rows
    assert any(r["skipped_reason"] == "out_of_scope" for r in js_bundle_rows)

    route_hints = [r["route_hint"] for r in js_routes]
    assert "/account/settings" in route_hints

    api_refs = [r["api_ref"] for r in js_api_refs]
    assert any("/api" in ref for ref in api_refs)
    assert any("graphql" in ref.lower() for ref in api_refs)

    assert js_config_hints
    assert any(
        "config" in r["config_hint"].lower() or "window" in r["config_hint"].lower()
        for r in js_config_hints
    )

    assert "Client Routes" in js_findings or "API References" in js_findings
    assert "api" in js_findings.lower() or "graphql" in js_findings.lower()


def test_stage1_enrichment_js_findings_graceful_fallback_when_bundles_zero(tmp_path: Path) -> None:
    """REC-003: js_findings.md has content when bundles=0, extracted from inline scripts."""
    recon_dir = tmp_path / "bundles-zero-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.com,https://example.com/,https,200,Example,nginx,\n",
        encoding="utf-8",
        newline="",
    )

    def mock_fetch(url: str) -> dict[str, str | int]:
        normalized = url.rstrip("/")
        if normalized == "https://example.com":
            return {
                "status": 200,
                "content_type": "text/html",
                "body": (
                    "<html><body>"
                    '<script>'
                    "fetch('/api/v2/data');"
                    "const path = '/dashboard/admin';"
                    "process.env.NEXT_PUBLIC_API_URL = '/api';"
                    "</script>"
                    "</body></html>"
                ),
            }
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://example.com"],
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    js_bundle_rows = _csv_rows(outputs["js_bundle_inventory.csv"])
    js_findings = outputs["js_findings.md"]
    js_api_refs = _csv_rows(outputs["js_api_refs.csv"])
    js_routes = _csv_rows(outputs["js_routes.csv"])

    assert len(js_bundle_rows) == 0
    assert "JavaScript Findings" in js_findings
    assert "bundles discovered: `0`" in js_findings
    assert "inline" in js_findings.lower() or "/api" in js_findings or "/dashboard" in js_findings
    assert js_api_refs or js_routes


def test_rec006_api_map_strengthening_from_endpoint_inventory(tmp_path: Path) -> None:
    """REC-006: api_surface strengthened from endpoint_inventory + route_inventory + js_api_refs."""
    recon_dir = tmp_path / "rec006-stage1"
    live_dir = recon_dir / "04_live_hosts"
    live_dir.mkdir(parents=True)
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "api.example.com,https://api.example.com/,https,200,API,nginx,\n",
        encoding="utf-8",
        newline="",
    )
    endpoint_path = recon_dir / "endpoint_inventory.csv"
    endpoint_path.write_text(
        "url,status,content_type,exists,notes\n"
        "https://api.example.com/manifest.json,200,application/json,yes,\n"
        "https://api.example.com/robots.txt,200,text/plain,yes,\n"
        "https://api.example.com/api/v1/config.json,200,application/json,yes,\n",
        encoding="utf-8",
        newline="",
    )

    def mock_fetch(url: str) -> dict[str, str | int]:
        normalized = url.rstrip("/")
        if normalized == "https://api.example.com":
            return {
                "status": 200,
                "content_type": "text/html",
                "body": "<html><body><a href='/docs'>Docs</a></body></html>",
            }
        return {"status": 404, "content_type": "text/plain", "body": ""}

    outputs = build_stage1_enrichment_artifacts(
        recon_dir=recon_dir,
        live_hosts=["https://api.example.com"],
        endpoint_inventory_path=endpoint_path,
        fetch_func=mock_fetch,
        use_mcp=False,
    )

    api_rows = _csv_rows(outputs["api_surface.csv"])
    endpoint_sourced = [r for r in api_rows if r.get("source") == "endpoint_inventory"]
    assert endpoint_sourced, "api_surface must include endpoint_inventory-sourced rows"
    manifest_row = next(
        (r for r in endpoint_sourced if "manifest.json" in r.get("path", "")),
        None,
    )
    assert manifest_row is not None
    assert manifest_row.get("evidence_ref", "").startswith("endpoint_inventory.csv:")
    assert manifest_row.get("schema_hint") == "json"

    json_candidates = _csv_rows(outputs["json_endpoint_candidates.csv"])
    assert json_candidates, "json_endpoint_candidates must be populated"
    paths = [r.get("path", "") for r in json_candidates]
    assert any("manifest.json" in p for p in paths)
    assert any("config.json" in p for p in paths)

    boundaries_md = outputs["frontend_backend_boundaries.md"]
    assert "endpoint_inventory.csv" in boundaries_md
    assert "graphql_candidates.csv" in boundaries_md
    assert "json_endpoint_candidates.csv" in boundaries_md
    assert "evidence_ref" in boundaries_md.lower() or "ref:" in boundaries_md.lower()
