"""Integration tests for Stage 1 report pipeline (RPT-010).

Tests generate_stage1_report with minimal recon dir fixtures.
Uses use_mcp=False and mock fetch_func to avoid network calls.
"""

import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from src.recon.reporting.html_report_builder import (
    _render_anomalies_from_structured,
    _render_stage2_from_structured,
)
from src.recon.reporting.stage1_contract import STAGE1_BASELINE_ARTIFACTS, STAGE1_REPORT_SECTIONS
from src.recon.reporting.stage1_report_generator import (
    STAGE1_OUTPUTS,
    _run_intel_adapters,
    generate_stage1_report,
)

REC108_TASK_NAMES = (
    "js_findings_analysis",
    "parameter_input_analysis",
    "api_surface_inference",
    "headers_tls_summary",
    "content_similarity_interpretation",
    "anomaly_interpretation",
    "stage2_preparation_summary",
    "stage3_preparation_summary",
)

KNOWN_SAFE_BASELINE_OUTPUTS = {
    "dns_summary.md",
    "subdomain_classification.csv",
    "headers_summary.md",
    "tls_summary.md",
    "stage1_report.html",
}


def test_stage1_outputs_list_is_synchronized_with_stage1_contract() -> None:
    assert set(STAGE1_OUTPUTS) == set(STAGE1_BASELINE_ARTIFACTS)

# --- Fixtures ---


@pytest.fixture
def recon_dir_full(tmp_path: Path) -> Path:
    """Create minimal recon dir structure with sample artifacts."""
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

    # 00_scope
    (scope_dir / "scope.txt").write_text("example.com\n*.example.com", encoding="utf-8")
    (scope_dir / "roe.txt").write_text("Rules of engagement placeholder", encoding="utf-8")
    (scope_dir / "targets.txt").write_text("example.com", encoding="utf-8")

    # 01_domains
    (domains_dir / "whois.txt").write_text(
        "Domain Name: example.com\nRegistrar: Test Registrar\nRegistry Expiry Date: 2025-12-31",
        encoding="utf-8",
    )
    (domains_dir / "ns.txt").write_text(
        "example.com.  nameserver = ns1.example.com.\nexample.com.  nameserver = ns2.example.com.",
        encoding="utf-8",
    )
    (domains_dir / "mx.txt").write_text(
        "example.com.  MX preference = 10, mail exchanger = mail.example.com.",
        encoding="utf-8",
    )
    (domains_dir / "txt.txt").write_text(
        'example.com.  text = "v=spf1 include:_spf.example.com ~all"',
        encoding="utf-8",
    )
    (domains_dir / "caa.txt").write_text(
        'example.com.  0 issue "letsencrypt.org"',
        encoding="utf-8",
    )

    # 02_subdomains
    (subdomains_dir / "subdomains_clean.txt").write_text(
        "www.example.com\napi.example.com\nmail.example.com",
        encoding="utf-8",
    )

    # 03_dns
    (dns_dir / "resolved.txt").write_text(
        "www.example.com -> 93.184.216.34\napi.example.com -> 93.184.216.35",
        encoding="utf-8",
    )
    (dns_dir / "cname_map.csv").write_text(
        "host,record_type,value,comment\nwww.example.com,CNAME,cdn.example.com,CDN",
        encoding="utf-8",
        newline="",
    )
    (dns_dir / "unresolved.txt").write_text("nonexistent.example.com", encoding="utf-8")

    # 04_live_hosts
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.com,https://example.com/,https,200,Example Domain,nginx,\n"
        "www.example.com,https://www.example.com/,https,200,Example WWW,nginx,",
        encoding="utf-8",
        newline="",
    )

    return tmp_path


@pytest.fixture
def mock_endpoint_fetch():
    """Mock fetch for endpoint inventory — returns deterministic data, no network."""

    def _fetch(_url: str) -> dict:
        return {
            "status": 200,
            "content_type": "text/plain",
            "exists": True,
            "notes": "mock",
        }

    return _fetch


@pytest.fixture
def mock_headers_fetch():
    """Mock fetch for headers summary — returns deterministic data, no network."""

    def _fetch(url: str, _timeout: float = 10.0) -> dict:
        return {
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html",
                "Server": "nginx",
                "X-Content-Type-Options": "nosniff",
            },
            "url": url,
        }

    return _fetch


# --- Tests ---


class TestGenerateStage1ReportFull:
    """Full pipeline with complete recon dir."""

    def test_all_expected_outputs_exist(
        self,
        recon_dir_full: Path,
        mock_endpoint_fetch,
        mock_headers_fetch,
    ) -> None:
        """All expected output files are created."""
        generated = generate_stage1_report(
            recon_dir_full,
            use_mcp=False,
            fetch_func=mock_endpoint_fetch,
            headers_fetch_func=mock_headers_fetch,
        )

        generated_names = {p.name for p in generated}
        conditional_outputs = {"intel_findings.json", "intel_summary.md"}
        mandatory_outputs = [name for name in STAGE1_OUTPUTS if name not in conditional_outputs]
        for name in mandatory_outputs:
            assert name in generated_names, f"Expected {name} in generated outputs"
        if "intel_findings.json" in generated_names:
            assert "intel_summary.md" in generated_names

        assert (recon_dir_full / "stage1_report.html").exists()
        assert (recon_dir_full / "stage1_report.html").name in generated_names or any(
            "stage1_report" in str(p) for p in generated
        )

    def test_dns_summary_contains_expected_sections(
        self,
        recon_dir_full: Path,
        mock_endpoint_fetch,
        mock_headers_fetch,
    ) -> None:
        """dns_summary.md contains Record Summary, Nameservers, SPF/DKIM/DMARC, Resolved vs Unresolved."""
        generate_stage1_report(
            recon_dir_full,
            use_mcp=False,
            fetch_func=mock_endpoint_fetch,
            headers_fetch_func=mock_headers_fetch,
        )

        dns_path = recon_dir_full / "dns_summary.md"
        assert dns_path.exists()
        content = dns_path.read_text(encoding="utf-8")
        assert "## Record Summary" in content
        assert "## Nameservers (NS)" in content
        assert "## SPF / DKIM / DMARC" in content
        assert "## Resolved vs Unresolved Subdomains" in content

    def test_subdomain_classification_has_header_and_rows(
        self,
        recon_dir_full: Path,
        mock_endpoint_fetch,
        mock_headers_fetch,
    ) -> None:
        """subdomain_classification.csv has header and data rows."""
        generate_stage1_report(
            recon_dir_full,
            use_mcp=False,
            fetch_func=mock_endpoint_fetch,
            headers_fetch_func=mock_headers_fetch,
        )

        csv_path = recon_dir_full / "subdomain_classification.csv"
        assert csv_path.exists()
        lines = csv_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) >= 2
        assert "subdomain,role,confidence,priority,notes" in lines[0]
        assert len(lines) > 1

    def test_stage1_report_html_contains_sections(
        self,
        recon_dir_full: Path,
        mock_endpoint_fetch,
        mock_headers_fetch,
    ) -> None:
        """stage1_report.html exists and contains Executive summary, Scope, DNS."""
        generate_stage1_report(
            recon_dir_full,
            use_mcp=False,
            fetch_func=mock_endpoint_fetch,
            headers_fetch_func=mock_headers_fetch,
        )

        html_path = recon_dir_full / "stage1_report.html"
        assert html_path.exists()
        content = html_path.read_text(encoding="utf-8")
        content_lower = content.lower()
        assert "executive" in content_lower or "summary" in content_lower
        assert "scope" in content_lower
        assert "dns" in content_lower

    def test_stage1_report_has_sections_5_8_with_taxonomy_tags(
        self,
        recon_dir_full: Path,
        mock_endpoint_fetch,
        mock_headers_fetch,
    ) -> None:
        generate_stage1_report(
            recon_dir_full,
            use_mcp=False,
            fetch_func=mock_endpoint_fetch,
            headers_fetch_func=mock_headers_fetch,
        )

        html_path = recon_dir_full / "stage1_report.html"
        content = html_path.read_text(encoding="utf-8")
        content_lower = content.lower()

        assert "8. javascript / frontend analysis" in content_lower
        assert "9. parameters and input surfaces" in content_lower
        assert "10. api surface mapping" in content_lower
        assert "11. headers / cookies / tls analysis" in content_lower
        assert "12. content similarity and routing behavior" in content_lower
        assert "13. anomaly validation" in content_lower
        assert "14. stage 2 preparation" in content_lower
        assert "17. stage 3 readiness" in content_lower
        assert "18. route classification" in content_lower
        assert 'id="section-08-javascript-frontend-analysis"' in content_lower
        assert 'id="section-09-parameters-input-surfaces"' in content_lower
        assert 'id="section-10-api-surface-mapping"' in content_lower
        assert 'id="section-11-headers-cookies-tls-analysis"' in content_lower
        assert 'id="section-12-content-similarity-and-routing-behavior"' in content_lower
        assert 'id="section-13-anomaly-validation"' in content_lower
        assert 'id="section-14-stage-2-preparation"' in content_lower
        assert 'id="section-17-stage-3-readiness"' in content_lower
        assert 'id="section-18-route-classification"' in content_lower

        h2_numbers = re.findall(r"<h2>(\d+)\.", content)
        assert h2_numbers
        assert len(h2_numbers) == len(set(h2_numbers))
        assert h2_numbers == [str(i) for i in range(1, 19)], "REC-010: 18 sections (17 Stage3 Readiness, 18 Route Classification)"

        assert "badge-evidence" in content_lower
        assert "badge-observation" in content_lower
        assert "badge-inference" in content_lower
        assert "badge-hypothesis" in content_lower

    def test_stage1_report_section_ids_follow_contract(self, recon_dir_full: Path, mock_endpoint_fetch, mock_headers_fetch) -> None:
        generate_stage1_report(
            recon_dir_full,
            use_mcp=False,
            fetch_func=mock_endpoint_fetch,
            headers_fetch_func=mock_headers_fetch,
        )
        content = (recon_dir_full / "stage1_report.html").read_text(encoding="utf-8").lower()
        html_section_ids = set(re.findall(r'<section id="([^"]+)" class="section">', content))
        contract_section_ids = {section["id"] for section in STAGE1_REPORT_SECTIONS}
        assert contract_section_ids.issubset(html_section_ids)

    def test_stage1_pipeline_generates_batch2_artifacts_and_safe_metadata_markers(
        self,
        recon_dir_full: Path,
        mock_endpoint_fetch,
        mock_headers_fetch,
    ) -> None:
        generate_stage1_report(
            recon_dir_full,
            use_mcp=False,
            fetch_func=mock_endpoint_fetch,
            headers_fetch_func=mock_headers_fetch,
        )

        batch2_files = [
            "headers_detailed.csv",
            "tls_summary.md",
            "content_clusters.csv",
            "redirect_clusters.csv",
            "anomaly_validation.md",
        ]
        for filename in batch2_files:
            path = recon_dir_full / filename
            assert path.exists(), f"{filename} must be generated"
            text = path.read_text(encoding="utf-8")
            assert text.strip()

        tls_summary = (recon_dir_full / "tls_summary.md").read_text(encoding="utf-8").lower()
        anomaly_validation = (recon_dir_full / "anomaly_validation.md").read_text(
            encoding="utf-8"
        ).lower()

        assert "tls handshake metadata" in tls_summary
        assert "authorized safe recon only" in anomaly_validation


class TestGenerateStage1ReportMissingArtifacts:
    """Graceful degradation with empty or partial recon dir."""

    def test_empty_recon_dir_no_exception(self, tmp_path: Path) -> None:
        """Empty recon dir: no exception, returns empty or minimal list."""
        # tmp_path is empty — not a valid recon structure
        result = generate_stage1_report(tmp_path, use_mcp=False)
        assert isinstance(result, list)
        assert all(p.exists() for p in result)
        assert all(p.parent == tmp_path for p in result)
        generated_names = {p.name for p in result}
        assert any(name in generated_names for name in KNOWN_SAFE_BASELINE_OUTPUTS)

    def test_partial_recon_dir_no_exception(self, tmp_path: Path) -> None:
        """Partial recon dir (only scope + domains): no exception, some outputs skipped."""
        (tmp_path / "00_scope").mkdir()
        (tmp_path / "01_domains").mkdir()
        (tmp_path / "02_subdomains").mkdir()
        (tmp_path / "03_dns").mkdir()
        (tmp_path / "04_live_hosts").mkdir()

        (tmp_path / "00_scope" / "scope.txt").write_text("example.com", encoding="utf-8")
        (tmp_path / "01_domains" / "whois.txt").write_text(
            "Registrar: Test",
            encoding="utf-8",
        )
        (tmp_path / "01_domains" / "ns.txt").write_text(
            "example.com.  nameserver = ns.example.com.",
            encoding="utf-8",
        )

        result = generate_stage1_report(tmp_path, use_mcp=False)
        assert isinstance(result, list)
        assert all(p.exists() for p in result)
        generated_names = {p.name for p in result}
        assert any(name in generated_names for name in KNOWN_SAFE_BASELINE_OUTPUTS)

    def test_nonexistent_recon_dir_returns_empty(self, tmp_path: Path) -> None:
        """Nonexistent recon dir returns empty list."""
        missing = tmp_path / "nonexistent_recon_xyz"
        assert not missing.exists()
        result = generate_stage1_report(missing, use_mcp=False)
        assert result == []


class TestGenerateStage1ReportMockedFetch:
    """Verify fetch_func is used for endpoint inventory (no network)."""

    def test_endpoint_inventory_uses_mock_fetch(
        self,
        recon_dir_full: Path,
        mock_headers_fetch,
    ) -> None:
        """endpoint_inventory.csv is populated from mock fetch_func."""
        seen_urls: list[str] = []

        def tracking_fetch(url: str) -> dict:
            seen_urls.append(url)
            return {"status": 200, "content_type": "text/plain", "exists": True, "notes": ""}

        generate_stage1_report(
            recon_dir_full,
            use_mcp=False,
            fetch_func=tracking_fetch,
            headers_fetch_func=mock_headers_fetch,
        )

        inv_path = recon_dir_full / "endpoint_inventory.csv"
        assert inv_path.exists()
        content = inv_path.read_text(encoding="utf-8")
        assert "url,status,content_type,exists,notes" in content
        assert seen_urls
        assert any(
            marker in u
            for u in seen_urls
            for marker in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")
        )

    def test_stage1_enrichment_ai_outputs_generated_without_breaking_legacy_outputs(
        self,
        recon_dir_full: Path,
        mock_headers_fetch,
    ) -> None:
        """Regression: legacy Stage1 outputs remain and new AI task files are generated."""
        generated = generate_stage1_report(
            recon_dir_full,
            use_mcp=False,
            fetch_func=lambda _url: {
                "status": 200,
                "content_type": "text/html",
                "exists": True,
                "notes": "mock",
                "body": "<html><body><script src='/app.js'></script></body></html>",
            },
            headers_fetch_func=mock_headers_fetch,
        )

        generated_names = {p.name for p in generated}
        # Legacy expectations
        assert "dns_summary.md" in generated_names
        assert "subdomain_classification.csv" in generated_names
        assert "endpoint_inventory.csv" in generated_names
        assert "route_inventory.csv" in generated_names
        assert "route_classification.csv" in generated_names

        # New enrichment AI task artifacts
        assert "ai_js_findings_analysis_raw.json" in generated_names
        assert "ai_js_findings_analysis_normalized.json" in generated_names
        assert "ai_js_findings_analysis_input_bundle.json" in generated_names
        assert "ai_js_findings_analysis_validation.json" in generated_names
        assert "ai_js_findings_analysis_rendered_prompt.md" in generated_names
        assert "ai_parameter_input_analysis_raw.json" in generated_names
        assert "ai_parameter_input_analysis_normalized.json" in generated_names
        assert "ai_parameter_input_analysis_input_bundle.json" in generated_names
        assert "ai_parameter_input_analysis_validation.json" in generated_names
        assert "ai_parameter_input_analysis_rendered_prompt.md" in generated_names
        assert "ai_api_surface_inference_raw.json" in generated_names
        assert "ai_api_surface_inference_normalized.json" in generated_names
        assert "ai_api_surface_inference_input_bundle.json" in generated_names
        assert "ai_api_surface_inference_validation.json" in generated_names
        assert "ai_api_surface_inference_rendered_prompt.md" in generated_names
        assert "ai_headers_tls_summary_raw.json" in generated_names
        assert "ai_headers_tls_summary_normalized.json" in generated_names
        assert "ai_headers_tls_summary_input_bundle.json" in generated_names
        assert "ai_headers_tls_summary_validation.json" in generated_names
        assert "ai_headers_tls_summary_rendered_prompt.md" in generated_names
        assert "ai_content_similarity_interpretation_raw.json" in generated_names
        assert "ai_content_similarity_interpretation_normalized.json" in generated_names
        assert "ai_content_similarity_interpretation_input_bundle.json" in generated_names
        assert "ai_content_similarity_interpretation_validation.json" in generated_names
        assert "ai_content_similarity_interpretation_rendered_prompt.md" in generated_names
        assert "ai_anomaly_interpretation_raw.json" in generated_names
        assert "ai_anomaly_interpretation_normalized.json" in generated_names
        assert "ai_anomaly_interpretation_input_bundle.json" in generated_names
        assert "ai_anomaly_interpretation_validation.json" in generated_names
        assert "ai_anomaly_interpretation_rendered_prompt.md" in generated_names
        assert "ai_stage2_preparation_summary_raw.json" in generated_names
        assert "ai_stage2_preparation_summary_normalized.json" in generated_names
        assert "ai_stage2_preparation_summary_input_bundle.json" in generated_names
        assert "ai_stage2_preparation_summary_validation.json" in generated_names
        assert "ai_stage2_preparation_summary_rendered_prompt.md" in generated_names
        assert "ai_stage3_preparation_summary_raw.json" in generated_names
        assert "ai_stage3_preparation_summary_normalized.json" in generated_names
        assert "ai_stage3_preparation_summary_input_bundle.json" in generated_names
        assert "ai_stage3_preparation_summary_validation.json" in generated_names
        assert "ai_stage3_preparation_summary_rendered_prompt.md" in generated_names

    def test_stage1_pipeline_persists_rec108_ai_bundles_and_manifest_with_linkage(
        self,
        recon_dir_full: Path,
        mock_headers_fetch,
    ) -> None:
        generated = generate_stage1_report(
            recon_dir_full,
            use_mcp=False,
            fetch_func=lambda _url: {
                "status": 200,
                "content_type": "text/html",
                "exists": True,
                "notes": "mock",
                "body": "<html><body><script src='/app.js'></script></body></html>",
            },
            headers_fetch_func=mock_headers_fetch,
        )
        generated_names = {p.name for p in generated}
        assert "ai_persistence_manifest.json" in generated_names

        run_id = recon_dir_full.name
        job_id = f"{run_id}-stage1"
        expected_run_link = f"recon://runs/{run_id}"
        expected_job_link = f"recon://jobs/{job_id}"
        expected_trace_prefix = f"{run_id}-{job_id}-mcp"

        manifest = json.loads((recon_dir_full / "ai_persistence_manifest.json").read_text(encoding="utf-8"))
        assert manifest["run_id"] == run_id
        assert manifest["job_id"] == job_id
        assert manifest["run_link"] == expected_run_link
        assert manifest["job_link"] == expected_job_link
        assert manifest["trace_id"] == expected_trace_prefix
        assert manifest["mcp_trace_refs"] == [
            "mcp_invocation_audit_meta.json",
            "mcp_invocation_audit.jsonl",
        ]

        saw_non_empty_evidence_refs = False
        for task_name in REC108_TASK_NAMES:
            raw_name = f"ai_{task_name}_raw.json"
            normalized_name = f"ai_{task_name}_normalized.json"
            input_bundle_name = f"ai_{task_name}_input_bundle.json"
            validation_name = f"ai_{task_name}_validation.json"
            rendered_prompt_name = f"ai_{task_name}_rendered_prompt.md"
            for filename in (
                raw_name,
                normalized_name,
                input_bundle_name,
                validation_name,
                rendered_prompt_name,
            ):
                assert filename in generated_names
                assert filename in manifest["ai_artifacts"]

            raw_doc = json.loads((recon_dir_full / raw_name).read_text(encoding="utf-8"))
            normalized_doc = json.loads((recon_dir_full / normalized_name).read_text(encoding="utf-8"))
            input_bundle_doc = json.loads((recon_dir_full / input_bundle_name).read_text(encoding="utf-8"))
            validation_doc = json.loads((recon_dir_full / validation_name).read_text(encoding="utf-8"))
            rendered_prompt = (recon_dir_full / rendered_prompt_name).read_text(encoding="utf-8")

            for doc in (raw_doc, normalized_doc, input_bundle_doc, validation_doc):
                assert doc["run_id"] == run_id
                assert doc["job_id"] == job_id
                assert doc["run_link"] == expected_run_link
                assert doc["job_link"] == expected_job_link
                assert doc["trace_id"].startswith(f"{expected_trace_prefix}:")
                assert doc["trace_id"].endswith(task_name)

            assert raw_doc["validation"]["is_valid"] is True
            assert normalized_doc["validation"]["is_valid"] is True
            assert validation_doc["input"]["is_valid"] is True
            assert validation_doc["output"]["is_valid"] is True

            assert isinstance(raw_doc["evidence_trace"]["evidence_refs"], list)
            assert isinstance(input_bundle_doc["evidence_refs"], list)
            if raw_doc["evidence_trace"]["evidence_refs"] or input_bundle_doc["evidence_refs"]:
                saw_non_empty_evidence_refs = True
            assert "mcp_invocation_audit_meta.json" in raw_doc["evidence_trace"]["mcp_trace_refs"]
            assert "mcp_invocation_audit.jsonl" in raw_doc["evidence_trace"]["mcp_trace_refs"]
            assert "mcp_invocation_audit_meta.json" in normalized_doc["evidence_trace"]["mcp_trace_refs"]
            assert "mcp_invocation_audit.jsonl" in normalized_doc["evidence_trace"]["mcp_trace_refs"]
            assert "mcp_invocation_audit_meta.json" in input_bundle_doc["mcp_trace_refs"]
            assert "mcp_invocation_audit.jsonl" in input_bundle_doc["mcp_trace_refs"]

            assert f"Task: {task_name}" in rendered_prompt
            assert f"Trace ID: {expected_trace_prefix}:{task_name}" in rendered_prompt
            assert expected_run_link in rendered_prompt
            assert expected_job_link in rendered_prompt
        assert saw_non_empty_evidence_refs is True

    def test_stage1_report_sections_8_14_have_headings_and_taxonomy_badges(
        self,
        recon_dir_full: Path,
        mock_endpoint_fetch,
        mock_headers_fetch,
    ) -> None:
        generate_stage1_report(
            recon_dir_full,
            use_mcp=False,
            fetch_func=mock_endpoint_fetch,
            headers_fetch_func=mock_headers_fetch,
        )

        content = (recon_dir_full / "stage1_report.html").read_text(encoding="utf-8")
        content_lower = content.lower()
        section_expectations = [
            (
                "section-08-javascript-frontend-analysis",
                "8. javascript / frontend analysis",
                ("badge-evidence", "badge-observation", "badge-inference"),
            ),
            (
                "section-09-parameters-input-surfaces",
                "9. parameters and input surfaces",
                ("badge-evidence", "badge-observation", "badge-hypothesis"),
            ),
            (
                "section-10-api-surface-mapping",
                "10. api surface mapping",
                ("badge-evidence", "badge-observation", "badge-inference"),
            ),
            (
                "section-11-headers-cookies-tls-analysis",
                "11. headers / cookies / tls analysis",
                ("badge-evidence", "badge-observation", "badge-inference"),
            ),
            (
                "section-12-content-similarity-and-routing-behavior",
                "12. content similarity and routing behavior",
                ("badge-evidence", "badge-observation", "badge-hypothesis"),
            ),
            (
                "section-13-anomaly-validation",
                "13. anomaly validation",
                ("badge-evidence", "badge-hypothesis"),
            ),
            (
                "section-14-stage-2-preparation",
                "14. stage 2 preparation",
                ("badge-inference",),
            ),
        ]
        for section_id, heading, badges in section_expectations:
            match = re.search(
                rf'<section id="{section_id}" class="section">(.+?)</section>',
                content_lower,
                flags=re.S,
            )
            assert match is not None, f"Missing section {section_id}"
            section_html = match.group(1)
            assert heading in section_html
            for badge in badges:
                assert badge in section_html, f"Missing {badge} in {section_id}"

    def test_stage1_report_sections_15_18_have_taxonomy_badges(
        self,
        recon_dir_full: Path,
        mock_endpoint_fetch,
        mock_headers_fetch,
    ) -> None:
        """REC-010: Sections 15-18 have Evidence/Observation/Inference badges."""
        generate_stage1_report(
            recon_dir_full,
            use_mcp=False,
            fetch_func=mock_endpoint_fetch,
            headers_fetch_func=mock_headers_fetch,
        )
        content = (recon_dir_full / "stage1_report.html").read_text(encoding="utf-8")
        content_lower = content.lower()
        section_expectations = [
            ("section-15-tools-and-ai-used", "15. tools", ("badge-evidence",)),
            ("section-16-intel-osint-enrichment", "16. intel", ("badge-observation",)),
            ("section-17-stage-3-readiness", "17. stage 3 readiness", ("badge-inference",)),
            ("section-18-route-classification", "18. route classification", ("badge-evidence", "badge-observation")),
        ]
        for section_id, heading, badges in section_expectations:
            match = re.search(
                rf'<section id="{section_id}" class="section">(.+?)</section>',
                content_lower,
                flags=re.S,
            )
            assert match is not None, f"Missing section {section_id}"
            section_html = match.group(1)
            assert heading in section_html
            for badge in badges:
                assert badge in section_html, f"Missing {badge} in {section_id}"

def test_run_intel_adapters_sanitizes_exception_details(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FailingAdapter:
        name = "failing_source"

        async def fetch(self, _domain: str) -> dict:
            raise RuntimeError("token=secret-value internal trace should never leak")

    fake_module = SimpleNamespace(get_available_intel_adapters=lambda: [_FailingAdapter()])
    monkeypatch.setitem(sys.modules, "src.recon.adapters.intel", fake_module)

    result = _run_intel_adapters("example.com")
    assert result["adapters"]

    adapter_entry = result["adapters"][0]
    assert adapter_entry["source"] == "failing_source"
    assert adapter_entry["error_code"] == "adapter_fetch_failed"
    assert adapter_entry["error_category"] == "upstream_adapter_error"
    assert "error" not in adapter_entry
    assert "secret-value" not in str(adapter_entry)


def test_stage2_structured_type_priority_are_whitelisted_for_css_classes() -> None:
    html = _render_stage2_from_structured(
        {
            "priority_hypotheses": [
                {
                    "type": 'evil" onclick="alert(1)',
                    "source": "ai",
                    "text": "payload",
                    "priority": 'high xss" style="display:block',
                }
            ],
            "trust_boundaries": [],
            "critical_assets": [],
            "entry_points": [],
        }
    )

    assert 'onclick="alert(1)' not in html
    assert 'style="display:block' not in html
    assert 'class="evil' not in html
    assert "badge-evil" not in html
    assert "badge-high xss" not in html
    assert 'class="observation"' in html
    assert "badge-observation" in html
    assert "badge-low" in html


def test_anomalies_structured_type_is_whitelisted_for_css_classes() -> None:
    html = _render_anomalies_from_structured(
        {
            "anomalies": [
                {
                    "type": 'inference bad" data-x="1',
                    "source": "scanner",
                    "host": "a.example.com",
                    "description": "desc",
                }
            ],
            "hypotheses": [
                {
                    "type": 'hypothesis<script>alert(1)</script>',
                    "source": "ai",
                    "text": "text",
                }
            ],
        }
    )

    assert 'data-x="1' not in html
    assert "<script>alert(1)</script>" not in html
    assert "badge-inference bad" not in html
    assert "badge-hypothesis<script>" not in html
    assert 'class="observation"' in html
    assert "badge-observation" in html
    assert "badge-hypothesis" in html
