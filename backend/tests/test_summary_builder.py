"""RECON-009 — recon summary document builder."""

import json

from src.recon.summary_builder import (
    RECON_SUMMARY_SCHEMA_VERSION,
    build_recon_summary_document,
    mask_email,
)


def test_mask_email_redacts_local_part() -> None:
    assert mask_email("alice@example.com").endswith("@example.com")
    assert "alice" not in mask_email("alice@example.com").split("@")[0]


def test_build_recon_summary_document_fixture() -> None:
    tool_results = {
        "subdomains_merged": {"stdout": json.dumps(["www.example.com", "api.example.com"])},
        "kal_dns_intel": [{"data": {"hostname": "mail.example.com"}}],
        "dns_depth": {
            "structured": {
                "records": [
                    {"host": "example.com", "type": "A", "value": "93.184.216.34"},
                ],
            },
        },
        "httpx": {
            "stdout": json.dumps(
                {
                    "url": "https://example.com/",
                    "host": "example.com",
                    "strict-transport-security": "max-age=31536000",
                }
            ),
        },
        "http_probe_tech_stack": {
            "by_host": {"example.com": {"technologies": [{"name": "nginx"}]}},
            "technologies": [{"host": "example.com", "name": "nginx", "version": None}],
        },
        "url_history_urls": {
            "urls": ["https://example.com/a", "https://example.com/b"],
        },
        "js_analysis": {
            "js_urls": ["https://example.com/app.js"],
            "query_params": {
                "unique_names": ["id", "token"],
                "urls_with_query": 2,
            },
        },
        "theharvester": {"stdout": "Contact: leak@example.com and other@example.org\n"},
        "asn_summary": {"asn": "15169", "org": "Test"},
        "gowitness_screenshots": {
            "artifacts": [
                {"url": "https://example.com/", "minio_key": "t/s/recon/raw/k.png", "success": True},
            ],
        },
        "recon_open_ports_merged": {"stdout": "ports: 443, port 80"},
    }

    doc = build_recon_summary_document(tool_results, target="https://example.com/")

    assert doc["_schema_version"] == RECON_SUMMARY_SCHEMA_VERSION
    assert doc["target"] == "https://example.com/"
    assert "www.example.com" in doc["subdomains"]
    assert doc["dns_records"]
    assert "example.com" in doc["live_hosts"] or "https://example.com/" in doc["live_hosts"]
    assert 80 in doc["ports"] and 443 in doc["ports"]
    assert len(doc["urls"]) == 2
    assert doc["js_files"] == ["https://example.com/app.js"]
    assert "id" in doc["parameters"].get("unique_param_names", [])
    assert doc["emails_masked"]
    assert doc["asn"].get("asn") == "15169"
    assert doc["screenshots"].get("https://example.com/") == "t/s/recon/raw/k.png"
    assert doc["technologies_combined"].get("technologies")
    assert doc["security_headers"].get("example.com", {}).get("strict-transport-security")
    assert doc["ssl_info"] == []
    assert doc["outdated_components"] == []


def test_build_recon_summary_document_empty() -> None:
    doc = build_recon_summary_document({}, target="")
    assert doc["_schema_version"] == RECON_SUMMARY_SCHEMA_VERSION
    assert doc["subdomains"] == []
    assert doc["security_headers"] == {}
