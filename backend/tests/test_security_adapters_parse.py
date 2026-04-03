"""Block 9 — security tool adapters: sample JSON/JSONL outputs for parse_output + normalize."""

import json

import pytest

from src.recon.adapters.security import (
    CheckovAdapter,
    ProwlerAdapter,
    ScoutSuiteAdapter,
    TerrascanAdapter,
    TruffleHogAdapter,
)


@pytest.mark.asyncio
async def test_trufflehog_jsonl_parse_and_normalize() -> None:
    line = json.dumps(
        {
            "DetectorName": "AWS",
            "Verified": True,
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "SourceMetadata": {"Data": {"filesystem": "/app/.env"}},
        }
    )
    adapter = TruffleHogAdapter()
    rows = await adapter.parse_output(line + "\n")
    assert len(rows) == 1
    findings = await adapter.normalize(rows)
    assert len(findings) == 1
    assert findings[0]["source_tool"] == "trufflehog"
    assert findings[0]["data"]["title"] == "AWS"
    assert findings[0]["data"]["severity"] == "high"
    assert findings[0]["data"]["cwe"] == "CWE-798"


@pytest.mark.asyncio
async def test_checkov_failed_checks_parse_and_normalize() -> None:
    raw = json.dumps(
        {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_1",
                        "check_name": "S3 policy",
                        "severity": "HIGH",
                        "file_path": "main.tf",
                        "file_line_range": [12, 14],
                    }
                ]
            }
        }
    )
    adapter = CheckovAdapter()
    rows = await adapter.parse_output(raw)
    assert len(rows) == 1
    findings = await adapter.normalize(rows)
    assert findings[0]["source_tool"] == "checkov"
    assert "CKV_AWS_1" in findings[0]["data"]["title"]
    assert findings[0]["data"]["cwe"] == "CWE-1032"


@pytest.mark.asyncio
async def test_terrascan_violations_parse_and_normalize() -> None:
    raw = json.dumps(
        {
            "results": {
                "violations": [
                    {
                        "rule_name": "S3_BUCKET_LOGGING_DISABLED",
                        "severity": "HIGH",
                        "file_name": "bucket.tf",
                        "line": 4,
                        "category": "S3",
                    }
                ]
            }
        }
    )
    adapter = TerrascanAdapter()
    rows = await adapter.parse_output(raw)
    assert len(rows) == 1
    findings = await adapter.normalize(rows)
    assert findings[0]["source_tool"] == "terrascan"
    assert findings[0]["data"]["title"] == "S3_BUCKET_LOGGING_DISABLED"


@pytest.mark.asyncio
async def test_prowler_jsonl_fail_only() -> None:
    adapter = ProwlerAdapter()
    lines = "\n".join(
        [
            json.dumps({"Status": "PASS", "CheckTitle": "ignored"}),
            json.dumps(
                {
                    "Status": "FAIL",
                    "CheckTitle": "Root account MFA",
                    "Severity": "HIGH",
                    "ResourceId": "arn:aws:iam::1:root",
                    "Region": "us-east-1",
                    "CheckID": "check_root_mfa",
                }
            ),
        ]
    )
    rows = await adapter.parse_output(lines)
    assert len(rows) == 1
    assert rows[0]["Status"] == "FAIL"
    findings = await adapter.normalize(rows)
    assert len(findings) == 1
    assert findings[0]["data"]["title"] == "Root account MFA"
    assert findings[0]["source_tool"] == "prowler"


@pytest.mark.asyncio
async def test_scoutsuite_js_prefix_parse_and_normalize() -> None:
    blob = """scoutsuite_results = {"services": {"s3": {"findings": {"f1": {"description": "Public bucket", "flagged_items": 3, "name": "f1"}}}}}}"""
    adapter = ScoutSuiteAdapter()
    rows = await adapter.parse_output(blob)
    assert len(rows) == 1
    findings = await adapter.normalize(rows)
    assert len(findings) == 1
    assert findings[0]["source_tool"] == "scoutsuite"
    assert "Public bucket" in findings[0]["data"]["title"]
    assert findings[0]["data"]["flagged_items"] == 3


@pytest.mark.asyncio
async def test_scoutsuite_flagged_zero_skipped_in_normalize() -> None:
    raw = json.dumps(
        {
            "services": {
                "ec2": {
                    "findings": {
                        "ok": {"description": "Clean", "flagged_items": 0},
                    }
                }
            }
        }
    )
    adapter = ScoutSuiteAdapter()
    rows = await adapter.parse_output(raw)
    assert len(rows) == 1
    findings = await adapter.normalize(rows)
    assert findings == []
