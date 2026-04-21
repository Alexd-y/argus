"""Unit tests for :mod:`src.sandbox.parsers.cloudsploit_parser` (Backlog §4.15 — ARG-029).

Pinned contracts:

* Canonical artefact ``cloudsploit.json`` overrides stdout.
* Both newer ``{"results": [...]}`` and legacy nested
  ``{"regions": {...}}`` envelopes are supported.
* Only ``FAIL`` and ``WARN`` statuses become findings; ``OK`` /
  ``UNKNOWN`` are dropped silently.
* Severity ladder: ``WARN`` → low (3.0); ``FAIL`` → medium (5.0);
  high-keyword titles (mfa / kms / encryption disabled / publicly
  accessible / world-readable / all users) escalate to high (7.5).
* Category routing follows ``_CATEGORY_KEYWORDS``.  AWS account IDs
  in ARNs are PRESERVED (tenancy identifier, not a secret).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers import cloudsploit_parser as cs_module
from src.sandbox.parsers.cloudsploit_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_cloudsploit_json,
)


def _result(
    *,
    status: str = "FAIL",
    title: str = "S3 Bucket All Users Acl",
    plugin: str = "bucketAllUsersAcl",
    category: str = "S3",
    region: str = "us-east-1",
    resource: str = "arn:aws:s3:::public-data",
    message: str = "Bucket grants public READ",
) -> dict[str, Any]:
    return {
        "status": status,
        "title": title,
        "plugin": plugin,
        "category": category,
        "region": region,
        "resource": resource,
        "message": message,
    }


def _payload(*results: dict[str, Any], cloud: str = "aws") -> bytes:
    return json.dumps({"cloud": cloud, "results": list(results)}).encode("utf-8")


def _legacy_payload(
    *,
    cloud: str = "aws",
    region: str = "us-east-1",
    plugin: str = "bucketAllUsersAcl",
    entries: list[dict[str, Any]] | None = None,
) -> bytes:
    return json.dumps(
        {
            "cloud": cloud,
            "regions": {region: {plugin: entries or [_result()]}},
        }
    ).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_cloudsploit_json(b"", b"", tmp_path, "cloudsploit") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "cloudsploit.json"
    canonical.write_bytes(_payload(_result(plugin="canonical_plugin")))
    decoy = _payload(_result(plugin="decoy_plugin"))
    findings = parse_cloudsploit_json(decoy, b"", tmp_path, "cloudsploit")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "canonical_plugin" in sidecar
    assert "decoy_plugin" not in sidecar


def test_only_fail_warn_emitted(tmp_path: Path) -> None:
    payload = _payload(
        _result(status="FAIL", plugin="fail"),
        _result(status="WARN", plugin="warn"),
        _result(status="OK", plugin="ok"),
        _result(status="UNKNOWN", plugin="unknown"),
    )
    findings = parse_cloudsploit_json(payload, b"", tmp_path, "cloudsploit")
    assert len(findings) == 2


def test_warn_severity_low_fail_severity_medium(tmp_path: Path) -> None:
    payload = _payload(
        _result(status="WARN", title="Low priority warning", plugin="w"),
        _result(status="FAIL", title="Medium failure", plugin="f"),
    )
    findings = parse_cloudsploit_json(payload, b"", tmp_path, "cloudsploit")
    scores = sorted(f.cvss_v3_score for f in findings)
    assert scores == pytest.approx([3.0, 5.0])


def test_high_keyword_escalates_severity(tmp_path: Path) -> None:
    payload = _payload(
        _result(
            status="FAIL",
            title="Root account MFA disabled",
            plugin="rootMfa",
            category="IAM",
            resource="arn:aws:iam::123456789012:root",
        )
    )
    findings = parse_cloudsploit_json(payload, b"", tmp_path, "cloudsploit")
    assert findings[0].cvss_v3_score == pytest.approx(7.5)


def test_encryption_disabled_routes_to_crypto(tmp_path: Path) -> None:
    payload = _payload(
        _result(
            status="FAIL",
            title="EBS Volume Encryption disabled",
            category="Encryption",
            plugin="ebsEnc",
        )
    )
    findings = parse_cloudsploit_json(payload, b"", tmp_path, "cloudsploit")
    assert findings[0].category is FindingCategory.CRYPTO
    assert 311 in findings[0].cwe


def test_mfa_routes_to_auth(tmp_path: Path) -> None:
    payload = _payload(
        _result(
            status="FAIL",
            title="MFA not enabled for IAM users",
            category="IAM",
            plugin="iamMfa",
        )
    )
    findings = parse_cloudsploit_json(payload, b"", tmp_path, "cloudsploit")
    assert findings[0].category is FindingCategory.AUTH
    assert 308 in findings[0].cwe


def test_public_routes_to_misconfig_with_cwe_732(tmp_path: Path) -> None:
    payload = _payload(
        _result(
            status="FAIL",
            title="S3 bucket publicly accessible",
            category="S3",
            plugin="bucketPublic",
        )
    )
    findings = parse_cloudsploit_json(payload, b"", tmp_path, "cloudsploit")
    assert findings[0].category is FindingCategory.MISCONFIG
    assert 732 in findings[0].cwe


def test_account_id_preserved_in_arn(tmp_path: Path) -> None:
    arn = "arn:aws:iam::123456789012:role/admin"
    parse_cloudsploit_json(
        _payload(_result(resource=arn)), b"", tmp_path, "cloudsploit"
    )
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "123456789012" in sidecar
    assert "REDACTED" not in sidecar


def test_legacy_envelope_supported(tmp_path: Path) -> None:
    payload = _legacy_payload(entries=[_result(plugin="legacy_check")])
    findings = parse_cloudsploit_json(payload, b"", tmp_path, "cloudsploit")
    assert len(findings) == 1


def test_dedup_collapses_same_plugin_region_resource_status(tmp_path: Path) -> None:
    payload = _payload(_result(), _result())
    findings = parse_cloudsploit_json(payload, b"", tmp_path, "cloudsploit")
    assert len(findings) == 1


def test_unsupported_payload_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    canonical = tmp_path / "cloudsploit.json"
    canonical.write_bytes(b'"a string is not a valid envelope"')
    with caplog.at_level("WARNING"):
        findings = parse_cloudsploit_json(b"", b"", tmp_path, "cloudsploit")
    assert findings == []
    assert any(
        "cloudsploit_parser_unsupported_payload" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_findings_have_likely_confidence(tmp_path: Path) -> None:
    findings = parse_cloudsploit_json(_payload(_result()), b"", tmp_path, "cloudsploit")
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_findings_sorted_by_severity_descending(tmp_path: Path) -> None:
    payload = _payload(
        _result(status="WARN", plugin="w1", title="warn-only"),
        _result(status="FAIL", plugin="f1", title="MFA disabled"),
        _result(status="FAIL", plugin="f2", title="random misconfig"),
    )
    findings = parse_cloudsploit_json(payload, b"", tmp_path, "cloudsploit")
    scores = [f.cvss_v3_score for f in findings]
    assert scores == sorted(scores, reverse=True)


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(cs_module, "_MAX_FINDINGS", 2)
    payload = _payload(
        *(
            _result(
                plugin=f"plugin-{i}",
                resource=f"arn:aws:s3:::bkt-{i}",
                title=f"Misconfig {i}",
            )
            for i in range(5)
        )
    )
    with caplog.at_level("WARNING"):
        findings = parse_cloudsploit_json(payload, b"", tmp_path, "cloudsploit")
    assert len(findings) == 2
    assert any(
        "cloudsploit_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )
