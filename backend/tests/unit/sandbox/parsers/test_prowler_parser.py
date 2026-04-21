"""Unit tests for :mod:`src.sandbox.parsers.prowler_parser` (Backlog/dev1_md §4.15 — ARG-029).

Pinned contracts:

* Top-level JSON array; canonical artefact ``prowler.json`` overrides
  stdout.
* Only ``Status == "FAIL"`` records are emitted; ``PASS`` / ``MUTED`` /
  ``MANUAL`` are dropped silently.
* Severity → CVSS map: critical=9.5, high=7.5, medium=5.0, low=3.0,
  info=0.0; unknown defaults to 0.0.
* Category routing: encryption/KMS/TLS keywords → CRYPTO; mfa/iam_user
  keywords → AUTH; otherwise MISCONFIG.  CWE varies accordingly.
* AWS account IDs in ``Resource.Identifier`` and ``ResourceArn`` are
  PRESERVED — they are tenancy identifiers, not secrets.
* Dedup: ``(check_id, account_id, resource_id)``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers import prowler_parser as prowler_module
from src.sandbox.parsers.prowler_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_prowler_json,
)


def _record(
    *,
    status: str = "FAIL",
    severity: str = "high",
    check_id: str = "iam_root_mfa_enabled",
    check_title: str = "Ensure MFA is enabled for the root account",
    service_name: str = "iam",
    region: str = "us-east-1",
    account_id: str = "123456789012",
    resource_id: str | None = None,
    resource_arn: str = "arn:aws:iam::123456789012:root",
    resource_type: str = "AwsIamUser",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "Status": status,
        "Severity": severity,
        "CheckID": check_id,
        "CheckTitle": check_title,
        "ServiceName": service_name,
        "Region": region,
        "AccountId": account_id,
        "ResourceId": resource_id or resource_arn,
        "ResourceArn": resource_arn,
        "ResourceType": resource_type,
        "Resource": {"Identifier": resource_arn},
        "StatusExtended": "Root account does not have MFA enabled",
        "Compliance": {"CIS-1.5.0": ["1.5"]},
        "Remediation": {
            "Recommendation": {
                "Text": "Enable MFA on the root account via the IAM console."
            }
        },
    }
    if extra:
        record.update(extra)
    return record


def _payload(*records: dict[str, Any]) -> bytes:
    return json.dumps(list(records)).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_prowler_json(b"", b"", tmp_path, "prowler") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "prowler.json"
    canonical.write_bytes(_payload(_record(check_id="canonical_check")))
    decoy = _payload(_record(check_id="decoy_check"))
    findings = parse_prowler_json(decoy, b"", tmp_path, "prowler")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "canonical_check" in sidecar
    assert "decoy_check" not in sidecar


def test_only_fail_status_emitted(tmp_path: Path) -> None:
    payload = _payload(
        _record(status="FAIL", check_id="fail_check"),
        _record(status="PASS", check_id="pass_check"),
        _record(status="MUTED", check_id="muted_check"),
        _record(status="MANUAL", check_id="manual_check"),
    )
    findings = parse_prowler_json(payload, b"", tmp_path, "prowler")
    assert len(findings) == 1


def test_severity_to_cvss_mapping(tmp_path: Path) -> None:
    payload = _payload(
        _record(severity="critical", check_id="c1", account_id="1"),
        _record(severity="high", check_id="c2", account_id="2"),
        _record(severity="medium", check_id="c3", account_id="3"),
        _record(severity="low", check_id="c4", account_id="4"),
        _record(severity="informational", check_id="c5", account_id="5"),
    )
    findings = parse_prowler_json(payload, b"", tmp_path, "prowler")
    scores = sorted(f.cvss_v3_score for f in findings)
    assert scores == pytest.approx([0.0, 3.0, 5.0, 7.5, 9.5])


def test_crypto_keyword_routes_to_crypto_category(tmp_path: Path) -> None:
    payload = _payload(
        _record(
            check_id="ec2_ebs_encryption_enabled",
            check_title="Ensure EBS volume encryption is enabled",
        )
    )
    findings = parse_prowler_json(payload, b"", tmp_path, "prowler")
    assert findings[0].category is FindingCategory.CRYPTO
    assert set(findings[0].cwe) == {327, 326}


def test_auth_keyword_routes_to_auth_category(tmp_path: Path) -> None:
    payload = _payload(_record(check_id="iam_root_mfa_enabled"))
    findings = parse_prowler_json(payload, b"", tmp_path, "prowler")
    assert findings[0].category is FindingCategory.AUTH
    assert set(findings[0].cwe) == {287, 521}


def test_public_keyword_routes_misconfig_with_732(tmp_path: Path) -> None:
    payload = _payload(
        _record(
            check_id="s3_bucket_public_access",
            check_title="Ensure S3 bucket is not publicly accessible",
        )
    )
    findings = parse_prowler_json(payload, b"", tmp_path, "prowler")
    assert findings[0].category is FindingCategory.MISCONFIG
    assert set(findings[0].cwe) == {732, 200}


def test_account_id_preserved_in_sidecar(tmp_path: Path) -> None:
    parse_prowler_json(_payload(_record()), b"", tmp_path, "prowler")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "123456789012" in sidecar
    assert "REDACTED" not in sidecar


def test_resource_arn_preserved_intact(tmp_path: Path) -> None:
    arn = "arn:aws:s3:::my-public-bucket"
    parse_prowler_json(
        _payload(
            _record(
                check_id="s3_bucket_public_access",
                resource_arn=arn,
                resource_id=arn,
            )
        ),
        b"",
        tmp_path,
        "prowler",
    )
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert arn in sidecar


def test_dedup_collapses_same_check_account_resource(tmp_path: Path) -> None:
    payload = _payload(_record(), _record())
    findings = parse_prowler_json(payload, b"", tmp_path, "prowler")
    assert len(findings) == 1


def test_findings_sorted_by_severity_descending(tmp_path: Path) -> None:
    payload = _payload(
        _record(severity="low", check_id="c1"),
        _record(severity="critical", check_id="c2"),
        _record(severity="high", check_id="c3"),
    )
    findings = parse_prowler_json(payload, b"", tmp_path, "prowler")
    severities = [f.cvss_v3_score for f in findings]
    assert severities == sorted(severities, reverse=True)


def test_envelope_not_list_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    canonical = tmp_path / "prowler.json"
    canonical.write_bytes(b'{"unexpected": "shape"}')
    with caplog.at_level("WARNING"):
        findings = parse_prowler_json(b"", b"", tmp_path, "prowler")
    assert findings == []
    assert any(
        "prowler_parser_envelope_not_list" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_record_missing_check_id_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    raw = _record()
    raw.pop("CheckID")
    payload = _payload(raw, _record(check_id="ok_check"))
    with caplog.at_level("WARNING"):
        findings = parse_prowler_json(payload, b"", tmp_path, "prowler")
    assert len(findings) == 1
    assert any(
        "prowler_parser_record_missing_field" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(prowler_module, "_MAX_FINDINGS", 2)
    payload = _payload(*(_record(check_id=f"check-{i}") for i in range(5)))
    with caplog.at_level("WARNING"):
        findings = parse_prowler_json(payload, b"", tmp_path, "prowler")
    assert len(findings) == 2
    assert any(
        "prowler_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_remediation_text_truncated_to_512(tmp_path: Path) -> None:
    long_text = "X" * 2000
    payload = _payload(
        _record(
            extra={
                "Remediation": {"Recommendation": {"Text": long_text}},
            }
        )
    )
    parse_prowler_json(payload, b"", tmp_path, "prowler")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").strip()
    blob = json.loads(sidecar)
    assert len(blob["remediation"]) == 512
