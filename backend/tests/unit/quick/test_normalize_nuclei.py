"""QUICK-005 — nuclei-like payload normalizes to Finding / Occurrence / Evidence."""

from __future__ import annotations

from typing import Any

import pytest

from src.quick.normalize import (
    QuickNormalizeContext,
    normalize_match,
    normalize_tool_output,
)
from src.quick.provenance import evidence_json_for_llm

_TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_SCAN_ID = "11111111-2222-3333-4444-555555555555"
_ENGAGEMENT_ID = "99999999-8888-7777-6666-555555555555"
_ASSET_ID = "abcdef01-2345-6789-abcd-ef0123456789"
_TASK_ID = "fedcba98-7654-3210-fedc-ba9876543210"
_POLICY_ID = "01234567-89ab-cdef-0123-456789abcdef"
_LEASE_ID = "aa11bb22-cc33-dd44-ee55-ff6677889900"
_ASSET = "https://app.example"
_FAKE_ARTIFACT = "t/s/vuln_analysis/raw/quick_tool_raw.json"


@pytest.fixture(autouse=True)
def _mock_minio(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "src.quick.normalize.sink_raw_json",
        lambda **_kwargs: _FAKE_ARTIFACT,
    )


def _ctx(**overrides: Any) -> QuickNormalizeContext:
    base: dict[str, Any] = dict(
        tenant_id=_TENANT_ID,
        scan_id=_SCAN_ID,
        engagement_id=_ENGAGEMENT_ID,
        asset_id=_ASSET_ID,
        asset=_ASSET,
        tool_id="nuclei",
        tool_version="3.3.0",
        capability_id="web.application.cve.known_product",
        phase="vuln_analysis",
        task_id=_TASK_ID,
        policy_decision_id=_POLICY_ID,
        lease_id=_LEASE_ID,
        template_id="http-cve-nginx",
        template_digest="b" * 64,
        protocol="https",
    )
    base.update(overrides)
    return QuickNormalizeContext(**base)


def _nuclei_match(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "template-id": "http-cve-nginx",
        "template_id": "http-cve-nginx",
        "matched-at": "https://app.example/login?user=admin",
        "host": "https://app.example",
        "severity": "high",
        "name": "Nginx known CVE",
        "title": "Nginx known CVE",
        "category": "cve",
        "parameter": "user",
        "matcher_name": "status",
        "password": "should-never-reach-llm",
        "token": "secret-token-value",
        "authorization": "Bearer leaked",
        "api_key": "sk-live-not-for-llm",
    }
    payload.update(overrides)
    return payload


def test_nuclei_payload_yields_finding_with_identity_fields() -> None:
    result = normalize_match(_nuclei_match(), ctx=_ctx())
    finding = result.finding
    occurrence = result.occurrence
    evidence = result.evidence

    assert finding.asset == _ASSET
    assert finding.asset_id == _ASSET_ID
    assert finding.endpoint == "https://app.example/login?user=admin"
    assert finding.parameter == "user"
    assert finding.protocol == "https"
    assert finding.template_id == "http-cve-nginx"
    assert finding.tool_id == "nuclei"
    assert finding.coverage_capability_id == "web.application.cve.known_product"
    assert finding.severity == "high"
    assert finding.title == "Nginx known CVE"

    assert occurrence.scanner == "nuclei"
    assert occurrence.detector_id == "http-cve-nginx"
    assert occurrence.protocol == "https"
    assert occurrence.parameter == "user"
    assert occurrence.endpoint == finding.endpoint
    assert occurrence.finding_key == finding.finding_key
    assert occurrence.late_oast is False

    assert evidence.tool_id == "nuclei"
    assert evidence.template_id == "http-cve-nginx"
    assert evidence.artifact_key == _FAKE_ARTIFACT
    assert len(evidence.evidence_hash) == 64
    assert len(finding.finding_key) == 64


def test_finding_linked_to_evidence_task_and_policy() -> None:
    result = normalize_match(_nuclei_match(), ctx=_ctx())
    finding = result.finding
    evidence = result.evidence

    assert finding.evidence_ids == (evidence.evidence_id,)
    assert finding.occurrence_keys == (result.occurrence.occurrence_key,)
    assert finding.task_id == _TASK_ID
    assert finding.policy_decision_id == _POLICY_ID
    assert finding.lease_id == _LEASE_ID
    assert finding.provenance.task_id == _TASK_ID
    assert finding.provenance.policy_decision_id == _POLICY_ID
    assert finding.provenance.lease_id == _LEASE_ID
    assert finding.provenance.scan_id == _SCAN_ID
    assert finding.provenance.evidence_hash == evidence.evidence_hash
    assert finding.provenance.artifact_key == _FAKE_ARTIFACT


def test_secrets_stripped_from_llm_evidence_json() -> None:
    result = normalize_match(_nuclei_match(), ctx=_ctx())
    payload = result.evidence.payload
    dumped = result.evidence.model_dump(mode="json")
    blob = str(dumped)

    for secret_key in ("password", "token", "authorization", "api_key"):
        assert secret_key not in payload
        assert secret_key not in dumped["payload"]
    assert "should-never-reach-llm" not in blob
    assert "secret-token-value" not in blob
    assert "sk-live-not-for-llm" not in blob
    assert "Bearer leaked" not in blob

    leaked = evidence_json_for_llm(_nuclei_match())
    assert "password" not in leaked
    assert "token" not in leaked
    assert "authorization" not in leaked
    assert "api_key" not in leaked


def test_secret_shaped_strings_redacted_in_llm_payload() -> None:
    result = normalize_match(
        _nuclei_match(host="https://app.example password=hunter2"),
        ctx=_ctx(),
    )
    host = result.evidence.payload.get("host")
    assert isinstance(host, str)
    assert "hunter2" not in host
    assert "[REDACTED]" in host


def test_parameter_extracted_from_query_when_not_explicit() -> None:
    payload = _nuclei_match()
    payload.pop("parameter")
    result = normalize_match(payload, ctx=_ctx())
    assert result.finding.parameter == "user"
    assert result.occurrence.parameter == "user"


def test_template_id_falls_back_to_hyphenated_nuclei_field() -> None:
    payload = _nuclei_match()
    payload.pop("template_id")
    result = normalize_match(payload, ctx=_ctx(template_id=None))
    assert result.finding.template_id == "http-cve-nginx"
    assert result.occurrence.detector_id == "http-cve-nginx"


def test_normalize_tool_output_jsonl_and_empty() -> None:
    ctx = _ctx()
    jsonl = "\n".join(
        (
            '{"template_id":"t1","matched_at":"https://app.example/a","severity":"high","category":"cve","name":"A"}',
            '{"template_id":"t2","matched_at":"https://app.example/b","severity":"medium","category":"xss","name":"B"}',
        )
    )
    results = normalize_tool_output(jsonl, ctx=ctx)
    assert len(results) == 2
    keys = [item.finding.finding_key for item in results]
    assert keys == sorted(keys)

    assert normalize_tool_output("", ctx=ctx) == ()
    assert normalize_tool_output(b"", ctx=ctx) == ()
    assert normalize_tool_output({"findings": []}, ctx=ctx) == ()


def test_normalize_tool_output_nested_matches_list() -> None:
    results = normalize_tool_output({"matches": [_nuclei_match()]}, ctx=_ctx())
    assert len(results) == 1
    assert results[0].finding.tool_id == "nuclei"
    assert results[0].finding.template_id == "http-cve-nginx"


def test_raw_artifact_not_stored_outside_raw_phases(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[str] = []

    def _sink(**kwargs: Any) -> str:
        called.append(str(kwargs.get("phase")))
        return _FAKE_ARTIFACT

    monkeypatch.setattr("src.quick.normalize.sink_raw_json", _sink)
    result = normalize_match(_nuclei_match(), ctx=_ctx(phase="reporting"))
    assert called == []
    assert result.evidence.artifact_key is None
    assert result.finding.provenance.artifact_key is None


def test_sink_failure_does_not_drop_normalized_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(**_kwargs: Any) -> str:
        raise OSError("minio unavailable")

    monkeypatch.setattr("src.quick.normalize.sink_raw_json", _boom)
    result = normalize_match(_nuclei_match(), ctx=_ctx())
    assert result.finding.finding_id
    assert result.evidence.artifact_key is None
    assert result.finding.evidence_ids == (result.evidence.evidence_id,)
