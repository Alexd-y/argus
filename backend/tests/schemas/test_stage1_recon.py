"""Unit tests for REC-001 Pydantic schemas (backend/app/schemas/recon/stage1.py)."""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from app.schemas.recon.stage1 import (
    AnomaliesStructured,
    AnomalyEntry,
    HypothesisEntry,
    McpTraceEvent,
    ReconResults,
    SslCertEntry,
    TechProfileEntry,
)


# --- Fixtures: valid data builders ---


def _valid_ssl_cert_entry() -> dict:
    return {
        "common_name": "example.com",
        "subject_alternative_names": ["*.example.com", "www.example.com"],
        "issuer": "CN=Let's Encrypt Authority X3",
        "validity_not_before": "2024-01-01T00:00:00",
        "validity_not_after": "2025-01-01T00:00:00",
    }


def _valid_recon_results() -> dict:
    return {
        "target_domain": "example.com",
        "scan_id": "scan-001",
        "generated_at": datetime.now().isoformat(),
        "dns": {"example.com": {"A": ["1.2.3.4"]}},
        "whois": {},
        "ssl_certs": {},
        "tech_stack": [],
        "http_headers": {},
    }


def _valid_tech_profile_entry() -> dict:
    return {
        "host": "example.com",
        "indicator_type": "cms",
        "value": "WordPress",
        "evidence": "X-Generator header",
        "confidence": 0.9,
    }


def _valid_mcp_trace_event() -> dict:
    return {
        "timestamp": datetime.now().isoformat(),
        "tool_name": "subfinder",
        "input_parameters": {"target": "example.com"},
        "output_summary": "Found 5 subdomains",
        "run_id": "run-001",
        "job_id": "job-001",
        "status": "success",
    }


def _valid_anomaly_entry() -> dict:
    return {
        "id": "anom-1",
        "type": "missing_headers",
        "source": "headers_analysis",
        "host": "example.com",
        "description": "Missing security headers",
        "evidence": "X-Frame-Options absent",
    }


def _valid_hypothesis_entry() -> dict:
    return {
        "id": "hyp-1",
        "type": "platform_alias",
        "source": "tech_stack",
        "text": "Possible WordPress CMS based on generator header",
    }


def _valid_anomalies_structured() -> dict:
    return {
        "anomalies": [_valid_anomaly_entry()],
        "hypotheses": [_valid_hypothesis_entry()],
        "coverage_gaps": ["Missing API surface data"],
    }


# --- SslCertEntry ---


class TestSslCertEntry:
    def test_valid_serialization(self) -> None:
        data = _valid_ssl_cert_entry()
        entry = SslCertEntry.model_validate(data)
        assert entry.common_name == "example.com"
        assert "*.example.com" in entry.subject_alternative_names
        assert entry.issuer == "CN=Let's Encrypt Authority X3"
        assert entry.validity_not_before.year == 2024
        assert entry.validity_not_after.year == 2025

    def test_valid_deserialization_roundtrip(self) -> None:
        data = _valid_ssl_cert_entry()
        entry = SslCertEntry.model_validate(data)
        dumped = entry.model_dump(mode="json")
        restored = SslCertEntry.model_validate(dumped)
        assert restored.common_name == entry.common_name
        assert restored.issuer == entry.issuer

    def test_empty_common_name_rejected(self) -> None:
        data = _valid_ssl_cert_entry()
        data["common_name"] = ""
        with pytest.raises(ValidationError):
            SslCertEntry.model_validate(data)

    def test_empty_issuer_rejected(self) -> None:
        data = _valid_ssl_cert_entry()
        data["issuer"] = ""
        with pytest.raises(ValidationError):
            SslCertEntry.model_validate(data)

    def test_common_name_max_length_exceeded_rejected(self) -> None:
        data = _valid_ssl_cert_entry()
        data["common_name"] = "x" * 513
        with pytest.raises(ValidationError):
            SslCertEntry.model_validate(data)

    def test_subject_alternative_names_default_empty(self) -> None:
        data = _valid_ssl_cert_entry()
        del data["subject_alternative_names"]
        entry = SslCertEntry.model_validate(data)
        assert entry.subject_alternative_names == []

    def test_subject_alternative_names_max_length_exceeded_rejected(self) -> None:
        data = _valid_ssl_cert_entry()
        data["subject_alternative_names"] = ["x"] * 201
        with pytest.raises(ValidationError):
            SslCertEntry.model_validate(data)

    def test_rejects_extra_fields(self) -> None:
        data = {**_valid_ssl_cert_entry(), "unknown_field": "x"}
        with pytest.raises(ValidationError):
            SslCertEntry.model_validate(data)

    def test_missing_required_field_rejected(self) -> None:
        data = _valid_ssl_cert_entry()
        del data["validity_not_after"]
        with pytest.raises(ValidationError):
            SslCertEntry.model_validate(data)


# --- ReconResults ---


class TestReconResults:
    def test_valid_serialization(self) -> None:
        data = _valid_recon_results()
        results = ReconResults.model_validate(data)
        assert results.target_domain == "example.com"
        assert results.scan_id == "scan-001"
        assert "example.com" in results.dns
        assert results.dns["example.com"]["A"] == ["1.2.3.4"]

    def test_valid_deserialization_roundtrip(self) -> None:
        data = _valid_recon_results()
        results = ReconResults.model_validate(data)
        dumped = results.model_dump(mode="json")
        restored = ReconResults.model_validate(dumped)
        assert restored.target_domain == results.target_domain
        assert restored.dns == results.dns

    def test_minimal_required_fields(self) -> None:
        data = {
            "target_domain": "example.com",
            "scan_id": "scan-001",
            "generated_at": datetime.now().isoformat(),
        }
        results = ReconResults.model_validate(data)
        assert results.dns == {}
        assert results.whois == {}
        assert results.ssl_certs == {}
        assert results.tech_stack == []
        assert results.http_headers == {}

    def test_empty_target_domain_rejected(self) -> None:
        data = _valid_recon_results()
        data["target_domain"] = ""
        with pytest.raises(ValidationError):
            ReconResults.model_validate(data)

    def test_target_domain_max_length_exceeded_rejected(self) -> None:
        data = _valid_recon_results()
        data["target_domain"] = "x" * 254
        with pytest.raises(ValidationError):
            ReconResults.model_validate(data)

    def test_empty_scan_id_rejected(self) -> None:
        data = _valid_recon_results()
        data["scan_id"] = ""
        with pytest.raises(ValidationError):
            ReconResults.model_validate(data)

    def test_missing_generated_at_rejected(self) -> None:
        data = _valid_recon_results()
        del data["generated_at"]
        with pytest.raises(ValidationError):
            ReconResults.model_validate(data)

    def test_whois_accepts_list(self) -> None:
        data = _valid_recon_results()
        data["whois"] = [{"domain": "example.com"}, {"domain": "test.com"}]
        results = ReconResults.model_validate(data)
        assert isinstance(results.whois, list)
        assert len(results.whois) == 2

    def test_tech_stack_max_length_exceeded_rejected(self) -> None:
        data = _valid_recon_results()
        data["tech_stack"] = [_valid_tech_profile_entry() for _ in range(2001)]
        with pytest.raises(ValidationError):
            ReconResults.model_validate(data)

    def test_rejects_extra_fields(self) -> None:
        data = {**_valid_recon_results(), "unknown_field": "x"}
        with pytest.raises(ValidationError):
            ReconResults.model_validate(data)


# --- TechProfileEntry ---


class TestTechProfileEntry:
    def test_valid_serialization(self) -> None:
        data = _valid_tech_profile_entry()
        entry = TechProfileEntry.model_validate(data)
        assert entry.host == "example.com"
        assert entry.indicator_type == "cms"
        assert entry.value == "WordPress"
        assert entry.evidence == "X-Generator header"
        assert entry.confidence == 0.9

    def test_valid_deserialization_roundtrip(self) -> None:
        data = _valid_tech_profile_entry()
        entry = TechProfileEntry.model_validate(data)
        dumped = entry.model_dump(mode="json")
        restored = TechProfileEntry.model_validate(dumped)
        assert restored.host == entry.host
        assert restored.confidence == entry.confidence

    def test_evidence_default_empty(self) -> None:
        data = _valid_tech_profile_entry()
        del data["evidence"]
        entry = TechProfileEntry.model_validate(data)
        assert entry.evidence == ""

    def test_confidence_default_none(self) -> None:
        data = _valid_tech_profile_entry()
        del data["confidence"]
        entry = TechProfileEntry.model_validate(data)
        assert entry.confidence is None

    def test_confidence_bounds_valid(self) -> None:
        for val in (0.0, 0.5, 1.0):
            data = _valid_tech_profile_entry()
            data["confidence"] = val
            entry = TechProfileEntry.model_validate(data)
            assert entry.confidence == val

    def test_confidence_below_zero_rejected(self) -> None:
        data = _valid_tech_profile_entry()
        data["confidence"] = -0.1
        with pytest.raises(ValidationError):
            TechProfileEntry.model_validate(data)

    def test_confidence_above_one_rejected(self) -> None:
        data = _valid_tech_profile_entry()
        data["confidence"] = 1.1
        with pytest.raises(ValidationError):
            TechProfileEntry.model_validate(data)

    def test_empty_host_rejected(self) -> None:
        data = _valid_tech_profile_entry()
        data["host"] = ""
        with pytest.raises(ValidationError):
            TechProfileEntry.model_validate(data)

    def test_empty_value_rejected(self) -> None:
        data = _valid_tech_profile_entry()
        data["value"] = ""
        with pytest.raises(ValidationError):
            TechProfileEntry.model_validate(data)

    def test_rejects_extra_fields(self) -> None:
        data = {**_valid_tech_profile_entry(), "unknown_field": "x"}
        with pytest.raises(ValidationError):
            TechProfileEntry.model_validate(data)


# --- McpTraceEvent ---


class TestMcpTraceEvent:
    def test_valid_serialization(self) -> None:
        data = _valid_mcp_trace_event()
        event = McpTraceEvent.model_validate(data)
        assert event.tool_name == "subfinder"
        assert event.run_id == "run-001"
        assert event.job_id == "job-001"
        assert event.status == "success"
        assert event.output_summary == "Found 5 subdomains"

    def test_valid_deserialization_roundtrip(self) -> None:
        data = _valid_mcp_trace_event()
        event = McpTraceEvent.model_validate(data)
        dumped = event.model_dump(mode="json")
        restored = McpTraceEvent.model_validate(dumped)
        assert restored.tool_name == event.tool_name
        assert restored.status == event.status

    def test_status_success(self) -> None:
        data = _valid_mcp_trace_event()
        data["status"] = "success"
        event = McpTraceEvent.model_validate(data)
        assert event.status == "success"

    def test_status_error(self) -> None:
        data = _valid_mcp_trace_event()
        data["status"] = "error"
        event = McpTraceEvent.model_validate(data)
        assert event.status == "error"

    def test_invalid_status_rejected(self) -> None:
        data = _valid_mcp_trace_event()
        data["status"] = "pending"
        with pytest.raises(ValidationError):
            McpTraceEvent.model_validate(data)

    def test_input_parameters_default_empty(self) -> None:
        data = _valid_mcp_trace_event()
        del data["input_parameters"]
        event = McpTraceEvent.model_validate(data)
        assert event.input_parameters == {}

    def test_output_summary_default_none(self) -> None:
        data = _valid_mcp_trace_event()
        del data["output_summary"]
        event = McpTraceEvent.model_validate(data)
        assert event.output_summary is None

    def test_empty_tool_name_rejected(self) -> None:
        data = _valid_mcp_trace_event()
        data["tool_name"] = ""
        with pytest.raises(ValidationError):
            McpTraceEvent.model_validate(data)

    def test_output_summary_max_length_exceeded_rejected(self) -> None:
        data = _valid_mcp_trace_event()
        data["output_summary"] = "x" * 10001
        with pytest.raises(ValidationError):
            McpTraceEvent.model_validate(data)

    def test_rejects_extra_fields(self) -> None:
        data = {**_valid_mcp_trace_event(), "unknown_field": "x"}
        with pytest.raises(ValidationError):
            McpTraceEvent.model_validate(data)


# --- AnomalyEntry ---


class TestAnomalyEntry:
    def test_valid_serialization(self) -> None:
        data = _valid_anomaly_entry()
        entry = AnomalyEntry.model_validate(data)
        assert entry.id == "anom-1"
        assert entry.type == "missing_headers"
        assert entry.source == "headers_analysis"
        assert entry.host == "example.com"
        assert entry.description == "Missing security headers"
        assert entry.evidence == "X-Frame-Options absent"

    def test_valid_deserialization_roundtrip(self) -> None:
        data = _valid_anomaly_entry()
        entry = AnomalyEntry.model_validate(data)
        dumped = entry.model_dump(mode="json")
        restored = AnomalyEntry.model_validate(dumped)
        assert restored.id == entry.id
        assert restored.description == entry.description

    def test_evidence_default_empty(self) -> None:
        data = _valid_anomaly_entry()
        del data["evidence"]
        entry = AnomalyEntry.model_validate(data)
        assert entry.evidence == ""

    def test_empty_id_rejected(self) -> None:
        data = _valid_anomaly_entry()
        data["id"] = ""
        with pytest.raises(ValidationError):
            AnomalyEntry.model_validate(data)

    def test_empty_description_rejected(self) -> None:
        data = _valid_anomaly_entry()
        data["description"] = ""
        with pytest.raises(ValidationError):
            AnomalyEntry.model_validate(data)

    def test_rejects_extra_fields(self) -> None:
        data = {**_valid_anomaly_entry(), "unknown_field": "x"}
        with pytest.raises(ValidationError):
            AnomalyEntry.model_validate(data)


# --- HypothesisEntry ---


class TestHypothesisEntry:
    def test_valid_serialization(self) -> None:
        data = _valid_hypothesis_entry()
        entry = HypothesisEntry.model_validate(data)
        assert entry.id == "hyp-1"
        assert entry.type == "platform_alias"
        assert entry.source == "tech_stack"
        assert "WordPress" in entry.text

    def test_valid_deserialization_roundtrip(self) -> None:
        data = _valid_hypothesis_entry()
        entry = HypothesisEntry.model_validate(data)
        dumped = entry.model_dump(mode="json")
        restored = HypothesisEntry.model_validate(dumped)
        assert restored.id == entry.id
        assert restored.text == entry.text

    def test_empty_id_rejected(self) -> None:
        data = _valid_hypothesis_entry()
        data["id"] = ""
        with pytest.raises(ValidationError):
            HypothesisEntry.model_validate(data)

    def test_empty_text_rejected(self) -> None:
        data = _valid_hypothesis_entry()
        data["text"] = ""
        with pytest.raises(ValidationError):
            HypothesisEntry.model_validate(data)

    def test_text_max_length_exceeded_rejected(self) -> None:
        data = _valid_hypothesis_entry()
        data["text"] = "x" * 5001
        with pytest.raises(ValidationError):
            HypothesisEntry.model_validate(data)

    def test_rejects_extra_fields(self) -> None:
        data = {**_valid_hypothesis_entry(), "unknown_field": "x"}
        with pytest.raises(ValidationError):
            HypothesisEntry.model_validate(data)


# --- AnomaliesStructured ---


class TestAnomaliesStructured:
    def test_valid_serialization(self) -> None:
        data = _valid_anomalies_structured()
        structured = AnomaliesStructured.model_validate(data)
        assert len(structured.anomalies) == 1
        assert len(structured.hypotheses) == 1
        assert "Missing API surface data" in structured.coverage_gaps

    def test_valid_deserialization_roundtrip(self) -> None:
        data = _valid_anomalies_structured()
        structured = AnomaliesStructured.model_validate(data)
        dumped = structured.model_dump(mode="json")
        restored = AnomaliesStructured.model_validate(dumped)
        assert len(restored.anomalies) == len(structured.anomalies)
        assert len(restored.hypotheses) == len(structured.hypotheses)

    def test_minimal_empty_defaults(self) -> None:
        data: dict = {}
        structured = AnomaliesStructured.model_validate(data)
        assert structured.anomalies == []
        assert structured.hypotheses == []
        assert structured.coverage_gaps == []

    def test_coverage_gaps_accepts_strings_and_dicts(self) -> None:
        data = {
            "coverage_gaps": [
                "Missing params inventory",
                {"type": "api_surface", "detail": "No API endpoints found"},
            ],
        }
        structured = AnomaliesStructured.model_validate(data)
        assert len(structured.coverage_gaps) == 2
        assert structured.coverage_gaps[0] == "Missing params inventory"
        assert structured.coverage_gaps[1] == {"type": "api_surface", "detail": "No API endpoints found"}

    def test_anomalies_max_length_exceeded_rejected(self) -> None:
        data = {"anomalies": [_valid_anomaly_entry() for _ in range(501)]}
        with pytest.raises(ValidationError):
            AnomaliesStructured.model_validate(data)

    def test_hypotheses_max_length_exceeded_rejected(self) -> None:
        data = {"hypotheses": [_valid_hypothesis_entry() for _ in range(201)]}
        with pytest.raises(ValidationError):
            AnomaliesStructured.model_validate(data)

    def test_coverage_gaps_max_length_exceeded_rejected(self) -> None:
        data = {"coverage_gaps": [f"gap-{i}" for i in range(201)]}
        with pytest.raises(ValidationError):
            AnomaliesStructured.model_validate(data)

    def test_rejects_extra_fields(self) -> None:
        data = {**_valid_anomalies_structured(), "unknown_field": "x"}
        with pytest.raises(ValidationError):
            AnomaliesStructured.model_validate(data)
