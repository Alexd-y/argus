"""Tests for recon Pydantic schemas — enums, scope, findings, API schemas."""

import pytest
from pydantic import ValidationError

from src.recon.schemas.base import (
    ArtifactType,
    EngagementStatus,
    FindingType,
    HypothesisPriority,
    JobStatus,
    ReconStage,
    TargetType,
)
from src.recon.schemas.scope import ScopeConfig, ScopeRule, ScopeValidationResult
from src.recon.schemas.findings import (
    ApiEndpointFinding,
    DnsRecordFinding,
    IpAddressFinding,
    JsFinding,
    ParameterFinding,
    SecretCandidate,
    ServiceFinding,
    SubdomainFinding,
    TechnologyFinding,
    TlsInfoFinding,
    UrlFinding,
)
from src.recon.schemas.engagement import EngagementCreate, EngagementResponse
from src.recon.schemas.target import ReconTargetCreate
from src.recon.schemas.job import ScanJobCreate
from src.recon.schemas.hypothesis import HypothesisCreate


class TestEnums:
    """Test all enum values are correct."""

    def test_recon_stage_values(self):
        assert ReconStage.SCOPE_PREP == 0
        assert ReconStage.REPORTING == 18
        assert len(ReconStage) == 19

    def test_finding_type_values(self):
        assert FindingType.SUBDOMAIN == "subdomain"
        assert FindingType.API_ENDPOINT == "api_endpoint"
        assert len(FindingType) >= 11

    def test_job_status_values(self):
        statuses = [s.value for s in JobStatus]
        assert "pending" in statuses
        assert "completed" in statuses
        assert "failed" in statuses

    def test_engagement_status_values(self):
        assert EngagementStatus.DRAFT == "draft"
        assert EngagementStatus.ACTIVE == "active"

    def test_artifact_type_values(self):
        assert ArtifactType.RAW == "raw"
        assert ArtifactType.REPORT == "report"


class TestScopeSchemas:
    """Test scope configuration schemas."""

    def test_scope_rule_valid(self):
        rule = ScopeRule(rule_type="include", value_type="domain", pattern="example.com")
        assert rule.pattern == "example.com"

    def test_scope_rule_invalid_type(self):
        with pytest.raises(ValidationError):
            ScopeRule(rule_type="invalid", value_type="domain", pattern="x")

    def test_scope_rule_empty_pattern(self):
        with pytest.raises(ValidationError):
            ScopeRule(rule_type="include", value_type="domain", pattern="  ")

    def test_scope_config_valid(self):
        config = ScopeConfig(
            rules=[ScopeRule(rule_type="include", value_type="domain", pattern="example.com")],
            wildcard_subdomains=True,
        )
        assert len(config.rules) == 1

    def test_scope_config_no_include_rules_fails(self):
        with pytest.raises(ValidationError):
            ScopeConfig(
                rules=[ScopeRule(rule_type="exclude", value_type="domain", pattern="test.com")]
            )

    def test_scope_config_empty_rules_ok(self):
        config = ScopeConfig(rules=[])
        assert len(config.rules) == 0


class TestFindingSchemas:
    """Test canonical finding data shapes."""

    def test_subdomain_finding(self):
        f = SubdomainFinding(subdomain="api.example.com", source="subfinder")
        assert f.subdomain == "api.example.com"
        assert f.is_wildcard is False

    def test_dns_record_finding(self):
        f = DnsRecordFinding(hostname="example.com", record_type="A", value="1.2.3.4")
        assert f.record_type == "A"

    def test_ip_finding(self):
        f = IpAddressFinding(ip="1.2.3.4", is_cdn=True, cdn_name="Cloudflare")
        assert f.is_cdn is True

    def test_service_finding(self):
        f = ServiceFinding(ip="1.2.3.4", port=443, service_name="https")
        assert f.port == 443

    def test_url_finding(self):
        f = UrlFinding(url="https://example.com/api", status_code=200)
        assert f.method == "GET"

    def test_technology_finding(self):
        f = TechnologyFinding(name="React", version="18.0", confidence=0.9)
        assert f.confidence == 0.9

    def test_parameter_finding(self):
        f = ParameterFinding(url="https://x.com/s", param_name="q", is_sensitive=False)
        assert f.param_type == "query"

    def test_tls_finding(self):
        f = TlsInfoFinding(hostname="example.com", protocol_version="TLSv1.3")
        assert f.port == 443

    def test_js_finding(self):
        f = JsFinding(url="https://x.com/app.js", finding_type="api_endpoint", value="/api/v1")
        assert f.finding_type == "api_endpoint"

    def test_secret_candidate(self):
        f = SecretCandidate(secret_type="api_key", value_masked="sk_***")
        assert f.confidence == 0.5

    def test_api_endpoint(self):
        f = ApiEndpointFinding(base_url="https://api.x.com", path="/users", method="POST")
        assert f.auth_required is None


class TestApiSchemas:
    """Test API request/response schemas."""

    def test_engagement_create_minimal(self):
        e = EngagementCreate(name="Test Engagement")
        assert e.name == "Test Engagement"

    def test_engagement_create_empty_name_fails(self):
        with pytest.raises(ValidationError):
            EngagementCreate(name="")

    def test_target_create(self):
        t = ReconTargetCreate(domain="example.com")
        assert t.target_type == TargetType.DOMAIN

    def test_scan_job_create(self):
        j = ScanJobCreate(target_id="abc-123", stage=2, tool_name="subfinder")
        assert j.stage == 2

    def test_scan_job_stage_range(self):
        with pytest.raises(ValidationError):
            ScanJobCreate(target_id="x", stage=99, tool_name="x")

    def test_hypothesis_create(self):
        h = HypothesisCreate(title="Exposed API", category="misconfig")
        assert h.priority == HypothesisPriority.MEDIUM
