"""Integration tests for Shannon-inspired pipeline contracts.

Tests the round-trip: VulnAnalysisOutput → ExploitationQueue → ExploitationInput
and the full pipeline phase handoff with structured data.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from src.orchestration.auth_config import (
    AuthConfig,
    AuthCredentials,
    LoginFlowStep,
    LoginType,
    RulesOfEngagement,
    ScopeRuleConfig,
    SuccessCondition,
    SuccessConditionType,
    TargetConfig,
)
from src.orchestration.evidence_tier import EvidenceTier, classify_finding
from src.orchestration.exploitation_queue import (
    ExploitHypothesis,
    ExploitationQueue,
    VulnClass,
    CATEGORY_TO_VULN_CLASS,
)
from src.orchestration.phases import (
    ExploitationInput,
    ExploitationOutput,
    VulnAnalysisOutput,
    ReportingInput,
)
from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)


class TestPipelineRoundTrip:
    """VulnAnalysisOutput → ExploitationQueue → ExploitationInput"""

    def test_structured_handoff(self) -> None:
        vuln_output = VulnAnalysisOutput(
            findings=[
                {
                    "category": "sqli",
                    "url": "/api/users?id=1",
                    "parameter": "id",
                    "confidence": 0.85,
                    "payload": "' OR 1=1 --",
                },
                {
                    "category": "xss",
                    "url": "/search?q=test",
                    "parameter": "q",
                    "confidence": 0.6,
                },
            ],
        )

        queue = ExploitationQueue.from_vuln_analysis_output(
            target="https://example.com",
            findings=vuln_output.findings,
            scan_id="test-scan-001",
            vuln_classes=[VulnClass.INJECTION, VulnClass.XSS],
        )

        assert len(queue.hypotheses) == 2

        sqli_h = [h for h in queue.hypotheses if h.vuln_type == FindingCategory.SQLI][0]
        xss_h = [h for h in queue.hypotheses if h.vuln_type == FindingCategory.XSS][0]

        assert sqli_h.vuln_class == VulnClass.INJECTION
        assert xss_h.vuln_class == VulnClass.XSS
        assert sqli_h.confidence == 0.85

        vuln_output_with_queues = VulnAnalysisOutput(
            findings=vuln_output.findings,
            exploitation_queues={
                "injection": ExploitationQueue(
                    target="https://example.com",
                    hypotheses=[sqli_h],
                    vuln_classes=[VulnClass.INJECTION],
                ),
                "xss": ExploitationQueue(
                    target="https://example.com",
                    hypotheses=[xss_h],
                    vuln_classes=[VulnClass.XSS],
                ),
            },
        )

        assert vuln_output_with_queues.exploitation_queues is not None
        assert "injection" in vuln_output_with_queues.exploitation_queues
        assert "xss" in vuln_output_with_queues.exploitation_queues

        combined_queue = ExploitationQueue(
            target="https://example.com",
            hypotheses=[sqli_h, xss_h],
        )
        expl_input = ExploitationInput(
            findings=vuln_output.findings,
            exploitation_queue=combined_queue,
        )

        assert expl_input.exploitation_queue is not None
        assert len(expl_input.exploitation_queue.hypotheses) == 2

    def test_backward_compat_without_queue(self) -> None:
        vuln_output = VulnAnalysisOutput(
            findings=[{"category": "sqli", "url": "/test"}]
        )

        assert vuln_output.exploitation_queues is None

        expl_input = ExploitationInput(findings=vuln_output.findings)
        assert expl_input.exploitation_queue is None
        assert len(expl_input.findings) == 1

    def test_exploitation_output_with_evidence_tiers(self) -> None:
        finding_id = uuid4().hex[:16]
        output = ExploitationOutput(
            exploits=[{"id": finding_id, "type": "sqli", "payload": "' OR 1=1 --"}],
            evidence=[{"finding_id": finding_id, "type": "screenshot"}],
            evidence_tiers={finding_id: EvidenceTier.EXPLOITED},
        )

        assert finding_id in output.evidence_tiers
        assert output.evidence_tiers[finding_id] == EvidenceTier.EXPLOITED

    def test_reporting_input_with_scope_config(self) -> None:
        ri = ReportingInput(
            target="https://example.com",
            scope_config={
                "description": "Test app",
                "rules": {
                    "focus": [{"description": "API", "type": "url_path", "value": "/api"}],
                    "avoid": [],
                },
            },
        )
        assert ri.scope_config is not None
        assert ri.scope_config["description"] == "Test app"

    def test_queue_filtering_by_confidence(self) -> None:
        queue = ExploitationQueue(
            target="https://example.com",
            hypotheses=[
                ExploitHypothesis(
                    vuln_type=FindingCategory.SQLI,
                    location="/api/users",
                    confidence=0.9,
                    suggested_payload="' OR 1=1 --",
                ),
                ExploitHypothesis(
                    vuln_type=FindingCategory.XSS,
                    location="/search",
                    confidence=0.3,
                    suggested_payload="<script>alert(1)</script>",
                ),
            ],
        )

        high_conf = queue.filter_by_confidence(0.5)
        assert len(high_conf.hypotheses) == 1
        assert high_conf.hypotheses[0].vuln_type == FindingCategory.SQLI

    def test_queue_filtering_by_evidence_tier(self) -> None:
        queue = ExploitationQueue(
            target="https://example.com",
            hypotheses=[
                ExploitHypothesis(
                    vuln_type=FindingCategory.SQLI,
                    location="/api/users",
                    confidence=0.9,
                    evidence_tier=EvidenceTier.EXPLOITED,
                ),
                ExploitHypothesis(
                    vuln_type=FindingCategory.XSS,
                    location="/search",
                    confidence=0.5,
                    evidence_tier=EvidenceTier.SUSPECTED,
                ),
            ],
        )

        confirmed_or_above = queue.filter_by_evidence_tier(EvidenceTier.CONFIRMED)
        assert len(confirmed_or_above.hypotheses) == 1
        assert confirmed_or_above.hypotheses[0].vuln_type == FindingCategory.SQLI


class TestAuthConfigIntegration:
    """AuthConfig YAML loading + placeholder resolution."""

    _YAML_CONFIG = """\
description: Test application
authentication:
  login_type: form
  login_url: https://app.example.com/login
  credentials:
    username: test@example.com
    password: s3cret
    totp_secret: null
  login_flow:
    - instruction: Type $username into the email field
    - instruction: Type $password into the password field
    - instruction: Click Sign In
  success_condition:
    type: url_contains
    value: /dashboard
rules:
  focus:
    - description: API endpoints
      type: url_path
      value: /api
  avoid:
    - description: Logout endpoint
      type: url_path
      value: /logout
  max_rps: 5
vuln_classes:
  - injection
  - xss
exploit: true
"""

    def test_yaml_round_trip(self) -> None:
        config = TargetConfig.from_yaml(self._YAML_CONFIG)
        assert config.description == "Test application"
        assert config.authentication is not None
        assert config.authentication.login_type == LoginType.FORM
        assert config.authentication.login_url == "https://app.example.com/login"
        assert config.authentication.credentials.username == "test@example.com"
        assert len(config.authentication.login_flow) == 3
        assert config.authentication.success_condition is not None
        assert config.authentication.success_condition.type == SuccessConditionType.URL_CONTAINS
        assert config.rules.focus[0].type == "url_path"
        assert config.vuln_classes == ["injection", "xss"]
        assert config.exploit is True

    def test_placeholder_resolution(self) -> None:
        config = TargetConfig.from_yaml(self._YAML_CONFIG)
        resolved = config.resolve_placeholders()
        assert resolved.authentication is not None
        step0 = resolved.authentication.login_flow[0].instruction
        assert "test@example.com" in step0
        step1 = resolved.authentication.login_flow[1].instruction
        assert "s3cret" in step1

    def test_no_auth_config(self) -> None:
        config = TargetConfig(description="No-auth target")
        assert config.authentication is None
        assert config.exploit is True
        assert config.vuln_classes == []

    def test_scope_rules_in_pipeline(self) -> None:
        config = TargetConfig.from_yaml(self._YAML_CONFIG)
        scope_rules = config.rules
        assert len(scope_rules.focus) == 1
        assert len(scope_rules.avoid) == 1
        assert scope_rules.max_rps == 5


class TestEvidenceTierInPipeline:
    """EvidenceTier classification integrates with finding pipeline."""

    def test_classify_findings_for_report(self) -> None:
        findings_data = [
            {"confidence": "exploitable", "has_payload": True},
            {"confidence": "exploitable", "has_payload": False},
            {"confidence": "confirmed", "has_payload": False},
            {"confidence": "likely", "has_evidence": True},
            {"confidence": "likely", "has_evidence": False},
            {"confidence": "suspected", "has_evidence": False},
        ]

        expected_tiers = [
            EvidenceTier.EXPLOITED,
            EvidenceTier.CONFIRMED,
            EvidenceTier.CONFIRMED,
            EvidenceTier.SUSPECTED,
            EvidenceTier.INFORMATIONAL,
            EvidenceTier.INFORMATIONAL,
        ]

        for fd, expected in zip(findings_data, expected_tiers):
            confidence = ConfidenceLevel(fd["confidence"])
            tier = classify_finding(
                confidence,
                has_payload=fd.get("has_payload", False),
                has_evidence=fd.get("has_evidence", False),
            )
            assert tier == expected, f"Expected {expected} for {fd}, got {tier}"

    def test_evidence_tier_in_exploitation_output(self) -> None:
        fid1, fid2 = uuid4().hex[:16], uuid4().hex[:16]
        output = ExploitationOutput(
            exploits=[],
            evidence=[],
            evidence_tiers={
                fid1: EvidenceTier.EXPLOITED,
                fid2: EvidenceTier.INFORMATIONAL,
            },
        )

        assert output.evidence_tiers[fid1] == EvidenceTier.EXPLOITED
        assert output.evidence_tiers[fid2] == EvidenceTier.INFORMATIONAL

    def test_vuln_class_mapping_completeness(self) -> None:
        for vc in VulnClass:
            assert vc in [VulnClass.INJECTION, VulnClass.XSS, VulnClass.AUTH, VulnClass.AUTHZ, VulnClass.SSRF]

        for cat in [FindingCategory.SQLI, FindingCategory.CMDI, FindingCategory.XSS, FindingCategory.SSRF]:
            assert cat in CATEGORY_TO_VULN_CLASS, f"{cat} not in CATEGORY_TO_VULN_CLASS"