"""Tests for Sandbox Validation Orchestrator."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from src.sandbox.validation.orchestrator import (
    ValidationOrchestrator,
    ValidationConfig,
    ValidationProfile,
    ValidationStatus,
    ValidationResult,
    PolicyBreachError,
)


class TestValidationConfig:
    def test_default_config(self):
        c = ValidationConfig()
        assert c.profile == ValidationProfile.WEB_APP
        assert c.timeout_seconds == 300
        assert c.capture_syscalls is True
        assert c.auto_abort_on_policy_breach is True

    def test_custom_config(self):
        c = ValidationConfig(
            profile=ValidationProfile.BINARY_SAMPLE,
            timeout_seconds=600,
            network_policy="allowlist",
            allowed_domains=["api.example.com"],
        )
        assert c.profile == ValidationProfile.BINARY_SAMPLE
        assert c.timeout_seconds == 600
        assert c.network_policy == "allowlist"
        assert "api.example.com" in c.allowed_domains


class TestValidationResult:
    def test_default_result(self):
        r = ValidationResult()
        assert r.status == ValidationStatus.PENDING
        assert r.exploitable is False
        assert r.confidence == 0.0


class TestOrchestratorInit:
    def test_creates_with_ids(self):
        orch = ValidationOrchestrator("tnt_1", "scan_1")
        assert orch.tenant_id == "tnt_1"
        assert orch.scan_id == "scan_1"


class TestHarnessSelection:
    def test_selects_webapp_harness(self):
        orch = ValidationOrchestrator("t", "s")
        harness = orch._select_harness(ValidationProfile.WEB_APP)
        from src.sandbox.validation.harness.profiles import WebAppHarness
        assert isinstance(harness, WebAppHarness)

    def test_selects_api_harness(self):
        orch = ValidationOrchestrator("t", "s")
        harness = orch._select_harness(ValidationProfile.API)
        from src.sandbox.validation.harness.profiles import ApiHarness
        assert isinstance(harness, ApiHarness)

    def test_selects_cli_harness(self):
        orch = ValidationOrchestrator("t", "s")
        harness = orch._select_harness(ValidationProfile.CLI)
        from src.sandbox.validation.harness.profiles import CliHarness
        assert isinstance(harness, CliHarness)

    def test_selects_binary_harness(self):
        orch = ValidationOrchestrator("t", "s")
        harness = orch._select_harness(ValidationProfile.BINARY_SAMPLE)
        from src.sandbox.validation.harness.profiles import BinaryHarness
        assert isinstance(harness, BinaryHarness)


class TestPolicyBreachError:
    def test_str_representation(self):
        err = PolicyBreachError("network access denied")
        assert str(err) == "network access denied"
        assert isinstance(err, Exception)
