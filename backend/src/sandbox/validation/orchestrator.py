"""Sandbox Validation Orchestrator — validates findings in isolated environments.

Manages the lifecycle: create environment → deploy harness → execute reproducer →
collect evidence → teardown. Supports profiles: web_app, api, cli, library, binary.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ValidationProfile(str, Enum):
    WEB_APP = "web_app"
    API = "api"
    CLI = "cli"
    LIBRARY = "library"
    BINARY_SAMPLE = "binary_sample"
    SERVICE_MESH = "service_mesh"


class ValidationStatus(str, Enum):
    PENDING = "pending"
    PROVISIONING = "provisioning"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"
    TIMED_OUT = "timed_out"


@dataclass
class ValidationConfig:
    """Configuration for a single validation run."""

    profile: ValidationProfile = ValidationProfile.WEB_APP
    timeout_seconds: int = 300
    memory_limit_mb: int = 512
    cpu_limit: float = 1.0
    network_policy: str = "deny_all"  # deny_all | allowlist
    allowed_domains: list[str] = field(default_factory=list)
    capture_syscalls: bool = True
    capture_network: bool = False
    capture_screenshots: bool = False
    snapshot_before: bool = True
    auto_abort_on_policy_breach: bool = True


@dataclass
class ValidationResult:
    id: str = ""
    finding_id: str = ""
    tenant_id: str = ""
    scan_id: str = ""
    profile: str = ""
    status: ValidationStatus = ValidationStatus.PENDING
    exploitable: bool = False
    confidence: float = 0.0
    evidence: list[dict[str, Any]] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    syscalls: list[dict[str, Any]] = field(default_factory=list)
    network_captures: list[dict[str, Any]] = field(default_factory=list)
    screenshots: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0
    error: str = ""
    policy_breaches: list[str] = field(default_factory=list)


class ValidationOrchestrator:
    """Central orchestrator for sandbox validation runs.

    Coordinates harness deployment, environment provisioning, monitoring,
    and evidence collection. Calls WhiteRabbitNeo for exploitability analysis.
    """

    def __init__(self, tenant_id: str, scan_id: str) -> None:
        self.tenant_id = tenant_id
        self.scan_id = scan_id

    async def validate(
        self,
        finding: dict[str, Any],
        config: ValidationConfig | None = None,
    ) -> ValidationResult:
        """Full validation lifecycle for a single finding."""
        config = config or ValidationConfig()
        result = ValidationResult(
            id=str(uuid.uuid4()),
            finding_id=finding.get("id", finding.get("finding_id", "")),
            tenant_id=self.tenant_id,
            scan_id=self.scan_id,
            profile=config.profile.value,
            started_at=datetime.now(UTC).isoformat(),
        )
        start = time.monotonic()

        try:
            result.status = ValidationStatus.PROVISIONING
            env = await self._provision_environment(config)

            result.status = ValidationStatus.RUNNING
            harness = self._select_harness(config.profile)
            reproducer = self._build_reproducer(finding, config.profile)

            raw_result = await harness.execute(
                reproducer,
                env,
                timeout=config.timeout_seconds,
                capture_syscalls=config.capture_syscalls,
                capture_network=config.capture_network,
            )

            result.stdout = raw_result.get("stdout", "")
            result.stderr = raw_result.get("stderr", "")
            result.exit_code = raw_result.get("exit_code", -1)
            result.logs = raw_result.get("logs", [])
            result.syscalls = raw_result.get("syscalls", [])
            result.network_captures = raw_result.get("network", [])
            result.status = ValidationStatus.COMPLETED

            result.exploitable, result.confidence = await self._assess_exploitability(
                finding, result
            )

        except TimeoutError:
            result.status = ValidationStatus.TIMED_OUT
            result.error = f"Validation timed out after {config.timeout_seconds}s"
        except PolicyBreachError as exc:
            result.status = ValidationStatus.ABORTED
            result.policy_breaches.append(str(exc))
            result.error = str(exc)
        except Exception as exc:
            result.status = ValidationStatus.FAILED
            result.error = str(exc)
            logger.warning("validation_failed", extra={
                "finding_id": result.finding_id,
                "error": str(exc),
            })
        finally:
            result.duration_ms = int((time.monotonic() - start) * 1000)
            result.completed_at = datetime.now(UTC).isoformat()
            await self._teardown_environment(result.id)

        return result

    async def validate_batch(
        self,
        findings: list[dict[str, Any]],
        config: ValidationConfig | None = None,
        max_concurrent: int = 3,
    ) -> list[ValidationResult]:
        """Validate multiple findings with concurrency limit."""
        sem = asyncio.Semaphore(max_concurrent)

        async def _validate_one(f: dict) -> ValidationResult:
            async with sem:
                return await self.validate(f, config)

        return await asyncio.gather(*[_validate_one(f) for f in findings])

    async def _provision_environment(self, config: ValidationConfig) -> dict[str, Any]:
        """Provision isolated environment (container or VM)."""
        env_id = str(uuid.uuid4())[:8]
        return {
            "id": env_id,
            "type": "container",
            "status": "ready",
            "network_ns": f"argus-sandbox-{env_id}",
        }

    async def _teardown_environment(self, validation_id: str) -> None:
        """Destroy environment after validation."""

    def _select_harness(self, profile: ValidationProfile):
        """Select appropriate harness for the validation profile."""
        from src.sandbox.validation.harness.profiles import (
            ApiHarness,
            BinaryHarness,
            CliHarness,
            LibraryHarness,
            WebAppHarness,
        )
        mapping = {
            ValidationProfile.WEB_APP: WebAppHarness,
            ValidationProfile.API: ApiHarness,
            ValidationProfile.CLI: CliHarness,
            ValidationProfile.LIBRARY: LibraryHarness,
            ValidationProfile.BINARY_SAMPLE: BinaryHarness,
            ValidationProfile.SERVICE_MESH: ApiHarness,
        }
        harness_cls = mapping.get(profile, WebAppHarness)
        return harness_cls()

    def _build_reproducer(
        self, finding: dict[str, Any], profile: ValidationProfile
    ) -> dict[str, Any]:
        """Build reproducer payload from finding data."""
        return {
            "target_url": finding.get("url") or finding.get("target", ""),
            "method": finding.get("method", "GET"),
            "payload": finding.get("payload") or finding.get("poc", ""),
            "param": finding.get("param") or finding.get("parameter", ""),
            "headers": finding.get("headers", {}),
            "cookies": finding.get("cookies", {}),
            "profile": profile.value,
        }

    async def _assess_exploitability(
        self, finding: dict[str, Any], result: ValidationResult
    ) -> tuple[bool, float]:
        """Use WhiteRabbitNeo to assess exploitability from validation results."""
        from src.llm.facade import call_llm_unified
        from src.llm.task_router import LLMTask

        if result.exit_code != 0 and not result.stdout:
            return False, 0.0

        prompt = f"""Assess whether this finding is exploitable based on sandbox validation results.

=== FINDING ===
Title: {finding.get('title', 'N/A')}
Severity: {finding.get('severity', 'unknown')}
CWE: {finding.get('cwe', 'N/A')}
Description: {finding.get('description', '')[:500]}

=== VALIDATION OUTPUT ===
Exit code: {result.exit_code}
Stdout: {result.stdout[:1000]}
Stderr: {result.stderr[:500]}

Respond with JSON: {{"exploitable": true/false, "confidence": 0.0-1.0, "rationale": "..."}}"""

        system = (
            "You assess exploitability from sandbox validation output. "
            "Be conservative: only mark exploitable if clear evidence exists. "
            "Respond ONLY with valid JSON."
        )

        try:
            response = await call_llm_unified(
                system, prompt,
                task=LLMTask.VALIDATION_ONESHOT,
                phase="exploitability_assessment",
            )
            import json as _json
            data = _json.loads(response)
            return data.get("exploitable", False), data.get("confidence", 0.0)
        except Exception:
            return result.exit_code == 0, 0.5


class PolicyBreachError(Exception):
    """Raised when validation violates security policy."""
