"""Shared fixtures for the :mod:`src.orchestrator` runtime test suite (ARG-008).

The fixtures here build a fully signed mini prompt catalog under
``tmp_path`` and an :class:`EchoLLMProvider` pre-loaded with canned
responses so every agent can run end-to-end without touching disk or
the network. The catalog uses the same Ed25519 plumbing as the real
:class:`PromptRegistry` so signature failures (tamper / wrong key) are
exercised exactly the same way they would be in production.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.orchestrator.agents import AgentContext
from src.orchestrator.cost_tracker import CostTracker
from src.orchestrator.llm_provider import EchoLLMProvider
from src.orchestrator.prompt_registry import PromptRegistry
from src.pipeline.contracts.finding_dto import FindingDTO
from src.pipeline.contracts.phase_io import ScanPhase
from src.policy.audit import AuditLogger, InMemoryAuditSink
from src.sandbox.signing import (
    SignatureRecord,
    SignaturesFile,
    public_key_id,
    sign_blob,
)

# ---------------------------------------------------------------------------
# Cryptography fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    """Return a freshly generated Ed25519 keypair plus its canonical key id."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key, public_key_id(public_key)


@pytest.fixture()
def keys_dir(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> Path:
    """Materialise the keypair under a fresh ``_keys`` directory."""
    _, public_key, kid = ed25519_keypair
    keys = tmp_path / "_keys"
    keys.mkdir()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    (keys / f"{kid}.ed25519.pub").write_bytes(pub_bytes)
    return keys


# ---------------------------------------------------------------------------
# Prompt fixtures
# ---------------------------------------------------------------------------


def _sample_prompt(
    prompt_id: str,
    agent_role: str,
    *,
    user_template: str | None = None,
    description: str | None = None,
    expected_schema_ref: str | None = None,
) -> dict[str, object]:
    """Return a minimal valid :class:`PromptDefinition` YAML payload."""
    return {
        "prompt_id": prompt_id,
        "version": "1.0.0",
        "agent_role": agent_role,
        "description": description or f"Test prompt for {agent_role!s} agent.",
        "system_prompt": (
            f"You are the {agent_role} agent in the ARGUS test fixture. "
            "Emit only JSON. No commentary."
        ),
        "user_prompt_template": user_template or "Inputs: {payload}",
        "expected_schema_ref": expected_schema_ref,
        "default_model_id": "test-echo-1",
        "default_max_tokens": 1024,
        "default_temperature": 0.0,
    }


@pytest.fixture()
def sample_prompt() -> Callable[..., dict[str, object]]:
    """Factory returning a fresh prompt YAML payload per call."""
    return _sample_prompt


def _write_signed_prompts(
    prompts_dir: Path,
    keys_dir_path: Path,
    keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    prompts: list[dict[str, object]],
) -> Path:
    """Write ``prompts`` to ``prompts_dir`` and emit a SIGNATURES manifest."""
    private_key, public_key, kid = keypair
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if not (keys_dir_path / f"{kid}.ed25519.pub").exists():
        (keys_dir_path / f"{kid}.ed25519.pub").write_bytes(pub_bytes)

    signatures = SignaturesFile()
    for payload in prompts:
        relative = f"{payload['prompt_id']}.yaml"
        yaml_path = prompts_dir / relative
        yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")
        yaml_path.write_bytes(yaml_bytes)
        signatures.upsert(
            SignatureRecord(
                sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
                relative_path=relative,
                signature_b64=sign_blob(private_key, yaml_bytes),
                public_key_id=kid,
            )
        )

    signatures_path = prompts_dir / "SIGNATURES"
    signatures.write(signatures_path)
    return signatures_path


@pytest.fixture()
def signed_prompts_dir(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> tuple[Path, Path, Path, str]:
    """Return ``(prompts_dir, keys_dir, signatures_path, key_id)``.

    Catalog: minimal planner + critic prompts. Tests can rebuild for
    larger cases via :func:`_write_signed_prompts`.
    """
    _, _, kid = ed25519_keypair
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    keys = tmp_path / "_keys"
    keys.mkdir()
    prompts = [
        _sample_prompt("planner_demo", "planner"),
        _sample_prompt("critic_demo", "critic"),
    ]
    sig_path = _write_signed_prompts(prompts_dir, keys, ed25519_keypair, prompts)
    return prompts_dir, keys, sig_path, kid


@pytest.fixture()
def full_signed_registry(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> tuple[PromptRegistry, Path, Path]:
    """Return a loaded :class:`PromptRegistry` with all 5 agent roles."""
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    keys = tmp_path / "_keys"
    keys.mkdir()
    prompts = [
        _sample_prompt(
            "planner_v1",
            "planner",
            user_template=(
                "Target: {target_summary}\nPhase: {phase}\n"
                "Previous: {previous_findings}"
            ),
            expected_schema_ref="validation_plan_v1",
        ),
        _sample_prompt(
            "critic_v1",
            "critic",
            user_template="Plan: {plan}\nPolicy: {tenant_policy}",
            expected_schema_ref="critic_verdict_v1",
        ),
        _sample_prompt(
            "verifier_v1",
            "verifier",
            user_template=(
                "Phase: {phase}\nTool output: {tool_output}\nOAST: {oast_evidence}"
            ),
            expected_schema_ref="finding_dto_list_v1",
        ),
        _sample_prompt(
            "reporter_v1",
            "reporter",
            user_template="Findings: {findings}",
            expected_schema_ref="report_narrative_v1",
        ),
        _sample_prompt(
            "fixer_v1",
            "fixer",
            user_template=(
                "Schema: {schema_ref}\nErrors: {schema_errors}\n"
                "Original: {original_content}"
            ),
        ),
    ]
    sig_path = _write_signed_prompts(prompts_dir, keys, ed25519_keypair, prompts)
    registry = PromptRegistry(
        prompts_dir=prompts_dir,
        signatures_path=sig_path,
        public_keys_dir=keys,
    )
    registry.load()
    return registry, prompts_dir, keys


# ---------------------------------------------------------------------------
# Echo provider canned responses
# ---------------------------------------------------------------------------


def _canned_validation_plan() -> dict[str, Any]:
    """Return a minimally valid :class:`ValidationPlanV1` payload."""
    return {
        "hypothesis": "Boolean-blind SQLi suspected on /search?q parameter",
        "risk": "high",
        "payload_strategy": {
            "registry_family": "sqli.boolean.diff.v3",
            "mutation_classes": ["canonicalization", "case_normalization"],
            "raw_payloads_allowed": False,
        },
        "validator": {
            "tool": "safe_validator",
            "inputs": {"endpoint": "/search", "param": "q"},
            "success_signals": ["response_diff > threshold"],
            "stop_conditions": ["http_500", "rate_limited"],
        },
        "approval_required": True,
        "evidence_to_collect": ["raw_output", "diff"],
        "remediation_focus": ["use parameterized queries"],
    }


def _canned_critic_verdict(approved: bool = True) -> dict[str, Any]:
    return {
        "approved": approved,
        "reasons": [] if approved else ["registry_family banned by tenant policy"],
        "suggested_modifications": None,
    }


def _canned_finding(scan_id: UUID, tenant_id: UUID) -> dict[str, Any]:
    return {
        "id": str(uuid4()),
        "tenant_id": str(tenant_id),
        "scan_id": str(scan_id),
        "asset_id": str(uuid4()),
        "tool_run_id": str(uuid4()),
        "category": "sqli",
        "cwe": [89],
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_v3_score": 9.8,
        "ssvc_decision": "Act",
        "owasp_wstg": ["WSTG-INPV-05"],
        "mitre_attack": ["T1190"],
        "confidence": "confirmed",
        "status": "new",
        "evidence_ids": [],
        "first_seen": "2026-04-17T12:00:00+00:00",
        "last_seen": "2026-04-17T12:05:00+00:00",
    }


def _canned_findings_payload(
    scan_id: UUID, tenant_id: UUID, count: int = 1
) -> dict[str, Any]:
    return {
        "findings": [_canned_finding(scan_id, tenant_id) for _ in range(count)],
    }


def _canned_report_narrative() -> dict[str, Any]:
    return {
        "executive_summary": "One critical SQLi finding observed on /search.",
        "technical_summary": "SQLi confirmed via boolean-blind probe; CVSS 9.8.",
        "recommendations": [
            "Switch /search to parameterised queries.",
            "Enable WAF SQLi rule set in blocking mode.",
        ],
    }


@pytest.fixture()
def canned_validation_plan() -> Callable[[], dict[str, Any]]:
    """Factory for fresh ValidationPlanV1 payloads (so tests can mutate copies)."""
    return _canned_validation_plan


@pytest.fixture()
def canned_critic_verdict() -> Callable[..., dict[str, Any]]:
    return _canned_critic_verdict


@pytest.fixture()
def canned_findings_payload() -> Callable[..., dict[str, Any]]:
    return _canned_findings_payload


@pytest.fixture()
def canned_report_narrative() -> Callable[[], dict[str, Any]]:
    return _canned_report_narrative


@pytest.fixture()
def echo_provider_factory() -> Callable[..., EchoLLMProvider]:
    """Return a factory building an :class:`EchoLLMProvider` with canned data."""

    def _build(
        responses: dict[str, dict[str, Any] | str] | None = None,
    ) -> EchoLLMProvider:
        provider = EchoLLMProvider()
        for prompt_id, payload in (responses or {}).items():
            provider.register_canned(prompt_id, payload)
        return provider

    return _build


# ---------------------------------------------------------------------------
# Domain fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def agent_context() -> AgentContext:
    return AgentContext(
        tenant_id=uuid4(),
        scan_id=uuid4(),
        phase=ScanPhase.VULN_ANALYSIS,
        correlation_id=uuid4(),
        previous_findings=[],
        target_summary={"asset": "https://example.test"},
    )


@pytest.fixture()
def cost_tracker() -> CostTracker:
    return CostTracker()


@pytest.fixture()
def audit_logger() -> AuditLogger:
    return AuditLogger(InMemoryAuditSink())


@pytest.fixture()
def now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers re-exported for test modules
# ---------------------------------------------------------------------------


def write_signed_prompts(
    prompts_dir: Path,
    keys_dir_path: Path,
    keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    prompts: list[dict[str, object]],
) -> Path:
    """Public re-export so test modules can craft custom catalogs."""
    return _write_signed_prompts(prompts_dir, keys_dir_path, keypair, prompts)


def canned_finding(scan_id: UUID, tenant_id: UUID) -> dict[str, Any]:
    """Public re-export of the FindingDTO canned payload."""
    return _canned_finding(scan_id, tenant_id)


def make_finding_dto(scan_id: UUID, tenant_id: UUID) -> FindingDTO:
    """Build a typed :class:`FindingDTO` for tests that require Pydantic input."""
    return FindingDTO.model_validate(_canned_finding(scan_id, tenant_id))


def canned_finding_response_json(scan_id: UUID, tenant_id: UUID, count: int = 1) -> str:
    """Return the JSON string the EchoLLMProvider should emit for the verifier."""
    return json.dumps(_canned_findings_payload(scan_id, tenant_id, count))
