"""Deterministic LLM-intent compiler (R8).

The LLM never runs commands. It returns a *typed intent* (schema below), and
this deterministic compiler validates it against schema / scope / profile /
lease / approvals / budget, resolves the tool and payload family against the
signed registries (allow-lists supplied by the caller), and builds a safe
``argv`` (no ``shell=True``, no raw command strings, no raw payloads).

Anything the LLM says that is not an allow-listed capability/tool/payload id is
rejected — so instructions injected into untrusted tool output can never turn
into actions (R6/R8.6). ``abstain_reason`` is always honored.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from src.core.structured_events import (
    EVENT_LLM_PLAN_ABSTAINED,
    EVENT_LLM_PLAN_APPROVED,
    EVENT_LLM_PLAN_REJECTED,
    emit_event,
)
from src.llm_orchestrator.schemas.loader import MutationClass
from src.pipeline.contracts.finding_dto import FindingCategory
from src.profiles.resolver import ResolvedScanProfile

logger = logging.getLogger(__name__)

# Keys that would smuggle a raw command / payload past the registry.
_FORBIDDEN_ARG_KEYS: frozenset[str] = frozenset(
    {
        "argv",
        "command",
        "cmd",
        "cmdline",
        "shell",
        "command_string",
        "command_template",
        "raw_payload",
        "raw_payloads",
        "payload",
        "payloads",
        "script",
        "exec",
        "eval",
    }
)

# Shell metacharacters that must never appear in a typed argument value.
_SHELL_METACHAR = re.compile(r"[;&|`$><\n\r()\\{}]|\$\(|&&|\|\|")

_VALID_MUTATION_CLASSES: frozenset[str] = frozenset(m.value for m in MutationClass)
_VALID_FINDING_CATEGORIES: frozenset[str] = frozenset(c.value for c in FindingCategory)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class LLMScanIntent(BaseModel):
    """The typed intent an LLM is allowed to emit (Design §9 / task §8)."""

    model_config = ConfigDict(extra="forbid")

    phase: str = Field(min_length=1, max_length=64)
    scope_refs: list[str] = Field(default_factory=list)
    finding_refs: list[str] = Field(default_factory=list)
    hypothesis: str = Field(default="", max_length=2000)
    capability_id: str | None = Field(default=None, max_length=128)
    tool_id: str | None = Field(default=None, max_length=128)
    typed_args: dict[str, Any] = Field(default_factory=dict)
    payload_family_id: str | None = Field(default=None, max_length=128)
    mutation_classes: list[str] = Field(default_factory=list)
    oracle: str | None = Field(default=None, max_length=128)
    evidence_contract: list[str] = Field(default_factory=list)
    stop_conditions: dict[str, Any] = Field(default_factory=dict)
    approval_required: bool = False
    abstain_reason: str | None = Field(default=None, max_length=500)


@dataclass(frozen=True, slots=True)
class CompilerContext:
    """Deterministic allow-lists + policy state for a single compile decision."""

    resolved_profile: ResolvedScanProfile
    allowed_scope_refs: frozenset[str] = field(default_factory=frozenset)
    allowed_tool_ids: frozenset[str] = field(default_factory=frozenset)
    allowed_payload_family_ids: frozenset[str] = field(default_factory=frozenset)
    lab_lease_active: bool = False
    granted_approvals: frozenset[str] = field(default_factory=frozenset)
    budget_remaining: bool = True
    scan_id: str | None = None
    tenant_id: str | None = None


@dataclass(frozen=True, slots=True)
class CompiledToolJob:
    """Safe, deterministic tool job produced from a validated intent."""

    tool_id: str
    capability_id: str | None
    argv: list[str]
    payload_family_id: str | None
    mutation_classes: list[str]
    approval_required: bool
    evidence_contract: list[str]
    stop_conditions: dict[str, Any]
    phase: str


@dataclass(frozen=True, slots=True)
class AbstainResult:
    """Returned when the LLM chose to abstain (allowed, not an error)."""

    reason: str


class IntentCompileError(Exception):
    """Machine-readable compile failure. ``code`` maps to the error contract."""

    def __init__(self, message: str, *, code: str) -> None:
        self.code = code
        super().__init__(message)


def _reject(code: str, message: str, ctx: CompilerContext) -> IntentCompileError:
    emit_event(
        EVENT_LLM_PLAN_REJECTED,
        tenant_id=ctx.tenant_id,
        scan_id=ctx.scan_id,
        scan_profile=ctx.resolved_profile.external_profile.value,
        reason_code=code,
        level=logging.WARNING,
    )
    return IntentCompileError(message, code=code)


def _parse_intent(raw: dict[str, Any] | LLMScanIntent) -> LLMScanIntent:
    if isinstance(raw, LLMScanIntent):
        return raw
    try:
        return LLMScanIntent.model_validate(raw)
    except ValidationError as exc:
        raise IntentCompileError(
            f"LLM intent failed schema validation: {exc.error_count()} error(s)",
            code="schema_invalid",
        ) from exc


def _build_argv(tool_id: str, typed_args: dict[str, Any]) -> list[str]:
    """Deterministically build argv (sorted keys) — never a shell string."""
    argv: list[str] = [tool_id]
    for key in sorted(typed_args):
        value = typed_args[key]
        flag = f"--{key.replace('_', '-')}"
        if isinstance(value, bool):
            if value:
                argv.append(flag)
            continue
        argv.extend([flag, str(value)])
    return argv


def compile_intent(
    raw: dict[str, Any] | LLMScanIntent, ctx: CompilerContext
) -> CompiledToolJob | AbstainResult:
    """Validate + compile an LLM intent into a safe tool job (or abstain)."""
    intent = _parse_intent(raw)  # raises schema_invalid

    # Abstain is always allowed.
    if intent.abstain_reason:
        emit_event(
            EVENT_LLM_PLAN_ABSTAINED,
            tenant_id=ctx.tenant_id,
            scan_id=ctx.scan_id,
            scan_profile=ctx.resolved_profile.external_profile.value,
            reason_code="abstain",
        )
        return AbstainResult(reason=intent.abstain_reason)

    # A concrete action requires a tool.
    if not intent.tool_id:
        raise _reject("schema_invalid", "intent has neither tool_id nor abstain_reason", ctx)

    # Reject raw command / raw payload smuggling.
    for key in intent.typed_args:
        if key.lower() in _FORBIDDEN_ARG_KEYS:
            raise _reject(
                "raw_command_rejected",
                f"typed_args contains forbidden key {key!r}",
                ctx,
            )
    for key, value in intent.typed_args.items():
        if isinstance(value, str) and _SHELL_METACHAR.search(value):
            raise _reject(
                "raw_command_rejected",
                f"typed_args[{key!r}] contains shell metacharacters",
                ctx,
            )

    # Scope containment.
    for ref in intent.scope_refs:
        if ref not in ctx.allowed_scope_refs:
            raise _reject("scope_violation", f"scope_ref {ref!r} not in allowed scope", ctx)

    # Profile capability / tool allow-list.
    if intent.tool_id not in ctx.allowed_tool_ids:
        raise _reject(
            "profile_capability_denied",
            f"tool {intent.tool_id!r} not allowed for profile "
            f"{ctx.resolved_profile.external_profile.value}",
            ctx,
        )

    # Payload family allow-list (when a payload is requested).
    if (
        intent.payload_family_id is not None
        and intent.payload_family_id not in ctx.allowed_payload_family_ids
    ):
        raise _reject(
            "payload_family_denied",
            f"payload family {intent.payload_family_id!r} not allowed",
            ctx,
        )

    # Mutation classes must be from the signed enum.
    for mc in intent.mutation_classes:
        if mc not in _VALID_MUTATION_CLASSES:
            raise _reject("payload_family_denied", f"unknown mutation class {mc!r}", ctx)

    # LAB lease gate (deep).
    if ctx.resolved_profile.requires_lab_lease and not ctx.lab_lease_active:
        raise _reject("lab_lease_required", "deep profile requires an active LAB lease", ctx)

    # Approval gate.
    needs_approval = intent.approval_required or ctx.resolved_profile.approval_policy in {
        "gated",
        "lease_bound",
    }
    if intent.approval_required:
        approval_key = intent.capability_id or intent.tool_id
        if approval_key not in ctx.granted_approvals:
            raise _reject("profile_capability_denied", "required approval not granted", ctx)

    # Budget gate.
    if not ctx.budget_remaining:
        raise _reject("budget_exhausted", "scan budget exhausted", ctx)

    job = CompiledToolJob(
        tool_id=intent.tool_id,
        capability_id=intent.capability_id,
        argv=_build_argv(intent.tool_id, intent.typed_args),
        payload_family_id=intent.payload_family_id,
        mutation_classes=list(intent.mutation_classes),
        approval_required=needs_approval,
        evidence_contract=list(intent.evidence_contract),
        stop_conditions=dict(intent.stop_conditions),
        phase=intent.phase,
    )
    emit_event(
        EVENT_LLM_PLAN_APPROVED,
        tenant_id=ctx.tenant_id,
        scan_id=ctx.scan_id,
        scan_profile=ctx.resolved_profile.external_profile.value,
        phase=intent.phase,
        tool_id=job.tool_id,
        payload_family_id=job.payload_family_id,
    )
    return job


def validate_finding_claim(claim: dict[str, Any]) -> None:
    """Reject fabricated/unsupported LLM finding claims (R6/R8).

    * A ``confirmed``/``exploitable`` status requires non-empty ``evidence_ids``.
    * A CVE mentioned anywhere in the claim requires ``evidence_ids``.
    * Unknown finding categories are rejected.
    """
    status = str(claim.get("verification_status") or claim.get("status") or "").lower()
    evidence_ids = claim.get("evidence_ids") or []
    category = claim.get("category")

    if category is not None and str(category) not in _VALID_FINDING_CATEGORIES:
        raise IntentCompileError(
            f"unknown finding category {category!r}", code="hallucinated_finding"
        )

    if status in {"confirmed", "exploitable"} and not evidence_ids:
        raise IntentCompileError(
            "confirmed/exploitable finding without evidence_ids",
            code="hallucinated_finding",
        )

    blob = " ".join(
        str(claim.get(k, "")) for k in ("title", "description", "cve", "hypothesis")
    )
    if _CVE_RE.search(blob) and not evidence_ids:
        raise IntentCompileError("CVE asserted without evidence_ids", code="cve_without_evidence")


__all__ = [
    "AbstainResult",
    "CompiledToolJob",
    "CompilerContext",
    "IntentCompileError",
    "LLMScanIntent",
    "compile_intent",
    "validate_finding_claim",
]
