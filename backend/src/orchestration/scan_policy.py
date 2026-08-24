"""Scan policy bridge — composes profile + tool registry + payload taxonomy (R8/R9/R10).

Builds the deterministic allow-lists that the LLM-intent compiler needs, from a
resolved scan profile and the signed registries. Pure and dependency-injected
(descriptors / families / parser set passed in) so it is fully unit-testable.
"""

from __future__ import annotations

from typing import Any

from src.llm_orchestrator.intent_compiler import CompilerContext
from src.payloads.taxonomy import FamilyLike, families_allowed_by_profile
from src.profiles.resolver import PROFILE_VERSION, ResolvedScanProfile
from src.sandbox.tool_registrability import DescriptorLike, registrable_tool_ids


def build_compiler_context(
    resolved: ResolvedScanProfile,
    *,
    tool_descriptors: list[DescriptorLike],
    payload_families: list[FamilyLike],
    parser_tool_ids: frozenset[str],
    known_executables: frozenset[str] | None = None,
    allowed_scope_refs: frozenset[str] = frozenset(),
    lab_lease_active: bool = False,
    granted_approvals: frozenset[str] = frozenset(),
    budget_remaining: bool = True,
    scan_id: str | None = None,
    tenant_id: str | None = None,
) -> CompilerContext:
    """Compose the deterministic allow-lists for the intent compiler.

    * allowed tools = signed descriptors that are registrable AND within the
      profile's risk ceiling (R9),
    * allowed payload families = families permitted by the profile policy (R10),
    * lease/approval/budget/scope come from runtime state (R8).
    """
    allowed_tool_ids = registrable_tool_ids(
        tool_descriptors,
        parser_tool_ids=parser_tool_ids,
        known_executables=known_executables,
        payload_risk_ceiling=resolved.payload_risk_ceiling,
        emit=True,
        scan_id=scan_id,
        tenant_id=tenant_id,
        scan_profile=resolved.external_profile.value,
    )
    allowed_payload_family_ids = families_allowed_by_profile(
        payload_families, resolved.external_profile.value
    )
    return CompilerContext(
        resolved_profile=resolved,
        allowed_scope_refs=allowed_scope_refs,
        allowed_tool_ids=allowed_tool_ids,
        allowed_payload_family_ids=allowed_payload_family_ids,
        lab_lease_active=lab_lease_active,
        granted_approvals=granted_approvals,
        budget_remaining=budget_remaining,
        scan_id=scan_id,
        tenant_id=tenant_id,
    )


def registry_versions(
    *,
    tool_registry_version: str | None = None,
    payload_registry_version: str | None = None,
    prompt_registry_version: str | None = None,
) -> dict[str, Any]:
    """Assemble the registry-version block for checkpoints / observability."""
    return {
        "tools": tool_registry_version,
        "payloads": payload_registry_version,
        "prompts": prompt_registry_version,
        "profile": PROFILE_VERSION,
    }


__all__ = ["build_compiler_context", "registry_versions"]
