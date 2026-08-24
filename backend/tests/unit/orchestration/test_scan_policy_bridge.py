"""Scan policy bridge composing profile + tools + payloads + intent compiler (R8/R9/R10)."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from src.llm_orchestrator.intent_compiler import (
    CompiledToolJob,
    IntentCompileError,
    compile_intent,
)
from src.orchestration.scan_policy import build_compiler_context, registry_versions
from src.profiles.resolver import resolve_scan_profile


@dataclass
class FakeDescriptor:
    tool_id: str
    command_template: list[str]
    risk_level: str = "low"
    requires_approval: bool = False


@dataclass
class FakeFamily:
    family_id: str
    cwe_ids: list[int]
    risk_level: str = "low"
    requires_approval: bool = False
    oast_required: bool = False


DESCRIPTORS = [
    FakeDescriptor("nuclei", ["nuclei"], risk_level="low"),
    FakeDescriptor("ffuf", ["ffuf"], risk_level="low"),
    FakeDescriptor("sqlmap", ["sqlmap"], risk_level="destructive"),
]
FAMILIES = [
    FakeFamily("xss_safe", [79], risk_level="low"),
    FakeFamily("sqli_destructive", [89], risk_level="destructive", requires_approval=True),
]
PARSERS = frozenset({"nuclei", "ffuf", "sqlmap"})
EXECUTABLES = frozenset({"nuclei", "ffuf", "sqlmap"})


def test_light_context_excludes_destructive_tool_and_payload():
    ctx = build_compiler_context(
        resolve_scan_profile("light"),
        tool_descriptors=DESCRIPTORS,
        payload_families=FAMILIES,
        parser_tool_ids=PARSERS,
        known_executables=EXECUTABLES,
    )
    assert "nuclei" in ctx.allowed_tool_ids
    assert "sqlmap" not in ctx.allowed_tool_ids  # destructive denied for light
    assert "xss_safe" in ctx.allowed_payload_family_ids
    assert "sqli_destructive" not in ctx.allowed_payload_family_ids


def test_deep_context_includes_destructive():
    ctx = build_compiler_context(
        resolve_scan_profile("deep"),
        tool_descriptors=DESCRIPTORS,
        payload_families=FAMILIES,
        parser_tool_ids=PARSERS,
        known_executables=EXECUTABLES,
        lab_lease_active=True,
    )
    assert "sqlmap" in ctx.allowed_tool_ids
    assert "sqli_destructive" in ctx.allowed_payload_family_ids


def test_composed_context_drives_intent_compiler():
    ctx = build_compiler_context(
        resolve_scan_profile("light"),
        tool_descriptors=DESCRIPTORS,
        payload_families=FAMILIES,
        parser_tool_ids=PARSERS,
        known_executables=EXECUTABLES,
        allowed_scope_refs=frozenset({"scope-1"}),
    )
    job = compile_intent(
        {
            "phase": "vuln_analysis",
            "scope_refs": ["scope-1"],
            "tool_id": "nuclei",
            "typed_args": {"severity": "high"},
            "payload_family_id": "xss_safe",
        },
        ctx,
    )
    assert isinstance(job, CompiledToolJob)

    # A destructive tool is rejected via the composed allow-list.
    with pytest.raises(IntentCompileError) as exc:
        compile_intent(
            {"phase": "exploitation", "scope_refs": ["scope-1"], "tool_id": "sqlmap"}, ctx
        )
    assert exc.value.code == "profile_capability_denied"


def test_registry_versions_block():
    v = registry_versions(tool_registry_version="t1", payload_registry_version="p1")
    assert v["tools"] == "t1"
    assert v["payloads"] == "p1"
    assert v["profile"] == "v1"
