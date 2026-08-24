"""Tool projection codegen from the signed descriptor set (R9.1)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from src.sandbox.tool_codegen import (
    derive_all,
    derive_executable_manifest,
    derive_mcp_definitions,
    derive_parser_map,
    derive_risk_metadata,
)


@dataclass
class FakeDescriptor:
    tool_id: str
    command_template: list[str]
    image: str = "argus-kali-web:latest"
    risk_level: str = "low"
    requires_approval: bool = False
    parse_strategy: str = "json_object"
    category: str = "recon"
    phase: str = "recon"


DESCRIPTORS = [
    FakeDescriptor("nuclei", ["nuclei", "-u", "{target}"], parse_strategy="nuclei_jsonl"),
    FakeDescriptor("ffuf", ["ffuf"], risk_level="medium"),
    FakeDescriptor("sqlmap", ["sqlmap"], risk_level="destructive", requires_approval=True),
    FakeDescriptor("skipfish", ["skipfish"]),  # no parser registered
]


def test_derive_executable_manifest():
    manifest = derive_executable_manifest(DESCRIPTORS)
    names = {e["name"] for e in manifest["executables"]}
    assert names == {"nuclei", "ffuf", "sqlmap", "skipfish"}
    assert manifest["total_tools"] == 4
    nuclei = next(e for e in manifest["executables"] if e["name"] == "nuclei")
    assert nuclei["tools"] == ["nuclei"]
    assert nuclei["kind"] == "binary"


def test_derive_parser_map():
    pm = derive_parser_map(DESCRIPTORS)
    assert pm["nuclei"] == "nuclei_jsonl"
    assert pm["ffuf"] == "json_object"


def test_derive_risk_metadata():
    rm = derive_risk_metadata(DESCRIPTORS)
    assert rm["sqlmap"]["risk_level"] == "destructive"
    assert rm["sqlmap"]["requires_approval"] is True
    assert rm["nuclei"]["requires_approval"] is False


def test_derive_mcp_definitions_filters_unparseable():
    defs = derive_mcp_definitions(
        DESCRIPTORS,
        parser_tool_ids=frozenset({"nuclei", "ffuf", "sqlmap"}),
        known_executables=frozenset({"nuclei", "ffuf", "sqlmap", "skipfish"}),
    )
    ids = {d["tool_id"] for d in defs}
    assert "skipfish" not in ids  # no parser → not published
    assert ids == {"nuclei", "ffuf", "sqlmap"}


def test_derive_all_keys():
    out = derive_all(
        DESCRIPTORS,
        parser_tool_ids=frozenset({"nuclei", "ffuf", "sqlmap"}),
        known_executables=frozenset({"nuclei", "ffuf", "sqlmap", "skipfish"}),
    )
    assert set(out.keys()) == {
        "executable_manifest",
        "parser_map",
        "risk_metadata",
        "mcp_definitions",
    }


def test_signed_registry_is_source_of_truth_for_executable_manifest():
    """Drift guard: committed expected_executables.json matches what the signed
    descriptors derive (the signed catalog is the single source of truth)."""
    try:
        from src.sandbox.tool_registry import ToolRegistry
    except Exception:  # pragma: no cover
        pytest.skip("tool registry unavailable")

    backend_root = Path(__file__).resolve().parents[3]
    tools_dir = backend_root / "config" / "tools"
    manifest_path = backend_root.parent / "infra" / "sandbox" / "expected_executables.json"
    if not tools_dir.is_dir() or not manifest_path.is_file():
        pytest.skip("catalog or manifest not present")

    registry = ToolRegistry(tools_dir=tools_dir)
    try:
        registry.load()
    except Exception as exc:  # pragma: no cover - signature/env issues
        pytest.skip(f"registry load failed: {exc}")

    descriptors = registry.all_descriptors()
    derived = derive_executable_manifest(descriptors)
    derived_names = {e["name"] for e in derived["executables"]}

    committed = json.loads(manifest_path.read_text(encoding="utf-8"))
    committed_names = {e["name"] for e in committed.get("executables", [])}

    # The committed manifest must be in sync with the signed descriptors.
    assert derived_names == committed_names, (
        f"executable manifest drift: only_in_descriptors="
        f"{sorted(derived_names - committed_names)} "
        f"only_in_manifest={sorted(committed_names - derived_names)}"
    )
