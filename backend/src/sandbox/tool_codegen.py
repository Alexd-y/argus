"""Derive every downstream tool projection from the ONE signed descriptor set (R9.1).

The signed ``backend/config/tools/*.yaml`` catalog is the single source of truth.
Everything downstream — executable manifest, MCP definitions, parser map,
risk/approval metadata — is *derived* here so drift between projections is
impossible by construction. A drift test asserts the committed executable
manifest matches what is derived from the descriptors.
"""

from __future__ import annotations

from typing import Any, Protocol

_WRAPPER_SUFFIXES: tuple[str, ...] = ("-wrapper", "-runner", "-cli")
_WRAPPER_PREFIXES: tuple[str, ...] = ("playwright",)


class DescriptorLike(Protocol):
    tool_id: str
    command_template: list[str]
    image: Any
    risk_level: Any
    requires_approval: bool
    parse_strategy: Any
    category: Any
    phase: Any


def _val(x: Any) -> Any:
    return getattr(x, "value", x)


def _classify_executable(executable: str) -> str:
    if executable.endswith(_WRAPPER_SUFFIXES) or executable.startswith(_WRAPPER_PREFIXES):
        return "wrapper"
    return "binary"


def _image_profile(image: Any) -> str:
    return str(image).partition(":")[0]


def _executable_of(descriptor: DescriptorLike) -> str:
    template = getattr(descriptor, "command_template", None) or []
    return str(template[0]) if template else ""


def derive_executable_manifest(descriptors: list[DescriptorLike]) -> dict[str, Any]:
    """Executable → {kind, tools, images} manifest (mirrors the generator script)."""
    grouped: dict[str, dict[str, set[str]]] = {}
    for descriptor in descriptors:
        executable = _executable_of(descriptor)
        if not executable:
            continue
        entry = grouped.setdefault(executable, {"tools": set(), "images": set()})
        entry["tools"].add(str(descriptor.tool_id))
        entry["images"].add(_image_profile(getattr(descriptor, "image", "")))
    executables = [
        {
            "name": name,
            "kind": _classify_executable(name),
            "tools": sorted(data["tools"]),
            "images": sorted(data["images"]),
        }
        for name, data in sorted(grouped.items())
    ]
    return {
        "schema_version": 1,
        "total_tools": len(descriptors),
        "total_executables": len(executables),
        "binary_count": sum(1 for e in executables if e["kind"] == "binary"),
        "wrapper_count": sum(1 for e in executables if e["kind"] == "wrapper"),
        "executables": executables,
    }


def derive_parser_map(descriptors: list[DescriptorLike]) -> dict[str, str]:
    """tool_id → declared parse_strategy (parser routing key)."""
    return {str(d.tool_id): str(_val(d.parse_strategy)) for d in descriptors}


def derive_risk_metadata(descriptors: list[DescriptorLike]) -> dict[str, dict[str, Any]]:
    """tool_id → {risk_level, requires_approval, category, phase}."""
    return {
        str(d.tool_id): {
            "risk_level": str(_val(d.risk_level)),
            "requires_approval": bool(d.requires_approval),
            "category": str(_val(getattr(d, "category", ""))),
            "phase": str(_val(getattr(d, "phase", ""))),
        }
        for d in descriptors
    }


def derive_mcp_definitions(
    descriptors: list[DescriptorLike],
    *,
    parser_tool_ids: frozenset[str],
    known_executables: frozenset[str] | None = None,
) -> list[dict[str, Any]]:
    """Registrable-only MCP tool definitions (R9.2). Uses the registrability gate."""
    from src.sandbox.tool_registrability import should_register_mcp_tool

    out: list[dict[str, Any]] = []
    for d in descriptors:
        if not should_register_mcp_tool(
            d, parser_tool_ids=parser_tool_ids, known_executables=known_executables
        ):
            continue
        out.append(
            {
                "tool_id": str(d.tool_id),
                "category": str(_val(getattr(d, "category", ""))),
                "phase": str(_val(getattr(d, "phase", ""))),
                "risk_level": str(_val(d.risk_level)),
                "requires_approval": bool(d.requires_approval),
                "parse_strategy": str(_val(d.parse_strategy)),
            }
        )
    return sorted(out, key=lambda e: e["tool_id"])


def derive_all(
    descriptors: list[DescriptorLike],
    *,
    parser_tool_ids: frozenset[str],
    known_executables: frozenset[str] | None = None,
) -> dict[str, Any]:
    """All projections from one signed descriptor set (single source of truth)."""
    return {
        "executable_manifest": derive_executable_manifest(descriptors),
        "parser_map": derive_parser_map(descriptors),
        "risk_metadata": derive_risk_metadata(descriptors),
        "mcp_definitions": derive_mcp_definitions(
            descriptors,
            parser_tool_ids=parser_tool_ids,
            known_executables=known_executables,
        ),
    }


__all__ = [
    "derive_all",
    "derive_executable_manifest",
    "derive_mcp_definitions",
    "derive_parser_map",
    "derive_risk_metadata",
]
