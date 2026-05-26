"""Binary analysis MCP tool — Ghidra/radare2/binwalk integration.

Provides firmware extraction, disassembly, decompilation, and binary
vulnerability pattern matching as MCP tools.

Ось C + Ось A from Развитие2.md: binary/firmware analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

BINARY_TOOLS = {
    "binwalk": {"docker_image": "argus/binwalk:latest", "description": "Firmware extraction and entropy analysis"},
    "ghidra": {"docker_image": "argus/ghidra:latest", "description": "Headless decompilation and analysis"},
    "radare2": {"docker_image": "argus/radare2:latest", "description": "Disassembly and binary diffing"},
}


@dataclass
class BinaryAnalysisRequest:
    binary_path: str = ""
    binary_url: str = ""
    analysis_type: str = "full"
    architecture: str = ""
    scan_id: str = ""
    timeout_seconds: int = 600


@dataclass
class BinaryFunction:
    name: str = ""
    address: str = ""
    size: int = 0
    decompiled: str = ""


@dataclass
class BinaryVulnerability:
    function_name: str
    vuln_type: str
    severity: str
    description: str
    address: str = ""


@dataclass
class BinaryAnalysisResult:
    functions: list[BinaryFunction] = field(default_factory=list)
    vulnerabilities: list[BinaryVulnerability] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    firmware_files: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: str = ""


BINARY_SYSTEM_PROMPT = (
    "You are a binary security analyst. Analyze the decompiled/disassembled "
    "code for vulnerability patterns: buffer overflows, format strings, "
    "integer overflows, use-after-free, command injection, hardcoded credentials. "
    "Return findings as JSON."
)

BINARY_USER_TEMPLATE = (
    "Analyze the following binary analysis output for security vulnerabilities:\n\n"
    "Binary: {binary_path}\n"
    "Architecture: {architecture}\n"
    "=== DECOMPILED FUNCTIONS ===\n{functions}\n=== END ===\n\n"
    'Return JSON: {{"vulnerabilities": [{{"function_name": "s", "vuln_type": "s", '
    '"severity": "s", "description": "s", "address": "s"}}]}}'
)


def build_binary_prompt(binary_path: str, architecture: str, functions: str) -> tuple[str, str]:
    try:
        from src.orchestration.prompt_loader import get_loader
        loader = get_loader()
        if loader.available:
            try:
                system, user = loader.render_extended_system_user(
                    "binary_analysis",
                    binary_path=binary_path, architecture=architecture,
                    functions=functions[:20000],
                )
                if system.strip() and user.strip():
                    return system, user
            except Exception:
                pass
    except Exception:
        pass
    return BINARY_SYSTEM_PROMPT, BINARY_USER_TEMPLATE.format(
        binary_path=binary_path, architecture=architecture,
        functions=functions[:20000],
    )


def detect_binary_type(file_path: str) -> str:
    _path_lower = file_path.lower()
    if _path_lower.endswith((".elf", ".so", ".o", ".bin")):
        return "elf"
    if _path_lower.endswith((".exe", ".dll", ".sys")):
        return "pe"
    if _path_lower.endswith((".dex", ".apk", ".jar")):
        return "dex"
    if _path_lower.endswith((".ipa", ".dylib")):
        return "macho"
    return "unknown"


__all__ = [
    "BINARY_TOOLS",
    "BinaryAnalysisRequest",
    "BinaryAnalysisResult",
    "BinaryFunction",
    "BinaryVulnerability",
    "build_binary_prompt",
    "detect_binary_type",
]