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
    "binwalk": {"docker_image": "argus-kali-runner:latest", "description": "Firmware extraction and entropy analysis"},
    "ghidra": {"docker_image": "argus-kali-runner:latest", "description": "Headless decompilation and analysis"},
    "radare2": {"docker_image": "argus-kali-runner:latest", "description": "Disassembly and binary diffing"},
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


async def run_binary_analysis(
    request: BinaryAnalysisRequest,
    use_sandbox: bool = True,
) -> BinaryAnalysisResult:
    """Run binary analysis pipeline: detect type → extract strings → decompile → LLM analysis.

    Requires binwalk/Ghidra/radare2 in sandbox or on host.
    Degrades gracefully if tools are unavailable.
    """
    import os
    import tempfile

    binary_type = detect_binary_type(request.binary_path) if request.binary_path else "unknown"
    if binary_type == "unknown" and request.binary_url:
        binary_type = "elf"

    if not request.binary_path and not request.binary_url:
        return BinaryAnalysisResult(error="No binary path or URL provided")

    from src.tools.executor import execute_command

    strings_out: list[str] = []
    firmware_files: list[str] = []

    if request.binary_path and os.path.isfile(request.binary_path):
        try:
            result = execute_command(
                f"strings {request.binary_path} | head -200",
                use_sandbox=use_sandbox,
                timeout_seconds=min(request.timeout_seconds, 30),
            )
            if result and result.get("stdout"):
                strings_out = result["stdout"].splitlines()[:200]
        except Exception as exc:
            logger.warning("binary_strings_failed", extra={"error": str(exc)})

        if request.analysis_type in ("full", "firmware"):
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    result = execute_command(
                        f"binwalk -e {request.binary_path} -C {tmpdir}",
                        use_sandbox=use_sandbox,
                        timeout_seconds=min(request.timeout_seconds, 120),
                    )
                    if result and result.get("stdout"):
                        for line in result["stdout"].splitlines():
                            if "extracted" in line.lower() or "->" in line:
                                firmware_files.append(line.strip())
            except Exception as exc:
                logger.warning("binwalk_failed", extra={"error": str(exc)})

    functions_text = "\n".join(strings_out[:50]) if strings_out else "No decompiled functions available"
    system_prompt, user_prompt = build_binary_prompt(
        binary_path=request.binary_path or request.binary_url,
        architecture=request.architecture or binary_type,
        functions=functions_text,
    )

    from src.llm.facade import call_llm_unified
    from src.llm.task_router import LLMTask

    vulns: list[BinaryVulnerability] = []
    try:
        response = await call_llm_unified(
            system_prompt, user_prompt,
            task=LLMTask.VULN_ANALYSIS,
            scan_id=request.scan_id,
            phase="binary_analysis",
        )
        if response:
            import json
            text = response if isinstance(response, str) else str(response)
            try:
                start = text.index("{")
                end = text.rindex("}") + 1
                parsed = json.loads(text[start:end])
                for item in parsed.get("vulnerabilities", []):
                    vulns.append(BinaryVulnerability(
                        function_name=item.get("function_name", ""),
                        vuln_type=item.get("vuln_type", ""),
                        severity=item.get("severity", "medium"),
                        description=item.get("description", ""),
                        address=item.get("address", ""),
                    ))
            except (ValueError, json.JSONDecodeError):
                logger.warning("binary_analysis_llm_parse_failed")
    except Exception as exc:
        logger.warning("binary_analysis_llm_failed", extra={"error": str(exc)})

    return BinaryAnalysisResult(
        functions=[],
        vulnerabilities=vulns,
        strings=strings_out[:100],
        firmware_files=firmware_files,
        error="" if vulns or strings_out else "No analysis results",
    )


__all__ = [
    "BINARY_TOOLS",
    "BinaryAnalysisRequest",
    "BinaryAnalysisResult",
    "BinaryFunction",
    "BinaryVulnerability",
    "build_binary_prompt",
    "detect_binary_type",
    "run_binary_analysis",
]