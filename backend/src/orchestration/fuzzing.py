"""Fuzzing MCP tool — AFL++/libFuzzer/Jazzer integration with LLM harness synthesis.

Provides fuzzing capabilities as MCP tools. The LLM generates fuzzing
harnesses based on the target's language/framework, then fuzzing engines
find crashes that translate to vulnerability findings.

Ось B из Развитие2.md + Фаза 2: fuzzing integration.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

FUZZER_ENGINES = {
    "afl_plus_plus": {
        "languages": ["c", "cpp", "go", "rust"],
        "docker_image": "argus/aflplusplus:latest",
        "command_template": "afl-fuzz -i {input_dir} -o {output_dir} -m none -- {target_binary}",
    },
    "libfuzzer": {
        "languages": ["c", "cpp", "rust"],
        "docker_image": "argus/libfuzzer:latest",
        "command_template": "{target_binary} -artifact_prefix={output_dir} {input_dir}",
    },
    "jazzer": {
        "languages": ["java"],
        "docker_image": "argus/jazzer:latest",
        "command_template": "jazzer --cp={classpath} --target_class={target_class}",
    },
}

HARNESS_TEMPLATES = {
    "c": (
        '#include <stdint.h>\n#include <stddef.h>\n'
        'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n'
        '    // TODO: LLM-generated target-specific harness\n'
        '    return 0;\n'
        '}}\n'
    ),
    "java": (
        'import com.code_intelligence.jazzer.api.FuzzedDataProvider;\n'
        'public class FuzzTarget {{\n'
        '    public static void fuzzerTestOneInput(FuzzedDataProvider data) {{\n'
        '        // TODO: LLM-generated target-specific harness\n'
        '    }}\n'
        '}}\n'
    ),
}


@dataclass
class FuzzingRequest:
    """Request to run a fuzzing campaign."""

    target_binary: str = ""
    target_class: str = ""
    language: str = "c"
    engine: str = "afl_plus_plus"
    input_dir: str = "/tmp/fuzz-input"
    output_dir: str = "/tmp/fuzz-output"
    timeout_seconds: int = 3600
    scan_id: str = ""


@dataclass
class FuzzCrash:
    """A crash found by the fuzzer."""

    crash_id: str = ""
    crash_file: str = ""
    crash_type: str = ""
    stack_trace: str = ""
    reproducible: bool = False


@dataclass
class FuzzingResult:
    """Result of a fuzzing campaign."""

    crashes: list[FuzzCrash] = field(default_factory=list)
    total_runs: int = 0
    duration_seconds: float = 0.0
    engine: str = ""
    harness_source: str = ""


def select_engine(language: str) -> str:
    """Select the best fuzzer engine for a given language."""
    for engine_name, config in FUZZER_ENGINES.items():
        if language.lower() in config["languages"]:
            return engine_name
    return "afl_plus_plus"


def generate_harness_stub(language: str, target_function: str = "") -> str:
    """Generate a fuzzing harness template for the given language."""
    template = HARNESS_TEMPLATES.get(language.lower(), HARNESS_TEMPLATES["c"])
    if target_function:
        template = template.replace("// TODO: LLM-generated target-specific harness", f"// Target: {target_function}")
    return template


FUZZ_SYSTEM_PROMPT = (
    "You are a fuzzing engineer. Generate a fuzzing harness for the target "
    "that maximizes code coverage. The harness must be safe (no network calls, "
    "no file writes outside /tmp). Respond ONLY with valid source code."
)

FUZZ_USER_TEMPLATE = (
    "Generate a fuzzing harness for the following target:\n\n"
    "Language: {language}\n"
    "Target function/class: {target}\n"
    "Framework: {framework}\n\n"
    "=== SOURCE CONTEXT ===\n{source_context}\n=== END ===\n\n"
    "Output the complete harness source code."
)


def build_fuzz_harness_prompt(
    language: str,
    target: str = "",
    framework: str = "",
    source_context: str = "",
) -> tuple[str, str]:
    return FUZZ_SYSTEM_PROMPT, FUZZ_USER_TEMPLATE.format(
        language=language,
        target=target,
        framework=framework,
        source_context=source_context[:20000],
    )


__all__ = [
    "FUZZER_ENGINES",
    "FuzzCrash",
    "FuzzingRequest",
    "FuzzingResult",
    "build_fuzz_harness_prompt",
    "generate_harness_stub",
    "select_engine",
]