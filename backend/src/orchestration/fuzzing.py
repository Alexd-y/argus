"""Fuzzing MCP tool — AFL++/libFuzzer/Jazzer integration with LLM harness synthesis.

Provides fuzzing capabilities as MCP tools. The LLM generates fuzzing
harnesses based on the target's language/framework, then fuzzing engines
find crashes that translate to vulnerability findings.

Ось B из Развитие2.md + Фаза 2: fuzzing integration.
"""

from __future__ import annotations

import logging
import os
import tempfile
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

FUZZER_ENGINES = {
    "afl_plus_plus": {
        "languages": ["c", "cpp", "go", "rust"],
        "docker_image": "argus-kali-runner:latest",
        "command_template": "afl-fuzz -i {input_dir} -o {output_dir} -m none -- {target_binary}",
        "install_hint": "installed in argus-kali-runner image",
    },
    "libfuzzer": {
        "languages": ["c", "cpp", "rust"],
        "docker_image": "argus-kali-runner:latest",
        "command_template": "{target_binary} -artifact_prefix={output_dir} {input_dir}",
        "install_hint": "clang -fsanitize=fuzzer in argus-kali-runner image",
    },
    "jazzer": {
        "languages": ["java"],
        "docker_image": "argus-kali-runner:latest",
        "command_template": "java -jar /opt/jazzer/target/jazzer-*.jar --cp={classpath} --target_class={target_class}",
        "install_hint": "installed in argus-kali-runner image at /opt/jazzer",
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
    source_code: str = ""
    harness_source: str = ""


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
    error: str = ""


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
    try:
        from src.orchestration.prompt_loader import get_loader
        loader = get_loader()
        if loader.available:
            try:
                system, user = loader.render_extended_system_user(
                    "fuzzing", language=language, target=target,
                    framework=framework, source_context=source_context[:20000]
                )
                if system.strip() and user.strip():
                    return system, user
            except Exception:
                pass
    except Exception:
        pass
    return FUZZ_SYSTEM_PROMPT, FUZZ_USER_TEMPLATE.format(
        language=language,
        target=target,
        framework=framework,
        source_context=source_context[:20000],
    )


def _parse_crashes_from_output(output_dir_listing: str, stderr: str) -> list[FuzzCrash]:
    """Parse crash entries from fuzzer output directory listing and stderr."""
    crashes: list[FuzzCrash] = []
    for line in output_dir_listing.splitlines():
        line = line.strip()
        if not line:
            continue
        lower = line.lower()
        is_crash = any(kw in lower for kw in ("crash", "oom", "timeout", "sig:", " hangs"))
        if is_crash or (line.startswith("id:") and "," in line):
            crash_type = "crash"
            if "oom" in lower:
                crash_type = "oom"
            elif "timeout" in lower or "hang" in lower:
                crash_type = "timeout"
            filename = line.split("/")[-1] if "/" in line else line.split("\\")[-1]
            crashes.append(FuzzCrash(
                crash_id=filename[:64],
                crash_file=line,
                crash_type=crash_type,
            ))
    for line in stderr.splitlines():
        stripped = line.strip()
        if "CRASH" in stripped.upper() or "SUMMARY:" in stripped.upper():
            crashes.append(FuzzCrash(crash_type="detected", stack_trace=stripped[:500]))
    return crashes


async def run_fuzzing_campaign(
    request: FuzzingRequest,
    use_sandbox: bool = True,
) -> FuzzingResult:
    """Execute a fuzzing campaign via sandbox container.

    1. Generate or use provided harness
    2. Write harness + seed corpus to temp directory
    3. Run fuzzer in sandbox via execute_command
    4. Parse crashes from output
    5. Return FuzzingResult with crashes
    """
    start = time.monotonic()
    engine_config = FUZZER_ENGINES.get(request.engine, FUZZER_ENGINES["afl_plus_plus"])
    harness = request.harness_source or generate_harness_stub(request.language, request.target_binary)

    from src.tools.executor import execute_command

    crash_dir = tempfile.mkdtemp(prefix="argus-fuzz-")
    input_dir = os.path.join(crash_dir, "input")
    output_dir = os.path.join(crash_dir, "output")
    harness_path = os.path.join(crash_dir, f"harness.{request.language}")

    try:
        os.makedirs(input_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)

        seed_file = os.path.join(input_dir, "seed")
        with open(seed_file, "w") as f:
            f.write("AA")

        with open(harness_path, "w") as f:
            f.write(harness)

        command = engine_config["command_template"].format(
            input_dir=input_dir,
            output_dir=output_dir,
            target_binary=request.target_binary,
            target_class=request.target_class,
            classpath=getattr(request, "classpath", ""),
        )

        timeout = min(request.timeout_seconds, 600)

        result = execute_command(
            command,
            use_sandbox=use_sandbox,
            timeout_sec=timeout,
        )

        crashes = _parse_crashes_from_output(
            result.get("stdout", ""),
            result.get("stderr", ""),
        )

        if use_sandbox:
            ls_result = execute_command(
                f"ls -la {output_dir}/",
                use_sandbox=True,
                timeout_sec=10,
            )
            extra_crashes = _parse_crashes_from_output(ls_result.get("stdout", ""), "")
            seen_ids = {c.crash_id for c in crashes}
            for ec in extra_crashes:
                if ec.crash_id not in seen_ids:
                    crashes.append(ec)
                    seen_ids.add(ec.crash_id)

        duration = time.monotonic() - start

        return FuzzingResult(
            crashes=crashes,
            total_runs=int(result.get("return_code", -1) != 0) + len(crashes),
            duration_seconds=round(duration, 2),
            engine=request.engine,
            harness_source=harness,
            error=result.get("stderr", "")[:2000] if not result.get("success", False) else "",
        )

    except Exception as exc:
        logger.warning("Fuzzing campaign failed: %s", exc)
        return FuzzingResult(
            engine=request.engine,
            harness_source=harness,
            error=str(exc),
            duration_seconds=time.monotonic() - start,
        )


__all__ = [
    "FUZZER_ENGINES",
    "FuzzCrash",
    "FuzzingRequest",
    "FuzzingResult",
    "build_fuzz_harness_prompt",
    "generate_harness_stub",
    "select_engine",
    "run_fuzzing_campaign",
]
