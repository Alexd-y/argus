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

#: Stable marker emitted ONLY by ``generate_harness_stub``; survives target-name
#: substitution and lets ``_is_stub_harness`` reliably tell a no-op template apart
#: from a real LLM-synthesized harness.
_STUB_SENTINEL = "ARGUS-FUZZ-STUB"

HARNESS_TEMPLATES = {
    "c": (
        "#include <stdint.h>\n#include <stddef.h>\n"
        "// ARGUS-FUZZ-STUB — no-op placeholder, not a usable harness\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{\n"
        "    // TODO: LLM-generated target-specific harness\n"
        "    return 0;\n"
        "}}\n"
    ),
    "java": (
        "import com.code_intelligence.jazzer.api.FuzzedDataProvider;\n"
        "// ARGUS-FUZZ-STUB — no-op placeholder, not a usable harness\n"
        "public class FuzzTarget {{\n"
        "    public static void fuzzerTestOneInput(FuzzedDataProvider data) {{\n"
        "        // TODO: LLM-generated target-specific harness\n"
        "    }}\n"
        "}}\n"
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
        template = template.replace(
            "// TODO: LLM-generated target-specific harness",
            f"// Target: {target_function}",
        )
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
                    "fuzzing",
                    language=language,
                    target=target,
                    framework=framework,
                    source_context=source_context[:20000],
                )
                if system.strip() and user.strip():
                    return system, user
            except Exception:
                logger.debug(
                    "build_fuzz_harness_prompt: suppressed best-effort error", exc_info=True
                )
    except Exception:
        logger.debug("build_fuzz_harness_prompt: suppressed best-effort error", exc_info=True)
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
            crashes.append(
                FuzzCrash(
                    crash_id=filename[:64],
                    crash_file=line,
                    crash_type=crash_type,
                )
            )
    for line in stderr.splitlines():
        stripped = line.strip()
        if "CRASH" in stripped.upper() or "SUMMARY:" in stripped.upper():
            crashes.append(FuzzCrash(crash_type="detected", stack_trace=stripped[:500]))
    return crashes


#: Languages whose harness must be compiled into an instrumented binary before the
#: fuzzer can run. (Java/Jazzer loads classes directly, so it is excluded.)
_COMPILED_LANGS = frozenset({"c", "cpp", "rust", "go"})

#: Compile the harness (+ optional target source) into an instrumented fuzz binary.
_LIBFUZZER_COMPILE = "clang -g -O1 -fsanitize=fuzzer,address {harness} {sources} -o {fuzz_bin}"
_AFL_COMPILE = "afl-cc -g -O1 -fsanitize=address {harness} {sources} -o {fuzz_bin}"


def _strip_code_fences(text: str) -> str:
    """Strip a leading/trailing ```lang fence an LLM may wrap the harness in."""
    s = (text or "").strip()
    if s.startswith("```"):
        lines = s.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        s = "\n".join(lines).strip()
    return s


def _is_stub_harness(harness: str) -> bool:
    """True when the harness is the shipped no-op template (cannot find real bugs).

    Detection keys off ``_STUB_SENTINEL`` which only ``generate_harness_stub`` emits
    and which survives target-name substitution, so a template is caught whether or
    not a target name was substituted. A real LLM harness never carries it.
    """
    if not harness or not harness.strip():
        return True
    return _STUB_SENTINEL in harness


async def synthesize_harness(request: FuzzingRequest) -> tuple[str, bool]:
    """Synthesize a target-specific fuzzing harness via the LLM (WRB, local).

    Returns ``(harness_source, is_stub)``. ``is_stub`` is True when no real harness
    could be produced (LLM unavailable / empty / still a no-op template), in which
    case the caller MUST NOT run the fuzzer — a no-op harness fabricates findings.
    """
    system, user = build_fuzz_harness_prompt(
        language=request.language,
        target=request.target_binary or request.target_class,
        framework="",
        source_context=request.source_code or "",
    )
    try:
        from src.llm.facade import LLMTask, call_llm_unified

        out = await call_llm_unified(
            system,
            user,
            task=LLMTask.EXPLOIT_GENERATION,
            scan_id=request.scan_id or None,
            phase="fuzzing",
        )
        code = _strip_code_fences(out or "")
        if code.strip() and not _is_stub_harness(code):
            return code, False
    except Exception:
        logger.debug("synthesize_harness: LLM unavailable, falling back to stub", exc_info=True)
    return generate_harness_stub(request.language, request.target_binary), True


async def run_fuzzing_campaign(
    request: FuzzingRequest,
    use_sandbox: bool = True,
) -> FuzzingResult:
    """Execute a fuzzing campaign via sandbox container.

    1. Use the provided harness, else synthesize a target-specific one via the LLM.
       A no-op stub harness short-circuits (honesty gate) — no fuzzer run, no crashes.
    2. Write harness + target source + seed corpus to a temp directory.
    3. Compile the harness into an instrumented binary (compiled languages).
    4. Run the fuzzer in the sandbox and parse crashes from a *successful* run only.
    """
    start = time.monotonic()
    engine_config = FUZZER_ENGINES.get(request.engine, FUZZER_ENGINES["afl_plus_plus"])

    if request.harness_source and request.harness_source.strip():
        harness, is_stub = request.harness_source, _is_stub_harness(request.harness_source)
        harness_is_llm = False
    else:
        harness, is_stub = await synthesize_harness(request)
        harness_is_llm = not is_stub

    # An LLM-synthesized harness is model-authored code we compile and execute, so it
    # ALWAYS runs inside the sandbox regardless of the sandbox setting (defense in
    # depth, symmetric with symbolic execution). A caller-provided harness keeps the
    # caller's setting.
    effective_sandbox = True if harness_is_llm else use_sandbox

    if is_stub:
        # Honesty gate (P0-1): a no-op harness cannot find real bugs, so running it and
        # reporting "crashes" would fabricate findings. Skip and say why instead.
        return FuzzingResult(
            engine=request.engine,
            harness_source=harness,
            error=(
                "fuzzing skipped: no target-specific harness could be synthesized "
                "(LLM unavailable or returned a no-op template)"
            ),
            duration_seconds=round(time.monotonic() - start, 2),
        )

    from src.tools.executor import execute_command

    crash_dir = tempfile.mkdtemp(prefix="argus-fuzz-")
    input_dir = os.path.join(crash_dir, "input")
    output_dir = os.path.join(crash_dir, "output")
    harness_path = os.path.join(crash_dir, f"harness.{request.language}")
    fuzz_bin = os.path.join(crash_dir, "fuzz_bin")

    try:
        os.makedirs(input_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)

        with open(os.path.join(input_dir, "seed"), "w") as f:
            f.write("AA")
        with open(harness_path, "w") as f:
            f.write(harness)

        source_path = ""
        if request.source_code.strip():
            source_path = os.path.join(crash_dir, f"target.{request.language}")
            with open(source_path, "w") as f:
                f.write(request.source_code)

        # Compile the harness into an instrumented binary for compiled languages;
        # a failed compile means we cannot fuzz, so we report that (no fabricated crashes).
        run_target = request.target_binary
        if request.language.lower() in _COMPILED_LANGS:
            compile_tmpl = _AFL_COMPILE if request.engine == "afl_plus_plus" else _LIBFUZZER_COMPILE
            compile_cmd = compile_tmpl.format(
                harness=harness_path, sources=source_path, fuzz_bin=fuzz_bin
            )
            comp = execute_command(compile_cmd, use_sandbox=effective_sandbox, timeout_sec=120)
            if not comp.get("success", False):
                return FuzzingResult(
                    engine=request.engine,
                    harness_source=harness,
                    error="harness compilation failed: " + (comp.get("stderr", "") or "")[:1500],
                    duration_seconds=round(time.monotonic() - start, 2),
                )
            run_target = fuzz_bin

        command = engine_config["command_template"].format(
            input_dir=input_dir,
            output_dir=output_dir,
            target_binary=run_target,
            target_class=request.target_class,
            classpath=getattr(request, "classpath", ""),
        )

        timeout = min(request.timeout_seconds, 600)
        result = execute_command(command, use_sandbox=effective_sandbox, timeout_sec=timeout)

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
    "run_fuzzing_campaign",
    "select_engine",
    "synthesize_harness",
]
