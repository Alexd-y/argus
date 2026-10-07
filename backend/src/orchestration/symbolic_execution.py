"""Symbolic execution MCP tool — angr/Z3 proof-of-vulnerability.

Uses symbolic execution to prove that a vulnerability path is feasible,
providing mathematical proof that user input can reach a dangerous sink.

Ось A п.2-3 из Развитие2.md: symbolic execution for PoV.
"""

from __future__ import annotations

import ast
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_URL_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
_HOSTNAME_ONLY = re.compile(r"^[a-z0-9\-]+(\.[a-z0-9\-]+)+$", re.IGNORECASE)

# Static allowlist for LLM-synthesized angr scripts. The script is written to disk
# and executed with ``python3``; prompt inputs partly derive from scan/target data,
# so unvalidated model output is a code-injection vector *into the scanner itself*.
# Only an angr/claripy symbolic-execution script shape is permitted; anything that
# could touch the OS, network, filesystem, or dynamic eval is rejected (→ trusted stub).
_ALLOWED_SCRIPT_IMPORTS = frozenset(
    {"angr", "claripy", "archinfo", "pyvex", "logging", "json", "sys"}
)
_FORBIDDEN_CALL_NAMES = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "open",
        "input",
        "breakpoint",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
    }
)
_FORBIDDEN_NAMES = frozenset(
    {
        "os",
        "subprocess",
        "socket",
        "shutil",
        "pathlib",
        "importlib",
        "ctypes",
        "builtins",
        "__builtins__",
        "pty",
        "commands",
        "requests",
        "urllib",
        "httpx",
        "pickle",
        "marshal",
    }
)


def _validate_angr_script(code: str) -> bool:
    """Static allowlist check on LLM-synthesized angr code before we execute it.

    Returns True only when the code parses and contains nothing outside an
    angr/claripy symbolic-execution shape: rejects non-allowlisted imports, dynamic
    eval/exec/open, and any reference to os/subprocess/socket/etc. Rejected code is
    discarded in favour of the trusted generated stub — model output is never run raw.
    """
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(a.name.split(".")[0] not in _ALLOWED_SCRIPT_IMPORTS for a in node.names):
                return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in _ALLOWED_SCRIPT_IMPORTS:
                return False
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _FORBIDDEN_CALL_NAMES:
                return False
        elif isinstance(node, ast.Name):
            if node.id in _FORBIDDEN_NAMES:
                return False
        elif isinstance(node, ast.Attribute):
            root: ast.expr = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in _FORBIDDEN_NAMES:
                return False
    return True


def _is_binary_target(binary_path: str) -> bool:
    """True only for a plausible *local binary file* — never a URL or web host.

    angr needs a real binary to prove a path; handing it a ``target_url`` (http://…)
    or a bare hostname can never produce a sound proof, so such inputs must not be
    run or labelled ``symbolic_execution_proven``. Rejects: empty, any ``scheme://``
    value, and domain-shaped hosts (``app.example.com``). Accepts filesystem paths
    (with a separator or that exist on disk) and simple local binary names.
    """
    p = (binary_path or "").strip()
    if not p:
        return False
    if "://" in p or _URL_SCHEME.match(p):
        return False
    if "/" in p or "\\" in p or os.path.exists(p):
        return True
    # No path separator: reject hostname-shaped values (web targets like
    # "app.example.com"); allow plain undotted local binary names (e.g. "fuzz_bin").
    # Dotted bare names without a path are ambiguous and are skipped — the safe
    # direction (no run, no proof) rather than risk a false proof over a web host.
    return not _HOSTNAME_ONLY.match(p)

SYMBOLIC_ENGINES = {
    "angr": {
        "languages": ["python", "c", "cpp"],
        "pip": "angr",
        "docker_image": "argus-kali-runner:latest",
        "install_hint": "installed in argus-kali-runner image",
    },
    "z3": {
        "languages": ["python", "c", "cpp"],
        "pip": "z3-solver",
        "docker_image": "argus-kali-runner:latest",
        "install_hint": "installed in argus-kali-runner image",
    },
}


@dataclass
class SymbolicExecutionRequest:
    """Request to run symbolic execution on a binary/function."""

    binary_path: str = ""
    function_name: str = ""
    source_file: str = ""
    sink_function: str = ""
    source_function: str = ""
    language: str = "c"
    engine: str = "angr"
    scan_id: str = ""
    timeout_seconds: int = 600


@dataclass
class SymbolicPathConstraint:
    """A path constraint discovered by symbolic execution."""

    variable: str = ""
    constraint: str = ""
    solvable: bool = False
    solution: str = ""


@dataclass
class SymbolicExecutionResult:
    """Result of symbolic execution analysis."""

    vulnerable: bool = False
    proven: bool = False
    path_constraints: list[SymbolicPathConstraint] = field(default_factory=list)
    input_values: dict[str, Any] = field(default_factory=dict)
    path_length: int = 0
    duration_seconds: float = 0.0
    error: str = ""
    angr_script: str = ""


SYMBOLIC_SYSTEM_PROMPT = (
    "You are a symbolic execution expert using angr/Z3.\n"
    "Generate angr Python scripts that prove vulnerability paths.\n"
    "The script must: 1) Load the binary, 2) Find the source function, "
    "3) Explore paths to the sink function, 4) Extract constraints, "
    "5) Solve for concrete input values that trigger the vulnerability.\n"
    "Output ONLY valid Python code using angr API."
)

SYMBOLIC_USER_TEMPLATE = (
    "Generate an angr script to prove the following vulnerability path:\n\n"
    "Binary: {binary_path}\n"
    "Source (user input): {source_function}\n"
    "Sink (dangerous): {sink_function}\n"
    "File: {source_file}\n\n"
    "The script should find concrete input values that reach the sink."
)


def build_symbolic_prompt(request: SymbolicExecutionRequest) -> tuple[str, str]:
    try:
        from src.orchestration.prompt_loader import get_loader

        loader = get_loader()
        if loader.available:
            try:
                system, user = loader.render_extended_system_user(
                    "symbolic_execution",
                    binary_path=request.binary_path,
                    source_function=request.source_function,
                    sink_function=request.sink_function,
                    source_file=request.source_file,
                )
                if system.strip() and user.strip():
                    return system, user
            except Exception:
                logger.debug("build_symbolic_prompt: suppressed best-effort error", exc_info=True)
    except Exception:
        logger.debug("build_symbolic_prompt: suppressed best-effort error", exc_info=True)
    return SYMBOLIC_SYSTEM_PROMPT, SYMBOLIC_USER_TEMPLATE.format(
        binary_path=request.binary_path,
        source_function=request.source_function,
        sink_function=request.sink_function,
        source_file=request.source_file,
    )


def generate_angr_stub(
    binary_path: str,
    source_function: str = "",
    sink_function: str = "",
) -> str:
    """Generate a basic angr script stub for symbolic execution."""
    return (
        f"import angr\nimport claripy\n\n"
        f"project = angr.Project('{binary_path}', auto_load_libs=False)\n"
        f"cfg = project.analyses.CFGFast()\n\n"
        f"src_addr = None\n"
        f"snk_addr = None\n"
        f"for func in cfg.functions.values():\n"
        f"    if '{source_function}' in func.name:\n"
        f"        src_addr = func.addr\n"
        f"    if '{sink_function}' in func.name:\n"
        f"        snk_addr = func.addr\n\n"
        f"if src_addr and snk_addr:\n"
        f"    state = project.factory.blank_state(addr=src_addr)\n"
        f"    simgr = project.factory.simulation_manager(state)\n"
        f"    simgr.explore(find=snk_addr)\n"
        f"    if simgr.found:\n"
        f"        found = simgr.found[0]\n"
        f"        print('VULNERABLE: path found')\n"
        f"        print('Input:', found.posix.dumps(0))\n"
    )


def _parse_angr_output(
    stdout: str, stderr: str  # noqa: ARG001 - retained for signature/API compatibility
) -> SymbolicExecutionResult:
    """Parse angr script output for vulnerability evidence."""
    vulnerable = False
    input_values: dict[str, Any] = {}
    constraints: list[SymbolicPathConstraint] = []

    lower_stdout = stdout.lower()
    if (
        "no path found" in lower_stdout
        or "no active states" in lower_stdout
        or "exploitation failed" in lower_stdout
    ):
        return SymbolicExecutionResult(vulnerable=False, proven=False)

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if "VULNERABLE" in line.upper() or (
            "path found" in line.lower() and "no " not in line.lower()[: line.lower().find("path")]
            if "path" in line.lower()
            else True
        ):
            vulnerable = True
        if line.startswith("Input:"):
            try:
                raw = line.split("Input:", 1)[1].strip()
                input_values["concrete_input"] = raw
            except Exception:
                logger.debug("_parse_angr_output: suppressed best-effort error", exc_info=True)
        if line.startswith("Constraint:"):
            try:
                parts = line.split(":", 1)
                constraints.append(
                    SymbolicPathConstraint(
                        variable=parts[0].replace("Constraint", "").strip(),
                        constraint=parts[1].strip() if len(parts) > 1 else "",
                        solvable=True,
                    )
                )
            except Exception:
                logger.debug("_parse_angr_output: suppressed best-effort error", exc_info=True)

    return SymbolicExecutionResult(
        vulnerable=vulnerable,
        proven=vulnerable,
        path_constraints=constraints,
        input_values=input_values,
    )


def _strip_code_fences(text: str) -> str:
    """Strip a leading/trailing ```python fence an LLM may wrap the script in."""
    s = (text or "").strip()
    if s.startswith("```"):
        lines = s.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        s = "\n".join(lines).strip()
    return s


async def _build_angr_script(request: SymbolicExecutionRequest) -> tuple[str, bool]:
    """Return ``(script, is_llm_synthesized)``.

    LLM output is accepted ONLY when it passes :func:`_validate_angr_script` (AST
    allowlist) — otherwise it is discarded in favour of the deterministic, trusted
    :func:`generate_angr_stub`. Model output is never executed raw.
    """
    system, user = build_symbolic_prompt(request)
    try:
        from src.llm.facade import LLMTask, call_llm_unified

        out = await call_llm_unified(
            system,
            user,
            task=LLMTask.EXPLOIT_GENERATION,
            scan_id=request.scan_id or None,
            phase="symbolic_execution",
        )
        code = _strip_code_fences(out or "")
        if code.strip() and "angr" in code and _validate_angr_script(code):
            return code, True
        if code.strip():
            logger.warning(
                "synthesize_angr_script: LLM script rejected by allowlist, using trusted stub"
            )
    except Exception:
        logger.debug(
            "synthesize_angr_script: LLM unavailable, using generic stub", exc_info=True
        )
    return (
        generate_angr_stub(
            request.binary_path,
            source_function=request.source_function,
            sink_function=request.sink_function,
        ),
        False,
    )


async def synthesize_angr_script(request: SymbolicExecutionRequest) -> str:
    """Synthesize a target-specific angr script via the LLM (WRB, local).

    Falls back to :func:`generate_angr_stub` when the LLM is unavailable or when its
    output fails the AST allowlist. See :func:`_build_angr_script`.
    """
    code, _ = await _build_angr_script(request)
    return code


async def run_symbolic_execution(
    request: SymbolicExecutionRequest,
    use_sandbox: bool = True,
) -> SymbolicExecutionResult:
    """Execute symbolic analysis via angr/Z3 in a sandbox container.

    0. HONESTY GATE: angr needs a real binary. A non-binary / web (URL) target can
       never be proven, so we skip it (``proven=False``) instead of running angr on
       a URL and mislabelling the result ``symbolic_execution_proven``.
    1. Synthesize a target-specific angr script (LLM, local) or fall back to a stub.
    2. Write script to temp file.
    3. Run in sandbox via execute_command.
    4. Parse results for vulnerability proof.
    """
    start = time.monotonic()

    if not _is_binary_target(request.binary_path):
        return SymbolicExecutionResult(
            vulnerable=False,
            proven=False,
            error=(
                "symbolic execution requires a local binary target; non-binary/web "
                f"input skipped (angr cannot prove paths over {request.binary_path!r})"
            ),
            duration_seconds=round(time.monotonic() - start, 2),
        )

    angr_script, _script_is_llm = await _build_angr_script(request)
    # LLM-synthesized scripts ALWAYS run inside the sandbox, never on the host,
    # regardless of the sandbox setting — defense in depth atop the AST allowlist.
    effective_sandbox = True if _script_is_llm else use_sandbox

    from src.tools.executor import execute_command

    script_path = ""
    try:
        script_dir = tempfile.mkdtemp(prefix="argus-symex-")
        script_path = f"{script_dir}/symex_{request.engine}.py"

        with open(script_path, "w") as f:
            f.write(angr_script)

        command = f"python3 {script_path}"

        timeout = min(request.timeout_seconds, 300)

        result = execute_command(
            command,
            use_sandbox=effective_sandbox,
            timeout_sec=timeout,
        )

        parsed = _parse_angr_output(
            result.get("stdout", ""),
            result.get("stderr", ""),
        )
        parsed.duration_seconds = round(time.monotonic() - start, 2)
        parsed.angr_script = angr_script
        parsed.error = (
            result.get("stderr", "")[:1000]
            if not result.get("success", False) and not parsed.vulnerable
            else ""
        )
        return parsed

    except Exception as exc:
        logger.warning("Symbolic execution failed: %s", exc)
        return SymbolicExecutionResult(
            error=str(exc),
            angr_script=angr_script,
            duration_seconds=round(time.monotonic() - start, 2),
        )


__all__ = [
    "SYMBOLIC_ENGINES",
    "SymbolicExecutionRequest",
    "SymbolicExecutionResult",
    "SymbolicPathConstraint",
    "build_symbolic_prompt",
    "generate_angr_stub",
    "run_symbolic_execution",
    "synthesize_angr_script",
]
