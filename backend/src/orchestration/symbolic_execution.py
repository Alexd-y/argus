"""Symbolic execution MCP tool — angr/Z3 proof-of-vulnerability.

Uses symbolic execution to prove that a vulnerability path is feasible,
providing mathematical proof that user input can reach a dangerous sink.

Ось A п.2-3 из Развитие2.md: symbolic execution for PoV.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

SYMBOLIC_ENGINES = {
    "angr": {"languages": ["python", "c", "cpp"], "pip": "angr"},
    "z3": {"languages": ["python", "c", "cpp"], "pip": "z3-solver"},
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
                pass
    except Exception:
        pass
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


__all__ = [
    "SYMBOLIC_ENGINES",
    "SymbolicExecutionRequest",
    "SymbolicExecutionResult",
    "SymbolicPathConstraint",
    "build_symbolic_prompt",
    "generate_angr_stub",
]