"""Language → interpreter argv for LAB scripts.

Docker always uses the sandbox image binaries. Local fallback uses the
current Python interpreter so unit tests on Windows still execute for real.
"""

from __future__ import annotations

import sys
from typing import Final

PYTHON_LANGUAGES: Final[frozenset[str]] = frozenset({"python", "python3", "py"})
SHELL_LANGUAGES: Final[frozenset[str]] = frozenset({"bash", "sh"})
JS_LANGUAGES: Final[frozenset[str]] = frozenset({"javascript", "js", "node"})
NUCLEI_LANGUAGES: Final[frozenset[str]] = frozenset(
    {"nuclei", "yaml", "nuclei-yaml", "nuclei_yaml"}
)


def normalize_language(language: str) -> str:
    return (language or "").strip().lower()


def is_nuclei_language(language: str) -> bool:
    return normalize_language(language) in NUCLEI_LANGUAGES


def interpreter_argv(language: str, *, local: bool) -> list[str]:
    """Return argv that reads the program from stdin (`-` / `-s`)."""
    lang = normalize_language(language)
    if lang in PYTHON_LANGUAGES:
        binary = sys.executable if local else "python3"
        return [binary, "-"]
    if lang in SHELL_LANGUAGES:
        return ["bash" if lang == "bash" else "sh", "-s"]
    if lang in JS_LANGUAGES:
        return ["node", "-"]
    raise ValueError(f"unsupported_lab_language:{lang or 'empty'}")


def normalize_local_command_argv(argv: list[str]) -> list[str]:
    """Map python/python3 to the current interpreter for local execution."""
    if not argv:
        return []
    head = argv[0].strip().lower()
    if head in {"python", "python3"}:
        return [sys.executable, *argv[1:]]
    return list(argv)
