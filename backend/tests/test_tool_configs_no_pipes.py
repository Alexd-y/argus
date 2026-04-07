"""Tests for FIX-004 — tool_configs.json: no raw shell pipes without requires_shell flag."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

_TOOL_CONFIGS_PATH = Path(__file__).resolve().parent.parent / "data" / "tool_configs.json"

_SHELL_OPERATORS = (" | ", " && ", " || ", " ; ")


def _load_tool_configs() -> dict[str, Any]:
    if not _TOOL_CONFIGS_PATH.is_file():
        pytest.skip(f"tool_configs.json not found at {_TOOL_CONFIGS_PATH}")
    return json.loads(_TOOL_CONFIGS_PATH.read_text(encoding="utf-8"))


def _iter_command_entries(
    obj: Any,
    *,
    path: str = "",
    requires_shell: bool = False,
) -> list[tuple[str, str, bool]]:
    """Recursively yield (json_path, command_string, requires_shell) for every command value."""
    entries: list[tuple[str, str, bool]] = []

    if isinstance(obj, dict):
        local_requires_shell = requires_shell or bool(obj.get("requires_shell"))

        commands = obj.get("commands")
        if isinstance(commands, dict):
            for mode, cmd in commands.items():
                if isinstance(cmd, str):
                    entries.append((f"{path}.commands.{mode}", cmd, local_requires_shell))

        for key, value in obj.items():
            if key in ("commands", "requires_shell"):
                continue
            entries.extend(
                _iter_command_entries(
                    value,
                    path=f"{path}.{key}" if path else key,
                    requires_shell=local_requires_shell,
                )
            )
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            entries.extend(
                _iter_command_entries(
                    item,
                    path=f"{path}[{idx}]",
                    requires_shell=requires_shell,
                )
            )

    return entries


def test_no_raw_shell_pipes() -> None:
    """Every command containing shell operators must have requires_shell: true on its entry."""
    configs = _load_tool_configs()
    entries = _iter_command_entries(configs)

    violations: list[str] = []
    for json_path, cmd, has_shell_flag in entries:
        if has_shell_flag:
            continue
        for op in _SHELL_OPERATORS:
            if op in cmd:
                violations.append(f"{json_path}: operator {op!r} in command {cmd!r}")
                break

    assert violations == [], (
        "Commands use shell operators without requires_shell: true:\n"
        + "\n".join(f"  - {v}" for v in violations)
    )


def test_at_least_one_requires_shell() -> None:
    """Sanity: the file must contain at least one entry with requires_shell: true."""
    configs = _load_tool_configs()
    entries = _iter_command_entries(configs)
    shell_entries = [e for e in entries if e[2]]
    assert len(shell_entries) >= 1, (
        "Expected at least one entry with requires_shell: true in tool_configs.json"
    )
