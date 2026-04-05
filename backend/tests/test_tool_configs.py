"""Test tool_configs.json structure and validity."""

import json
from pathlib import Path

import pytest

CONFIGS_PATH = Path(__file__).resolve().parent.parent / "data" / "tool_configs.json"


@pytest.fixture(scope="module")
def tool_configs() -> dict:
    return json.loads(CONFIGS_PATH.read_text(encoding="utf-8"))


def test_valid_json(tool_configs: dict) -> None:
    assert isinstance(tool_configs, dict)


def test_legacy_tools_present(tool_configs: dict) -> None:
    for tool in ("dalfox", "xsstrike", "ffuf", "nuclei", "sqlmap"):
        assert tool in tool_configs, f"Legacy tool '{tool}' missing from root"
        assert "default_args" in tool_configs[tool], f"{tool} missing default_args"
        assert "aggressive_args" in tool_configs[tool], f"{tool} missing aggressive_args"


def test_categories_present(tool_configs: dict) -> None:
    assert "categories" in tool_configs
    categories = tool_configs["categories"]
    assert len(categories) >= 27, f"Expected >=27 categories, got {len(categories)}"


def test_each_tool_has_required_fields(tool_configs: dict) -> None:
    required = {"binary", "commands", "output_format", "timeout_seconds", "parser"}
    for cat_name, cat_tools in tool_configs["categories"].items():
        for tool_name, tool_cfg in cat_tools.items():
            for field in required:
                assert field in tool_cfg, f"{cat_name}/{tool_name} missing '{field}'"


def test_commands_have_at_least_one_mode(tool_configs: dict) -> None:
    for cat_name, cat_tools in tool_configs["categories"].items():
        for tool_name, tool_cfg in cat_tools.items():
            commands = tool_cfg["commands"]
            assert len(commands) >= 1, f"{cat_name}/{tool_name} has no commands"


def test_timeout_is_valid(tool_configs: dict) -> None:
    for cat_name, cat_tools in tool_configs["categories"].items():
        for tool_name, tool_cfg in cat_tools.items():
            timeout = tool_cfg["timeout_seconds"]
            if isinstance(timeout, int):
                assert timeout > 0, f"{cat_name}/{tool_name} timeout must be positive"
            elif isinstance(timeout, dict):
                for mode, val in timeout.items():
                    assert isinstance(val, int) and val > 0, (
                        f"{cat_name}/{tool_name} timeout[{mode}] must be positive int"
                    )
            else:
                pytest.fail(f"{cat_name}/{tool_name} timeout has unexpected type {type(timeout)}")
