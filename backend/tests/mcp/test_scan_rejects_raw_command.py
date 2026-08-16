"""QUICK-007 — MCP ``scan.create`` rejects raw argv/command strings.

Rejection happens in ``ScanCreateInput`` before the service layer. No DB.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from src.mcp.schemas.scan import ScanCreateInput, ScanProfile
from src.quick.create import (
    RAW_COMMAND_NOT_ALLOWED,
    RawCommandNotAllowedError,
    reject_raw_command_fields,
)


def _assert_raw_command_rejected(payload: dict) -> None:
    with pytest.raises((PydanticValidationError, RawCommandNotAllowedError)) as exc_info:
        ScanCreateInput.model_validate(payload)
    text = str(exc_info.value).lower()
    assert (
        "argv" in text
        or "command" in text
        or RAW_COMMAND_NOT_ALLOWED in text
        or "raw" in text
    )


def test_scan_create_rejects_top_level_argv() -> None:
    _assert_raw_command_rejected(
        {
            "target": "https://example.com",
            "profile": ScanProfile.STANDARD.value,
            "argv": ["nmap", "-sV", "example.com"],
        }
    )


def test_scan_create_rejects_top_level_command() -> None:
    _assert_raw_command_rejected(
        {
            "target": "https://example.com",
            "command": "nmap -sV example.com",
        }
    )


@pytest.mark.parametrize(
    "forbidden_key",
    ["argv", "command", "cmdline", "cmd", "shell", "command_string", "command_template"],
)
def test_scan_create_rejects_forbidden_key_in_scan_options(forbidden_key: str) -> None:
    _assert_raw_command_rejected(
        {
            "target": "https://example.com",
            "scan_options": {forbidden_key: ["echo", "pwned"]},
        }
    )


def test_scan_create_rejects_argv_nested_in_params() -> None:
    _assert_raw_command_rejected(
        {
            "target": "https://example.com",
            "params": {"argv": ["sqlmap", "-u", "https://example.com"]},
        }
    )


def test_scan_create_rejects_command_nested_in_quick() -> None:
    _assert_raw_command_rejected(
        {
            "target": "https://example.com",
            "execution_mode": "quick",
            "quick": {"profile": "balanced", "command": "nuclei -u https://example.com"},
        }
    )


def test_reject_raw_command_fields_helper_raises_typed_error() -> None:
    with pytest.raises(RawCommandNotAllowedError) as exc_info:
        reject_raw_command_fields({"command": "id"})
    assert exc_info.value.code == RAW_COMMAND_NOT_ALLOWED


def test_scan_create_allows_payload_without_raw_command() -> None:
    payload = ScanCreateInput(
        target="https://example.com",
        profile=ScanProfile.STANDARD,
        scan_options={"execution_mode": "production"},
    )
    assert payload.target == "https://example.com"
    assert payload.scan_options is not None
    assert "argv" not in payload.scan_options
    assert "command" not in payload.scan_options
