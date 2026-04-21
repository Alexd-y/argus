"""Tests for custom script adapter whitelist (M-7)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest


class TestCustomScriptWhitelist:
    """M-7: Custom script adapter uses whitelist for args."""

    def test_safe_arg_regex(self) -> None:
        _SAFE_ARG_RE = re.compile(r"^[A-Za-z0-9_.:/\-]+$")
        assert _SAFE_ARG_RE.match("safe-arg_123")
        assert _SAFE_ARG_RE.match("https://target.com:8080")
        assert _SAFE_ARG_RE.match("192.168.1.1")
        assert not _SAFE_ARG_RE.match("arg; evil")
        assert not _SAFE_ARG_RE.match("$(cmd)")
        assert not _SAFE_ARG_RE.match("arg`cmd`")
        assert not _SAFE_ARG_RE.match("arg|pipe")
        assert not _SAFE_ARG_RE.match("arg&bg")
        assert not _SAFE_ARG_RE.match("")

    def test_no_blacklist_in_adapter(self) -> None:
        source = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "recon"
            / "exploitation"
            / "adapters"
            / "custom_script_adapter.py"
        )
        text = source.read_text(encoding="utf-8")
        assert "[;&|" not in text, "Old blacklist pattern still present"
        assert "_SAFE_ARG_RE" in text or "_validate_arg" in text

    def test_validate_arg_rejects_injection(self) -> None:
        """_validate_arg must raise ValueError on unsafe characters."""
        from src.recon.exploitation.adapters.custom_script_adapter import (
            _validate_arg,
        )

        with pytest.raises(ValueError):
            _validate_arg("arg; evil")

        with pytest.raises(ValueError):
            _validate_arg("$(cmd)")

        with pytest.raises(ValueError):
            _validate_arg("arg`cmd`")

    def test_validate_arg_accepts_valid(self) -> None:
        """_validate_arg must pass clean args through."""
        from src.recon.exploitation.adapters.custom_script_adapter import (
            _validate_arg,
        )

        assert _validate_arg("safe-arg_123") == "safe-arg_123"
        assert _validate_arg("https://target.com:8080") == "https://target.com:8080"

    def test_build_command_uses_shlex_quote(self) -> None:
        """Custom script adapter should use shlex.quote for safe command building."""
        source = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "recon"
            / "exploitation"
            / "adapters"
            / "custom_script_adapter.py"
        )
        text = source.read_text(encoding="utf-8")
        assert "shlex.quote" in text or "shlex" in text
