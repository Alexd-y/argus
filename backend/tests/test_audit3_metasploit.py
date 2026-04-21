"""Tests for Metasploit adapter sanitization (H-7)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest


class TestMetasploitSanitization:
    """H-7: Metasploit adapter must validate targets."""

    def test_no_bash_c_in_adapter(self) -> None:
        source = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "recon"
            / "exploitation"
            / "adapters"
            / "metasploit_adapter.py"
        )
        text = source.read_text(encoding="utf-8")
        assert "bash -c" not in text, "Shell-based msfconsole launch still present"

    def test_validate_target_exists(self) -> None:
        source = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "recon"
            / "exploitation"
            / "adapters"
            / "metasploit_adapter.py"
        )
        text = source.read_text(encoding="utf-8")
        assert "_validate_target" in text
        assert "_SAFE_TARGET_RE" in text

    def test_safe_target_regex(self) -> None:
        """Safe target regex must reject shell metacharacters."""
        _SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9._:\-/]+$")
        assert _SAFE_TARGET_RE.match("192.168.1.1")
        assert _SAFE_TARGET_RE.match("example.com")
        assert _SAFE_TARGET_RE.match("https://target.com:8443/path")
        assert not _SAFE_TARGET_RE.match("target; rm -rf /")
        assert not _SAFE_TARGET_RE.match("target$(whoami)")
        assert not _SAFE_TARGET_RE.match("target | cat /etc/passwd")
        assert not _SAFE_TARGET_RE.match("target`id`")
        assert not _SAFE_TARGET_RE.match("")

    def test_validate_target_rejects_injection(self) -> None:
        """_validate_target must raise ValueError on shell metacharacters."""
        from src.recon.exploitation.adapters.metasploit_adapter import (
            _validate_target,
        )

        with pytest.raises(ValueError):
            _validate_target("target; rm -rf /")

        with pytest.raises(ValueError):
            _validate_target("$(whoami)")

        with pytest.raises(ValueError):
            _validate_target("")

    def test_validate_target_accepts_valid(self) -> None:
        """_validate_target must pass clean targets through."""
        from src.recon.exploitation.adapters.metasploit_adapter import (
            _validate_target,
        )

        assert _validate_target("192.168.1.1") == "192.168.1.1"
        assert _validate_target("example.com") == "example.com"
