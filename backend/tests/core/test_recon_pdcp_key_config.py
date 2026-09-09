"""RECON-008 — asnmap PDCP API key gate settings.

A single env var drives both the recon gate (this setting) and asnmap auth in the
sandbox. It must be readable under both the canonical PDCP_API_KEY name and the
RECON_-prefixed alias, and default to empty (asnmap gated off).
"""

from __future__ import annotations

import pytest
from src.core.config import Settings


def test_recon_pdcp_api_key_defaults_empty() -> None:
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.recon_pdcp_api_key == ""


def test_recon_pdcp_api_key_from_pdcp_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDCP_API_KEY", "pdcp-secret-123")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.recon_pdcp_api_key == "pdcp-secret-123"


def test_recon_pdcp_api_key_from_recon_prefixed_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PDCP_API_KEY", raising=False)
    monkeypatch.setenv("RECON_PDCP_API_KEY", "recon-scoped-key")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.recon_pdcp_api_key == "recon-scoped-key"
