"""Tests for opt-in structured-output enforcement in the scan pipeline (B5b-2)."""

from __future__ import annotations

import json

import pytest
from src.core.config import settings
from src.orchestration import ai_prompts
from src.orchestration.prompt_registry import RECON

_VALID_RECON = {"assets": [], "subdomains": [], "ports": []}
_INVALID_RECON = {"foo": "bar"}


class TestPhaseSchemaOk:
    def test_disabled_accepts_anything(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "argus_scan_schema_enforcement", False)
        assert ai_prompts._phase_schema_ok(_INVALID_RECON, RECON) is True

    def test_enabled_accepts_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "argus_scan_schema_enforcement", True)
        assert ai_prompts._phase_schema_ok(_VALID_RECON, RECON) is True

    def test_enabled_rejects_invalid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "argus_scan_schema_enforcement", True)
        assert ai_prompts._phase_schema_ok(_INVALID_RECON, RECON) is False

    def test_enabled_unknown_phase_accepts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "argus_scan_schema_enforcement", True)
        assert ai_prompts._phase_schema_ok(_INVALID_RECON, "source_analysis") is True


def _queued_responder(responses: list[str]):
    async def _caller(*_a: object, **_k: object) -> str:
        return responses.pop(0)

    return _caller


class TestCallLlmWithJsonRetry:
    async def test_disabled_accepts_loose_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "argus_scan_schema_enforcement", False)
        monkeypatch.setattr(
            ai_prompts, "call_llm_unified", _queued_responder([json.dumps(_INVALID_RECON)])
        )
        data = await ai_prompts._call_llm_with_json_retry(RECON, "u", "s")
        assert data == _INVALID_RECON  # loose JSON accepted, no retry

    async def test_enabled_valid_first_try(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "argus_scan_schema_enforcement", True)
        monkeypatch.setattr(
            ai_prompts, "call_llm_unified", _queued_responder([json.dumps(_VALID_RECON)])
        )
        data = await ai_prompts._call_llm_with_json_retry(RECON, "u", "s")
        assert data == _VALID_RECON

    async def test_enabled_invalid_then_fixer_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "argus_scan_schema_enforcement", True)
        # First response is parseable but schema-invalid → fixer retry yields valid.
        monkeypatch.setattr(
            ai_prompts,
            "call_llm_unified",
            _queued_responder([json.dumps(_INVALID_RECON), json.dumps(_VALID_RECON)]),
        )
        data = await ai_prompts._call_llm_with_json_retry(RECON, "u", "s")
        assert data == _VALID_RECON

    async def test_enabled_invalid_exhausts_to_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "argus_scan_schema_enforcement", True)
        # Every attempt is schema-invalid → degrades to None (as legacy on failure).
        monkeypatch.setattr(
            ai_prompts,
            "call_llm_unified",
            _queued_responder([json.dumps(_INVALID_RECON)] * 10),
        )
        data = await ai_prompts._call_llm_with_json_retry(RECON, "u", "s")
        assert data is None
